# Optimization Report — CIS Hardening Platform

## Overview

This document describes 15 performance and quality improvements implemented across the backend (FastAPI) and frontend (React/TypeScript) of the CIS Hardening Platform. Changes are grouped by area and ordered as they were applied.

---

## Group C — Strict Type Validation (F-11)

**Files:** `web/backend/models.py`, `web/frontend/src/types.ts`

### Problem
`GenerateRequest.format` was typed as a plain `str`, meaning any value (e.g. `"invalid"`) would pass validation and only fail silently inside the generator.

### Fix
- **Backend:** Changed `format` to `Literal["ansible", "bash", "gpo", "powershell"]` using Python's `typing.Literal`. Pydantic now rejects unknown formats with a `422 Unprocessable Entity` response before the request reaches any business logic.
- **Frontend:** Mirrored the constraint as a TypeScript union type `"ansible" | "bash" | "gpo" | "powershell"`, giving compile-time safety in `api.ts` and `HardeningContext.tsx`.

---

## Group A — Backend I/O & Caching (F-01, F-02, F-04, F-05)

**Files:** `web/backend/services/rule_loader.py`, `web/backend/services/generator.py`

### A1 — Rule Loader Cache (F-02)

#### Problem
Every call to `GET /api/rules/{os}` triggered a full filesystem scan — reading all JSON files from `platforms/windows/rules/**` or parsing `index.json` — even for back-to-back identical requests.

#### Fix
Added a module-level `_cache: dict[str, tuple[dict, float]]` in `rule_loader.py`. `load_rules_grouped()` checks the cache first; if the entry is younger than `_CACHE_TTL` (60 seconds), it returns the cached result immediately without touching the disk. On expiry the cache is refreshed transparently. Uses `time.monotonic()` to avoid wall-clock skew.

---

### A2 — Windows Rule Index (F-01)

#### Problem
`_load_windows_rule_json(rule_id)` and `_find_windows_rule_files(rule_ids)` both did an **O(N×M)** scan: for every rule ID requested, they iterated through every `.json` file on disk, opened it, parsed it, and compared the `rule_id` field. With 300+ Windows rules this scaled poorly.

#### Fix
Added a module-level `_windows_rule_index: dict[str, dict] | None` in `generator.py`. On first use, `_get_windows_rule_index()` does a **single** `rglob` scan, builds a dict `rule_id → {"data": ..., "path": ...}`, and caches it for the lifetime of the process.

- `_load_windows_rule_json(rule_id)` → **O(1)** dict lookup
- `_find_windows_rule_files(rule_ids)` → **O(N)** iteration over requested IDs only

---

### A3 — SHA-256 Sidecar Files (F-04, F-05)

#### Problem
Two functions re-hashed artifact files on every call:
- `_find_permanent_by_sha256()` opened and hashed every permanent artifact file to find a match.
- `get_artifact_info()` re-hashed the artifact file on every metadata lookup.

For large artifacts (ZIP files, long scripts) this was unnecessary I/O.

#### Fix
After writing each artifact file, a `.sha256` sidecar file is written alongside it (e.g. `artifacts/abc123/.sha256`).

- `_find_permanent_by_sha256()` reads the sidecar first; only falls back to full hashing if the sidecar is missing (backward compatibility for pre-existing artifacts).
- `get_artifact_info()` reads the sidecar; computes and writes it lazily if absent.

---

## Group B — Async GPO Generation (F-03)

**Files:** `web/backend/services/generator.py`, `web/backend/routers/rules.py`

### Problem
`_generate_windows_gpo()` called `subprocess.run()` synchronously. This **blocked the entire async event loop** for up to 60 seconds while PowerShell ran, preventing the server from handling any other requests concurrently.

### Fix
Converted `_generate_windows_gpo()` to `async def` using `asyncio.create_subprocess_exec`:

```python
proc = await asyncio.create_subprocess_exec(
    "powershell", "-ExecutionPolicy", "Bypass", "-File", str(custom_script_path),
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    cwd=str(tools_dir),
)
stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
```

- The event loop is **free to serve other requests** while PowerShell runs.
- `asyncio.wait_for(..., timeout=60)` kills the process and returns a clean error on timeout.
- The top-level `generate()` function was also made `async def` and `await`s the GPO branch.
- The router's `generate_config` endpoint already had `async def`, so it just needed `result = await generate(...)`.

---

## Group D — Data-Driven Ubuntu Resolver (F-12)

**Files:** `platforms/linux/ubuntu/desktop/rules/index.json`, `web/backend/services/resolver.py`

### Problem
`resolver.py` contained a large hardcoded `UBUNTU_DEPENDENCIES` Python dict with ~30 entries. This was a maintenance liability: adding or changing a dependency required editing Python source code rather than the rule data files.

### Fix

**`index.json`:** Added `"depends_on"` and `"conflicts_with"` arrays directly to the 30 rules that have dependencies:

| Rule group | Example entry |
|---|---|
| UFW chain | `4.2.1` → `depends_on: ["4.1.1"]` |
| nftables chain | `4.3.2` → `depends_on: ["4.1.1"]` |
| iptables chain | `4.4.2.1` → `depends_on: ["4.1.1"]` |
| GDM | `1.7.3` → `depends_on: ["1.7.1"]` |
| PAM | `5.3.2.1` → `depends_on: ["5.3.1.1"]` |

**`resolver.py`:** Replaced the hardcoded dict with `_load_ubuntu_deps()` which reads the `index.json` at resolve time and returns only entries that have non-empty dependency fields. The firewall mutual-exclusion sets (`_UFW_RULES`, `_NFT_RULES`, `_IPT_RULES`) are structural constants and remain hardcoded — they define which rules belong to which firewall group, which is not per-rule metadata.

---

## Group E — Artifact Eviction (F-13)

**File:** `web/backend/services/generator.py`

### Problem
Permanent artifacts accumulated on disk indefinitely. There was no cleanup mechanism, so the `artifacts/` directory would grow without bound.

### Fix
Added `_cleanup_old_permanent_artifacts()` which removes any permanent artifact directory whose `mtime` is older than `ARTIFACT_TTL_DAYS` (default: 30 days, configurable via the `ARTIFACT_TTL_DAYS` environment variable).

The function is called once at module import time, wrapped in a `try/except` so a cleanup failure never prevents server startup.

---

## Group F — Rate Limiting (F-15)

**Files:** `web/backend/requirements.txt`, `web/backend/main.py`, `web/backend/routers/rules.py`

### Problem
The `/api/generate` and `/api/resolve` endpoints had no rate limiting, making them vulnerable to abuse — generation in particular can be CPU- and I/O-intensive.

### Fix
Added `slowapi==0.1.9` (a FastAPI-compatible rate-limiting middleware) to `requirements.txt`.

Configured in `main.py`:
```python
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

Applied in `routers/rules.py`:
- `POST /api/generate` → **10 requests/minute** per IP
- `POST /api/resolve` → **30 requests/minute** per IP

Exceeding the limit returns HTTP `429 Too Many Requests`.

---

## Group J — Environment Variable for API URL (F-09, F-10)

**Files:** `web/frontend/src/services/api.ts`, `web/frontend/.env.example` *(new)*

### Problem
The backend URL was hardcoded as `"http://localhost:8001/api"` in `api.ts`. The download URL construction used a fragile `.replace("/api", "")` approach. Changing the host required editing source code.

### Fix
- `api.ts` now reads `import.meta.env.VITE_API_HOST` with a fallback to `"http://localhost:8000"`:
  ```typescript
  const API_HOST = import.meta.env.VITE_API_HOST ?? "http://localhost:8000";
  const API_BASE = `${API_HOST}/api`;
  ```
- `downloadArtifact()` constructs the full URL as `` `${API_HOST}${downloadUrl}` `` — no more fragile string replacement.
- A new `.env.example` file documents the variable for developers:
  ```
  VITE_API_HOST=http://localhost:8000
  ```

---

## Group G — RuleCard Memoization (F-06)

**Files:** `web/frontend/src/components/RuleCard.tsx`, `web/frontend/src/components/RuleList.tsx`

### Problem
`RuleCard` called `useHardening()` internally to read `state.selectedRuleIds` and `toggleRule`. Because it subscribed directly to context, **every toggle action caused all visible RuleCards to re-render**, even those whose selection state didn't change.

### Fix
- **`RuleCard`**: Removed the `useHardening()` call. Added `isSelected: boolean` and `onToggle: (id: string) => void` as explicit props. Wrapped the component with `React.memo` so it only re-renders when its own props change.
- **`RuleList`**: Now computes `isSelected={state.selectedRuleIds.has(rule.rule_id)}` per card and passes down `onToggle={toggleRule}` (which is already `useCallback`-stable from the context).

**Result:** Toggling one rule now causes **exactly 1 RuleCard re-render** instead of N.

---

## Group H — Rule List Virtualization (F-07)

**Files:** `web/frontend/package.json`, `web/frontend/src/components/RuleList.tsx`

### Problem
Sections with many rules (e.g. Section 18 with 100+ Windows Administrative Templates) rendered all RuleCards into the DOM at once, causing layout and paint work proportional to the total rule count.

### Fix
Added `@tanstack/react-virtual` and extracted a `SectionContent` sub-component in `RuleList.tsx`.

- Sections with **≤ 30 rules** render normally (no virtualization overhead).
- Sections with **> 30 rules** use `useVirtualizer` with a scrollable container (`max-height: 480px`). Only the visible cards (~7–8 at a time, plus 5 overscan) are mounted in the DOM.

```typescript
const virtualizer = useVirtualizer({
    count: rules.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 72,
    overscan: 5,
    enabled: shouldVirtualize,
});
```

---

## Group I — Request Cancellation (F-08)

**Files:** `web/frontend/src/context/HardeningContext.tsx`, `web/frontend/src/services/api.ts`

### Problem
If the user clicked "Calculate" or "Generate" multiple times in quick succession, all in-flight requests continued to run. Responses could arrive out of order, causing stale or incorrect state to be displayed.

### Fix

**`api.ts`:** `resolveRules()` and `generateConfig()` now accept an optional `signal?: AbortSignal` parameter, forwarded to `fetch()`.

**`HardeningContext.tsx`:** Added two `useRef` slots for `AbortController` instances:

```typescript
const resolveControllerRef = useRef<AbortController | null>(null);
const generateControllerRef = useRef<AbortController | null>(null);
```

Each time `runResolve` or `runGenerate` is called:
1. The previous controller (if any) is aborted — cancelling the in-flight HTTP request.
2. A fresh `AbortController` is created and stored.
3. After `await`, the handler checks `controller.signal.aborted` before dispatching any state update, ensuring stale responses are silently dropped.

---

## Summary Table

| ID | Area | File(s) Changed | Impact |
|---|---|---|---|
| F-01 | Windows rule O(N×M) scan | `generator.py` | O(1) lookup per rule |
| F-02 | Rule loader disk scan on every request | `rule_loader.py` | 60s TTL cache |
| F-03 | Blocking subprocess in async handler | `generator.py`, `rules.py` | Non-blocking async subprocess |
| F-04 | SHA-256 re-hash on duplicate check | `generator.py` | Sidecar file read |
| F-05 | SHA-256 re-hash on artifact info | `generator.py` | Sidecar file read |
| F-06 | All RuleCards re-render on any toggle | `RuleCard.tsx`, `RuleList.tsx` | `React.memo` + lifted props |
| F-07 | Full rule list DOM render | `RuleList.tsx` | `useVirtualizer` for >30 rules |
| F-08 | Stale responses from rapid clicks | `HardeningContext.tsx`, `api.ts` | `AbortController` per request |
| F-09 | Hardcoded backend URL | `api.ts`, `.env.example` | `VITE_API_HOST` env var |
| F-10 | Fragile download URL construction | `api.ts` | Direct `${API_HOST}${url}` |
| F-11 | Unvalidated format string | `models.py`, `types.ts` | `Literal` / union type |
| F-12 | Hardcoded dependency dict in Python | `resolver.py`, `index.json` | Data-driven from index.json |
| F-13 | No artifact eviction | `generator.py` | TTL-based cleanup on startup |
| F-15 | No rate limiting on expensive endpoints | `main.py`, `rules.py`, `requirements.txt` | slowapi 10/30 req/min |
