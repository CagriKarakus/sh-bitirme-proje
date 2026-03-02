# OPTIMIZATIONS.md — CIS Hardening Platform

> **Audit Date:** 2026-03-02
> **Scope:** Full codebase — FastAPI backend, React/TS frontend, generator scripts
> **Model:** Claude Sonnet 4.6

---

## 1. Optimization Summary

### Current Health

The codebase is architecturally clean and well-structured. The FastAPI backend separates concerns well (loader / resolver / generator), and the React frontend uses idiomatic hooks + `useReducer`. However, several **O(N×M) file-scan patterns** dominate the hot paths and will cause serious latency regression at scale. The most critical issue is the Windows rule lookup in `generator.py`, which performs a full recursive directory scan per selected rule.

### Top 3 Highest-Impact Improvements

1. **Cache rule loading** — `load_rules_grouped()` hits disk on every request; a module-level dict cache with mtime invalidation eliminates 100% of repeat I/O.
2. **Fix N×M Windows rule lookup** — `_load_windows_rule_json()` does a full `rglob` scan for each selected rule; pre-indexing rule IDs to paths drops this from O(N×M) to O(1) per lookup.
3. **Wrap blocking subprocess in thread pool** — `subprocess.run()` for GPO generation blocks the FastAPI async event loop for up to 60 seconds, starving all other requests.

### Biggest Risk if No Changes Are Made

On a Windows generate request with 50+ rules selected, the backend performs **50+ full recursive directory scans**, each opening and JSON-parsing every `.json` file in the rules directory. At 100 rule files × 50 selected rules = 5,000 `open()` + `json.load()` calls per HTTP request. This will cause 5–30 second response times and is trivially exploitable as a DoS amplification vector.

---

## 2. Findings (Prioritized)

---

### F-01: N×M File Scan in Windows Rule Lookup

- **Title:** `_load_windows_rule_json()` performs full `rglob` scan per selected rule
- **Category:** I/O / Algorithm
- **Severity:** Critical
- **Impact:** Latency on `/generate` (Windows PS1 path), potential DoS amplification
- **Evidence:** `web/backend/services/generator.py:289-304`, called in loop at line 335

```python
# generator.py:335 — called once PER rule_id
for rid in rule_ids:
    rule = _load_windows_rule_json(rid)   # Each call does:
```

```python
# generator.py:289-304
def _load_windows_rule_json(rule_id: str) -> dict | None:
    for rules_dir in [win_base / "rules", win_base / "manual_rules"]:
        for json_file in rules_dir.rglob("*.json"):   # Full scan every time
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)                    # Parse every file
            if data.get("rule_id") == rule_id:
                return data
```

- **Why it's inefficient:** For N selected rules and M total JSON files, this is O(N × M) `open()` + `json.load()` calls. With 50 rules selected and 100 JSON files, that's 5,000 file operations per request. The same full scan also occurs in `_find_windows_rule_files()` (line 307–324).
- **Recommended fix:** Build a module-level `dict[rule_id → Path]` index once at startup (or on first use), keyed by `rule_id`. Both `_load_windows_rule_json()` and `_find_windows_rule_files()` consult this index — reducing lookup to O(1).
- **Tradeoffs / Risks:** Index must be invalidated if JSON files change on disk. Use `os.stat()` on the rules base directory mtime, or just rebuild on startup (acceptable since rules change rarely).
- **Expected impact estimate:** 95%+ latency reduction for Windows PS1 generation with many rules.
- **Removal Safety:** Safe
- **Reuse Scope:** `generator.py` + `rule_loader.py` — both share the same scan pattern

---

### F-02: No In-Memory Cache for Rule Loading

- **Title:** `load_rules_grouped()` hits disk on every `GET /api/rules/{os}`
- **Category:** I/O / Caching
- **Severity:** High
- **Impact:** Latency on every page load / OS switch
- **Evidence:** `web/backend/services/rule_loader.py:73–113`

```python
# Called on every GET /api/rules/windows
def _load_windows_directory(base_dir: Path, ...) -> List[RuleItem]:
    for json_file in sorted(base_dir.rglob("*.json")):    # Full rglob each time
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)                             # Parse every file
```

- **Why it's inefficient:** Rules almost never change at runtime. There is zero caching — every call to `GET /api/rules/windows` performs a full recursive scan and JSON parse of every file in `platforms/windows/rules/`. The `sorted()` call adds an O(M log M) sort on top of the O(M) scan.
- **Recommended fix:** Use `functools.lru_cache` with `maxsize=2` (one per OS) or a module-level dict `_cache: dict[str, dict]`. Invalidate via a TTL (e.g., 60s) or by checking the mtime of the rules root directory with `Path.stat().st_mtime`.
- **Tradeoffs / Risks:** Stale data if rules change on disk during server uptime. Acceptable: rules are static files, not a database. A restart always clears the cache.
- **Expected impact estimate:** Eliminates ~100% of disk I/O on repeated requests. Estimated 200–500ms → <5ms for the Windows rule list.
- **Removal Safety:** Safe
- **Reuse Scope:** `rule_loader.py`

---

### F-03: Blocking Subprocess Starves Async Event Loop

- **Title:** `subprocess.run()` in GPO generation blocks FastAPI's async worker
- **Category:** Concurrency / Reliability
- **Severity:** High
- **Impact:** All other in-flight requests are blocked for up to 60 seconds during GPO generation
- **Evidence:** `web/backend/services/generator.py:556-563`

```python
result = subprocess.run(
    ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(custom_script_path)],
    capture_output=True,
    text=True,
    timeout=60,          # Blocks for up to 60 seconds
    cwd=str(tools_dir),
)
```

- **Why it's inefficient:** FastAPI uses an async event loop (asyncio). `subprocess.run()` is a **blocking** call. When the FastAPI endpoint calls `generate()` which calls `_generate_windows_gpo()`, the event loop is frozen for the full subprocess duration, preventing any other request from being handled (including health checks, rule listing, etc.).
- **Recommended fix:** Replace with `asyncio.create_subprocess_exec()` (fully async, compatible with FastAPI). Alternatively, wrap in `loop.run_in_executor(None, ...)` using Python's `asyncio.get_event_loop().run_in_executor()` with a thread pool.
- **Tradeoffs / Risks:** Async subprocess requires changing the `generate()` function and the router to `await` it. Medium refactor. `run_in_executor` is a simpler drop-in with minimal changes.
- **Expected impact estimate:** Eliminates full event loop blockage. Other requests remain responsive during GPO generation.
- **Removal Safety:** Needs Verification (functional change)
- **Reuse Scope:** `generator.py` + `routers/rules.py`

---

### F-04: `_find_permanent_by_sha256` Reads All Artifacts on Every Permanent Save

- **Title:** SHA256 deduplication reads every permanent artifact file
- **Category:** I/O / Algorithm
- **Severity:** High
- **Impact:** Latency on every permanent `/generate` call grows linearly with artifact count
- **Evidence:** `web/backend/services/generator.py:50-62`

```python
def _find_permanent_by_sha256(sha256: str) -> str | None:
    for art_dir in ARTIFACTS_DIR.iterdir():
        if not art_dir.is_dir() or not (art_dir / ".permanent").exists():
            continue
        for f in art_dir.iterdir():
            if f.is_file() and not f.name.startswith("."):
                try:
                    if _sha256(f) == sha256:    # Reads entire file to compare
                        return art_dir.name
```

- **Why it's inefficient:** Every permanent generate call opens and hashes every permanent artifact file. As artifact count grows (e.g., 100 artifacts at 1MB each = 100MB of file reads per request). This is O(N × artifact_size) with no upper bound.
- **Recommended fix:** Write the SHA256 to a sidecar file (e.g., `{artifact_id}/.sha256`) immediately after generation. Deduplication reads only the tiny `.sha256` files, not the actual artifact content.
- **Tradeoffs / Risks:** Sidecar files must be kept in sync with artifacts. If an artifact is partially written (crash during write), sidecar may be stale. Mitigate by writing sidecar only after the main file is flushed/closed.
- **Expected impact estimate:** Deduplication check drops from O(N × file_size) to O(N × ~64 bytes). Near-instant for any reasonable artifact count.
- **Removal Safety:** Safe (additive change; fallback to full scan if sidecar missing)
- **Reuse Scope:** `generator.py`

---

### F-05: `get_artifact_info` Recomputes SHA256 on Every Lookup

- **Title:** Artifact info endpoint re-hashes the file on every call
- **Category:** I/O / Caching
- **Severity:** Medium
- **Impact:** Unnecessary disk I/O for every `GET /api/artifact/{id}` call
- **Evidence:** `web/backend/services/generator.py:650-660`

```python
def get_artifact_info(artifact_id: str) -> dict | None:
    ...
    return {
        "filename": file_path.name,
        "sha256": _sha256(file_path),    # Reads+hashes entire file on every call
    }
```

- **Why it's inefficient:** The SHA256 never changes once an artifact is written. But the endpoint recomputes it by reading the entire file on every lookup. With the sidecar fix from F-04, this becomes a trivial sidecar read.
- **Recommended fix:** Same `.sha256` sidecar from F-04 — `get_artifact_info` reads the sidecar file (~64 bytes) instead of hashing the full artifact.
- **Tradeoffs / Risks:** Depends on F-04 sidecar implementation.
- **Expected impact estimate:** Multi-MB file read → 64-byte read per lookup. Essentially free.
- **Removal Safety:** Safe
- **Reuse Scope:** `generator.py`

---

### F-06: RuleCard Not Memoized — All Cards Re-render on Any State Change

- **Title:** `RuleCard` re-renders globally on every `selectedRuleIds` mutation
- **Category:** Frontend / CPU
- **Severity:** Medium
- **Impact:** Janky UI when toggling rules with 100+ visible cards
- **Evidence:** `web/frontend/src/components/RuleCard.tsx:12-91`, `HardeningContext.tsx:97-102`

```typescript
// reducer.ts — TOGGLE_RULE always creates a new Set reference
case "TOGGLE_RULE": {
    const next = new Set(state.selectedRuleIds);  // New reference → all cards re-render
    ...
}
```

```typescript
// RuleCard.tsx — consumes global state; no React.memo
export default function RuleCard({ rule, onInfoClick }: Props) {
    const { state, toggleRule } = useHardening();    // Re-runs on any state change
    const isSelected = state.selectedRuleIds.has(rule.rule_id);
```

- **Why it's inefficient:** `useHardening()` returns the whole context value. `state` changes on every action (toggle, search, filter). Every visible `RuleCard` re-renders even if its own `rule_id` selection state didn't change. With 200 visible cards, a single toggle triggers 200 re-renders.
- **Recommended fix:** Wrap `RuleCard` in `React.memo`. Extract `isSelected` as a derived prop passed from the parent (so the card component itself doesn't need to call `useHardening`). Then `React.memo` can do a shallow-prop comparison and skip the render.
- **Tradeoffs / Risks:** Props must be stable (no inline object/function creation at the call site). `onInfoClick` needs to be memoized in the parent with `useCallback`.
- **Expected impact estimate:** Reduces re-renders from O(N) to O(1) per toggle for a list of N rules.
- **Removal Safety:** Safe
- **Reuse Scope:** `RuleCard.tsx` + `RuleList.tsx`

---

### F-07: No Virtualization for Large Rule Lists

- **Title:** `RuleList` renders all visible rules as real DOM nodes
- **Category:** Frontend / Memory / CPU
- **Severity:** Medium
- **Impact:** Initial render time and scroll performance with 100+ rules visible
- **Evidence:** `web/frontend/src/components/RuleList.tsx:122-128`

```tsx
{isOpen && (
    <div className="section-rules">
        {rules.map((rule) => (
            <RuleCard key={rule.rule_id} rule={rule} onInfoClick={onInfoClick} />
        ))}
    </div>
)}
```

- **Why it's inefficient:** When a section with 50+ rules is expanded, all 50 DOM nodes are created and painted. With multiple sections open and 200+ total rules visible, this can cause 100–300ms initial render times on low-end hardware.
- **Recommended fix:** Use `@tanstack/react-virtual` (small, no dependencies) to virtualize the rule list within each section. Only render cards visible in the viewport + a small overscan buffer.
- **Tradeoffs / Risks:** Virtualization adds complexity. The accordion structure (sections) makes row-height estimation slightly tricky if card heights vary. Alternative: lazy render sections (only render card DOM when a section is open, which already happens via `isOpen` guard) and defer virtualization until perf is measured.
- **Expected impact estimate:** Reduces DOM nodes by 80%+ when multiple sections are open. 200ms → 30ms initial section render for large sections.
- **Removal Safety:** Safe (additive)
- **Reuse Scope:** `RuleList.tsx`

---

### F-08: `runResolve` / `runGenerate` Have No Request Cancellation

- **Title:** Concurrent async operations can produce race conditions
- **Category:** Concurrency / Reliability
- **Severity:** Medium
- **Impact:** Stale results shown if user triggers multiple rapid resolve/generate clicks
- **Evidence:** `web/frontend/src/context/HardeningContext.tsx:226-258`

```typescript
const runResolve = useCallback(async () => {
    dispatch({ type: "SET_RESOLVING", resolving: true });
    try {
        const result = await resolveRules(...);   // No AbortController
        dispatch({ type: "SET_VALIDATION", result });
    }
    ...
}, [state.selectedOS, state.selectedRuleIds]);
```

- **Why it's inefficient:** Unlike `fetchRules` (which has a `cancelled` flag), `runResolve` and `runGenerate` have no cancellation mechanism. If the user clicks "Calculate" twice quickly, two responses arrive in non-deterministic order; the older response may overwrite the newer one.
- **Recommended fix:** Use `AbortController` + `signal` in each async function. On a second invocation before the first completes, call `controller.abort()` on the previous controller.
- **Tradeoffs / Risks:** UI must not trigger duplicate requests in rapid succession anyway (button is disabled while `isResolving` is true). The button `disabled={selectedCount === 0 || state.isResolving}` already prevents this for resolve — but `runGenerate` is called from `ValidationPanel`, which may not block properly. Verify UI guards before deprioritizing this.
- **Expected impact estimate:** Prevents rare but hard-to-debug UI state corruption.
- **Removal Safety:** Safe (additive)
- **Reuse Scope:** `HardeningContext.tsx`

---

### F-09: API Base URL Hardcoded — No Environment Variable Support

- **Title:** `API_BASE` is hardcoded to `http://localhost:8001/api`
- **Category:** Reliability / Build
- **Severity:** Medium
- **Impact:** Zero-config deployability; breaks in staging, production, or Docker environments
- **Evidence:** `web/frontend/src/services/api.ts:12`

```typescript
const API_BASE = "http://localhost:8001/api";
```

Also note: CLAUDE.md states backend runs on port **8000**, but `api.ts` targets port **8001**. This is an active inconsistency.

- **Why it's inefficient:** Any deployment outside localhost (Docker, remote server, staging) requires manual code edits. Vite supports `.env` files with `import.meta.env.VITE_*` variables natively.
- **Recommended fix:** Replace with `const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8001/api";` and add a `.env.example` file. Also reconcile the port discrepancy between CLAUDE.md (8000) and `api.ts` (8001).
- **Tradeoffs / Risks:** None — additive change, backward compatible.
- **Expected impact estimate:** Enables multi-environment deployment without code changes.
- **Removal Safety:** Safe
- **Reuse Scope:** `api.ts` + `.env` files

---

### F-10: `downloadArtifact` URL Construction Is Fragile

- **Title:** Download URL built via `API_BASE.replace("/api", "")` — breaks on any path change
- **Category:** Reliability
- **Severity:** Low
- **Impact:** Silent breakage if `API_BASE` changes format
- **Evidence:** `web/frontend/src/services/api.ts:63`

```typescript
const fullUrl = `${API_BASE.replace("/api", "")}${downloadUrl}`;
// If API_BASE = "http://localhost:8001/api"
// and downloadUrl = "/api/download/abc123"
// Result: "http://localhost:8001" + "/api/download/abc123" = correct
// But if API_BASE changes to "http://localhost:8001/v2/api" → broken
```

- **Why it's inefficient:** String manipulation on a URL path is fragile. The backend already returns a full relative URL path in `download_url`. A cleaner approach uses a dedicated base host constant or constructs URLs properly.
- **Recommended fix:** Extract `API_HOST = import.meta.env.VITE_API_HOST ?? "http://localhost:8001"` as a separate constant, and keep `API_BASE = \`${API_HOST}/api\``. Download URL becomes `fullUrl = \`${API_HOST}${downloadUrl}\``.
- **Tradeoffs / Risks:** Requires env var coordination with F-09.
- **Expected impact estimate:** Prevents silent bugs during any URL structure refactor.
- **Removal Safety:** Safe
- **Reuse Scope:** `api.ts`

---

### F-11: No Input Validation on `format` Field in `/generate` Endpoint

- **Title:** `GenerateRequest.format` is accepted as any string with no enum validation
- **Category:** Reliability / Security-impacting Inefficiency
- **Severity:** Low
- **Impact:** Unexpected format strings silently fall through to defaults; no user-facing error
- **Evidence:** `web/backend/models.py:48`, `web/backend/services/generator.py:612-622`

```python
# models.py
class GenerateRequest(BaseModel):
    format: str = "ansible"    # No Literal["ansible","bash","gpo","powershell"]
```

```python
# generator.py:612-622
if os_name == "ubuntu":
    if fmt == "bash":
        result = _generate_ubuntu_bash(rule_ids)
    else:                    # Any unknown format silently becomes ansible
        result = _generate_ubuntu_ansible(rule_ids)
```

- **Why it's inefficient:** A user sending `format: "invalid"` gets an Ansible playbook silently, with no error. Pydantic supports `Literal` types for enum-like validation at zero cost.
- **Recommended fix:** `format: Literal["ansible", "bash", "gpo", "powershell"] = "ansible"` in `GenerateRequest`. Pydantic will return a 422 with a descriptive error for invalid values.
- **Tradeoffs / Risks:** None — pure validation tightening.
- **Expected impact estimate:** Prevents confusing silent behavior.
- **Removal Safety:** Safe
- **Reuse Scope:** `models.py` + `types.ts` (mirror the union type in frontend)

---

### F-12: Resolver Dependency Map Is Hardcoded, Not Loaded from Data

- **Title:** Ubuntu dependency graph is a static Python dict, not data-driven
- **Category:** Maintainability / Algorithm
- **Severity:** Low
- **Impact:** Every new Ubuntu rule that has dependencies requires code changes to `resolver.py`
- **Evidence:** `web/backend/services/resolver.py:16-57`

```python
UBUNTU_DEPENDENCIES: Dict[str, Dict[str, List[str]]] = {
    "4.2.1": {"depends_on": ["4.1.1"], "conflicts_with": []},
    # ... 26 more hardcoded entries
}
```

- **Why it's inefficient:** The Ubuntu `index.json` or individual rule metadata files could carry `depends_on` / `conflicts_with` fields, making the resolver self-updating. The hardcoded dict will drift from the actual rule set over time, creating silent validation gaps.
- **Recommended fix:** Add `depends_on: list[str]` and `conflicts_with: list[str]` to Ubuntu `index.json` entries. Load dependency data dynamically in `resolver.py` from the same index file used by `rule_loader.py`.
- **Tradeoffs / Risks:** Requires updating `index.json` schema and migrating current deps. Medium effort. Windows resolver is already stubbed out (no dependencies validated) which is a related gap.
- **Expected impact estimate:** Reduces maintenance risk; new rules automatically participate in dependency checking.
- **Removal Safety:** Needs Verification (data migration)
- **Reuse Scope:** `resolver.py` + `rule_loader.py` + `index.json`

---

### F-13: Permanent Artifact Store Has No Eviction or Size Cap

- **Title:** `ARTIFACTS_DIR` grows unboundedly for permanent artifacts
- **Category:** Reliability / Cost
- **Severity:** Low
- **Impact:** Disk exhaustion over time; no administrative tooling to inspect/prune
- **Evidence:** `web/backend/services/generator.py:34-36`, `generator.py:625-632`

```python
def _mark_permanent(artifact_id: str) -> None:
    (ARTIFACTS_DIR / artifact_id / ".permanent").touch()  # No TTL, no max-size
```

- **Why it's inefficient:** SHA256 deduplication prevents byte-for-byte duplicates, but semantically different artifacts (same rules, different timestamps) generate unique artifacts that accumulate forever.
- **Recommended fix:** Add an admin endpoint or a startup-time cleanup job that prunes permanent artifacts older than a configurable TTL (e.g., 30 days). Log artifact count and total size at startup.
- **Tradeoffs / Risks:** Users who saved an artifact ID and return months later may find it gone. Document TTL clearly in API response.
- **Expected impact estimate:** Prevents disk exhaustion in long-running deployments.
- **Removal Safety:** Likely Safe
- **Reuse Scope:** `generator.py` + `routers/rules.py`

---

### F-14: `SELECT_ALL` Creates a Full Array on Every Invocation

- **Title:** `SELECT_ALL` reducer maps all rules to IDs on every call
- **Category:** Frontend / Memory
- **Severity:** Low
- **Impact:** Minor GC pressure on large rule sets; no visible lag
- **Evidence:** `web/frontend/src/context/HardeningContext.tsx:104-110`

```typescript
case "SELECT_ALL":
    return {
        ...state,
        selectedRuleIds: new Set(state.rules.map((r) => r.rule_id)),  // Array + Set alloc
        ...
    };
```

- **Why it's inefficient:** `state.rules.map(r => r.rule_id)` allocates a temporary array before constructing the Set. With 300+ rules this is negligible, but can be made allocation-free by using a generator approach.
- **Recommended fix:** `new Set(state.rules.map(r => r.rule_id))` is already idiomatic. Only worth addressing if profiling shows GC pressure. Mark as **acknowledged, low priority**.
- **Tradeoffs / Risks:** Not worth changing.
- **Expected impact estimate:** Negligible.
- **Removal Safety:** Safe
- **Reuse Scope:** `HardeningContext.tsx`

---

### F-15: No Rate Limiting or Authentication on Generate Endpoint

- **Title:** `/api/generate` is unauthenticated and unthrottled
- **Category:** Security-impacting Inefficiency / Reliability
- **Severity:** Medium
- **Impact:** Any client can trigger unlimited artifact generation; GPO path invokes PowerShell subprocesses
- **Evidence:** `web/backend/routers/rules.py:43-61`, `web/backend/main.py` (no auth middleware)

- **Why it's inefficient:** The `/api/generate` endpoint for GPO format spawns a PowerShell subprocess. Without rate limiting, a single attacker can flood the server with PowerShell processes. The lack of auth also means the artifact store is accessible to anyone.
- **Recommended fix:** Add `slowapi` (FastAPI-compatible rate limiter) for the `/generate` and `/resolve` endpoints. For a dev/internal tool, IP-based rate limiting (e.g., 10 generate requests/minute) is sufficient. For production, add HTTP Basic auth or API key header via FastAPI's `Depends()`.
- **Tradeoffs / Risks:** Adds dependency (`slowapi`). Rate limiting configuration must account for legitimate bulk use cases (admin running many generates).
- **Expected impact estimate:** Prevents DoS via PowerShell process flooding.
- **Removal Safety:** Safe (additive)
- **Reuse Scope:** `main.py` + `routers/rules.py`

---

## 3. Quick Wins (Do First)

These changes are low effort, high impact, and safe to apply immediately:

| Priority | Finding | Effort | Impact |
|---|---|---|---|
| 1 | **F-02** — Cache rule loading (lru_cache on `load_rules`) | ~30 min | Eliminates all repeat I/O on GET /rules |
| 2 | **F-11** — Add `Literal` type to `GenerateRequest.format` | ~5 min | Free validation, zero risk |
| 3 | **F-09** — Replace hardcoded `API_BASE` with env var | ~15 min | Enables any deployment |
| 4 | **F-10** — Fix `downloadArtifact` URL construction | ~10 min | Prevents future fragility |
| 5 | **F-06** — Wrap `RuleCard` in `React.memo` | ~30 min | Immediate render perf gain |
| 6 | **F-05** — Store SHA256 in sidecar file | ~45 min | Makes F-04 a prerequisite for permanent store scale |

---

## 4. Deeper Optimizations (Do Next)

These require more design work but provide significant long-term value:

### 4.1 Unified Windows Rule Index (addresses F-01 + F-02)

Build a module-level `_windows_rule_index: dict[str, dict]` that maps `rule_id → full rule data` and `rule_id → Path`. Populated once on startup or first request, refreshed via mtime check. Both `rule_loader.py` and `generator.py` consume this shared index instead of each doing independent `rglob` scans.

### 4.2 Async GPO Generation (addresses F-03)

Convert `_generate_windows_gpo()` to use `asyncio.create_subprocess_exec()`. The router endpoint is already `async def`; the generator service needs to become `async def generate(...)`. This is a function-signature change that propagates upward but has no correctness risk.

### 4.3 Data-Driven Ubuntu Resolver (addresses F-12)

Extend `index.json` with `"depends_on": []` and `"conflicts_with": []` fields per rule. The `resolver.py` loads this data at startup (or from the shared index). Remove the hardcoded `UBUNTU_DEPENDENCIES` dict. This makes the resolver future-proof as new Ubuntu rules are added.

### 4.4 SHA256 Sidecar + Artifact Eviction (addresses F-04 + F-13)

On artifact write: `(art_dir / ".sha256").write_text(sha256)`. On deduplication check: only read `.sha256` files. Add a startup task that logs artifact count/size and prunes entries older than 30 days (configurable via env var `ARTIFACT_TTL_DAYS`).

### 4.5 Virtual Rule List (addresses F-07)

After implementing F-06 (React.memo), measure actual render performance with 200+ rules visible. If section-open render time exceeds 50ms, introduce `@tanstack/react-virtual` with a fixed estimated row height. Given the accordion structure, apply virtualization per-section rather than globally.

---

## 5. Validation Plan

### Backend

#### Rule Loading Cache (F-02)
```bash
# Before: time the /rules/windows endpoint with repeated calls
ab -n 20 -c 5 http://localhost:8001/api/rules/windows

# After: same test — expect near-zero I/O on cached responses
# Also check: htop / Process Monitor for file handle counts
```

#### Windows Rule Lookup (F-01)
```bash
# Benchmark: generate a PS1 script for 20 windows rules
# Before: observe N×rglob calls in strace / Process Monitor
# After: observe 0 extra scans (index consulted directly)
time curl -X POST http://localhost:8001/api/generate \
  -H "Content-Type: application/json" \
  -d '{"os":"windows","rule_ids":[...20 ids...],"format":"powershell"}'
```

#### Async GPO (F-03)
```bash
# Concurrent request test: send two requests simultaneously
# Before: second request hangs until first PowerShell subprocess exits
# After: both requests proceed concurrently
curl ... & curl ... & wait
```

#### SHA256 Sidecar (F-04, F-05)
```python
# Unit test: write artifact, verify .sha256 sidecar exists and matches
# Measure: time _find_permanent_by_sha256() with 50 artifacts in store
import timeit
```

### Frontend

#### RuleCard Memoization (F-06)
```
# React DevTools Profiler:
# - Before: "Render" flame graph shows 200 RuleCard renders on single toggle
# - After: Only 1-2 RuleCard re-renders per toggle (the changed one + parent)
```

#### API Base URL (F-09)
```bash
# Smoke test: set VITE_API_BASE=http://staging:8001/api
# Run npm run build && serve the dist — verify all API calls go to staging
```

### Correctness Preservation
- Run all existing rules through the generate pipeline before and after caching changes — output must be byte-for-byte identical.
- For resolver: run the firewall conflict test with UFW + nftables rules selected — must still produce an error.
- For React.memo: verify that checking/unchecking a rule still visually updates the card immediately (no stale render).

---

## 6. Optimized Code / Patches

### Patch 6.1 — Rule Loader Cache (`rule_loader.py`)

```python
# Add to top of rule_loader.py (after imports)
import time

_cache: dict[str, tuple[dict, float]] = {}  # os_name → (grouped_result, timestamp)
_CACHE_TTL = 60.0  # seconds

def load_rules_grouped(os_name: str) -> Dict[str, List[RuleItem]]:
    """Return rules grouped by section (cached for TTL seconds)."""
    now = time.monotonic()
    if os_name in _cache:
        result, ts = _cache[os_name]
        if now - ts < _CACHE_TTL:
            return result

    rules = load_rules(os_name)
    grouped: Dict[str, List[RuleItem]] = {}
    for rule in rules:
        key = rule.section or "Other"
        grouped.setdefault(key, []).append(rule)

    _cache[os_name] = (grouped, now)
    return grouped
```

---

### Patch 6.2 — Windows Rule Index (`generator.py`)

```python
# Add module-level index, built on first use
_windows_rule_index: dict[str, dict] | None = None

def _get_windows_rule_index() -> dict[str, dict]:
    global _windows_rule_index
    if _windows_rule_index is not None:
        return _windows_rule_index

    index: dict[str, dict] = {}
    win_base = PROJECT_ROOT / "platforms" / "windows"
    for rules_dir in [win_base / "rules", win_base / "manual_rules"]:
        if not rules_dir.exists():
            continue
        for json_file in rules_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "rule_id" in data:
                    index[data["rule_id"]] = data
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    _windows_rule_index = index
    return index

# Replace _load_windows_rule_json:
def _load_windows_rule_json(rule_id: str) -> dict | None:
    return _get_windows_rule_index().get(rule_id)

# Replace _find_windows_rule_files:
def _find_windows_rule_files(rule_ids: List[str]) -> list[Path]:
    # NOTE: returns paths by re-scanning, but only once for all IDs
    index = _get_windows_rule_index()
    id_set = set(rule_ids)
    win_base = PROJECT_ROOT / "platforms" / "windows"
    files = []
    for rules_dir in [win_base / "rules", win_base / "manual_rules"]:
        if not rules_dir.exists():
            continue
        for json_file in rules_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("rule_id") in id_set:
                    files.append(json_file)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return files
    # BETTER ALTERNATIVE: also store paths in the index:
    # index[rule_id] = {"data": data, "path": json_file}
    # Then _find_windows_rule_files just does: [index[rid]["path"] for rid in rule_ids if rid in index]
```

---

### Patch 6.3 — SHA256 Sidecar (`generator.py`)

```python
# After writing the artifact file, store the SHA256 in a sidecar
def _save_artifact(out_dir: Path, content: str | bytes, filename: str, encoding="utf-8") -> tuple[Path, str]:
    out_path = out_dir / filename
    if isinstance(content, bytes):
        out_path.write_bytes(content)
    else:
        out_path.write_text(content, encoding=encoding)
    sha256 = _sha256(out_path)
    (out_dir / ".sha256").write_text(sha256, encoding="ascii")  # Sidecar
    return out_path, sha256

# Replace _find_permanent_by_sha256:
def _find_permanent_by_sha256(sha256: str) -> str | None:
    for art_dir in ARTIFACTS_DIR.iterdir():
        if not art_dir.is_dir() or not (art_dir / ".permanent").exists():
            continue
        sidecar = art_dir / ".sha256"
        if sidecar.exists():
            try:
                if sidecar.read_text().strip() == sha256:
                    return art_dir.name
            except OSError:
                continue
        # Fallback: compute from file (for old artifacts without sidecar)
        for f in art_dir.iterdir():
            if f.is_file() and not f.name.startswith((".", "_")):
                try:
                    if _sha256(f) == sha256:
                        return art_dir.name
                except OSError:
                    continue
    return None

# Update get_artifact_info to use sidecar:
def get_artifact_info(artifact_id: str) -> dict | None:
    if not is_artifact_permanent(artifact_id):
        return None
    art_dir = ARTIFACTS_DIR / artifact_id
    file_path = get_artifact_path(artifact_id)
    if not file_path or not file_path.exists():
        return None
    sidecar = art_dir / ".sha256"
    sha256 = sidecar.read_text().strip() if sidecar.exists() else _sha256(file_path)
    return {"filename": file_path.name, "sha256": sha256}
```

---

### Patch 6.4 — Literal Type for Format Field (`models.py`)

```python
from typing import Literal

class GenerateRequest(BaseModel):
    os: str
    rule_ids: list[str]
    format: Literal["ansible", "bash", "gpo", "powershell"] = "ansible"
    permanent: bool = False
```

Mirror in `types.ts`:
```typescript
export interface GenerateRequest {
  os: string;
  rule_ids: string[];
  format: "ansible" | "bash" | "gpo" | "powershell";
  permanent: boolean;
}
```

---

### Patch 6.5 — API Base URL via Env Var (`api.ts`)

```typescript
const API_HOST = import.meta.env.VITE_API_HOST ?? "http://localhost:8001";
const API_BASE = `${API_HOST}/api`;

// Fix downloadArtifact:
export function downloadArtifact(downloadUrl: string): void {
    const fullUrl = `${API_HOST}${downloadUrl}`;  // Clean construction
    const a = document.createElement("a");
    a.href = fullUrl;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}
```

Add `.env.example`:
```
VITE_API_HOST=http://localhost:8001
```

---

### Patch 6.6 — RuleCard Memoization (`RuleCard.tsx`)

```typescript
import { memo } from "react";

interface Props {
    rule: RuleItem;
    isSelected: boolean;          // Passed from parent, not read from global state
    onToggle: (id: string) => void;
    onInfoClick: (rule: RuleItem) => void;
}

const RuleCard = memo(function RuleCard({ rule, isSelected, onToggle, onInfoClick }: Props) {
    const { t } = useLocale();
    // No useHardening() call — isSelected comes from parent as stable prop
    ...
    return (
        <div
            className={`rule-card${isSelected ? " rule-card--selected" : ""}`}
            onClick={() => onToggle(rule.rule_id)}
        >
            ...
        </div>
    );
});

export default RuleCard;
```

In `RuleList.tsx`, pass `isSelected` explicitly:
```typescript
<RuleCard
    key={rule.rule_id}
    rule={rule}
    isSelected={state.selectedRuleIds.has(rule.rule_id)}
    onToggle={toggleRule}
    onInfoClick={onInfoClick}
/>
```

> **Note:** `state.selectedRuleIds.has(rule.rule_id)` is computed in the parent (which re-renders when the Set changes), so each card gets the correct boolean. `React.memo` then prevents re-render of cards whose `isSelected` didn't change.

---

*End of OPTIMIZATIONS.md*
