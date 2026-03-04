# AGENTS.md

## Must-follow constraints

- **UI text in Turkish, code in English.** All user-facing strings (labels, errors, toasts) must be Turkish. Code identifiers, comments in code, and docs use English.
- **No Tailwind.** Frontend uses Vanilla CSS only (`web/frontend/src/index.css`). Do not add CSS utility frameworks.
- **Frontend types must mirror backend models.** `web/frontend/src/types.ts` must stay in sync with `web/backend/models.py`. Change both when modifying API contracts.
- **i18n via locale JSON files.** All UI strings go in `src/locales/tr.json` and `src/locales/en.json`, not hardcoded in components. `tr.json` is the type anchor.
- **Windows rule JSON placement:** `platforms/windows/rules/S{N}_{Category}/{rule_id}.json`. Non-automatable rules go in `platforms/windows/rules/Manual/`.
- **Windows rule constraints:**
  - `registry_config.path` must start with `HKLM:\\`
  - `audit_logic` PowerShell must return `$true` or `$false`
  - PowerShell scripts must use `-ErrorAction SilentlyContinue`
- **Read `docs/WINDOWS_HARDENING_ARCHITECTURE.md` before creating any Windows rule.**

## Validation before finishing

```bash
# Frontend
cd web/frontend && npx tsc -b && npx eslint .

# Backend (no test suite — just verify syntax)
cd web/backend && python -c "from main import app"
```

## Repo-specific conventions

- Package manager: **npm** (not pnpm/yarn) for frontend
- CSS variables: `--sp-xs/sm/md/lg/xl`, `--radius-sm/md`, `--accent`, `--bg-*`, `--text-*`, `--border`
- i18n hook: `useLocale()` from `src/context/LocaleContext.tsx` returns `{ locale, setLocale, t }`
- `t(key, vars?)` uses `{placeholder}` interpolation syntax
- State management: React Context (`src/context/HardeningContext.tsx`), no Redux
- API base: backend on `:8000`, frontend dev on `:5173`
- Linux rule structure: `platforms/linux/ubuntu/{desktop,server}/rules/SX/X.X/X.X.X/` containing `audit.sh` (exit 0=PASS, 1=FAIL) + `remediation.sh`

## Known gotchas

- `react-refresh/only-export-components` lint warnings in context files (`HardeningContext.tsx`, `LocaleContext.tsx`) are expected — do not "fix" them
- `web/frontend/src/locales/tr.json` is the **type anchor** for i18n keys. Add keys there first; `en.json` must match the same structure
- Generated artifacts go to `web/backend/artifacts/` — this directory is gitignored
