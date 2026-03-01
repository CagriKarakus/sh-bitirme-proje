# CLAUDE.md – CIS Benchmark Automation Framework

## Project Overview

Multi-platform **CIS Benchmark security hardening** framework. Provides automated audit/remediation rules for Linux, Windows, and Android, plus a web-based management interface.

## Tech Stack

| Layer | Technology |
|---|---|
| **Linux Rules** | Bash scripts (`audit.sh`, `remediation.sh`) + Ansible YAML |
| **Windows Rules** | JSON definitions → generated PowerShell / GPO via tools |
| **Web Backend** | Python 3, FastAPI 0.115, Pydantic 2.9, Uvicorn |
| **Web Frontend** | React 19, TypeScript ~5.9, Vite 7, Vanilla CSS |
| **Windows Tools** | PowerShell scripts (`generator.ps1`, `ps_script_builder.ps1`, `gpo_builder.ps1`, etc.) |
| **Python Tools** | `build_registry.py`, `compose_rule_scripts.py`, `compose_ansible.py`, `platform_detector.py` |

## Directory Structure

```
sh-bitirme-proje/
├── platforms/
│   ├── linux/
│   │   ├── ubuntu/{desktop,server}/rules/    # Bash audit.sh + remediation.sh per rule
│   │   └── common/rules/
│   ├── windows/
│   │   ├── rules/                            # JSON rule definitions (main)
│   │   │   ├── S1_Account_Policies/
│   │   │   ├── S2_Local_Policies/
│   │   │   ├── S5_System_Services/
│   │   │   ├── S9_Windows_Firewall/
│   │   │   ├── S17_Advanced_Audit_Policy/
│   │   │   ├── S18_Administrative_Templates/
│   │   │   ├── Manual/                       # Non-automatable rules
│   │   │   └── ...
│   │   ├── tools/                            # PowerShell generators
│   │   └── output/                           # Generated PS1/GPO artifacts
│   └── android/rules/
├── web/
│   ├── backend/                              # FastAPI app
│   │   ├── main.py                           # App entry point
│   │   ├── models.py                         # Pydantic schemas
│   │   ├── routers/rules.py                  # API endpoints
│   │   ├── services/                         # Business logic
│   │   │   ├── rule_loader.py                # Loads rules from filesystem
│   │   │   ├── resolver.py                   # Dependency/conflict checker
│   │   │   └── generator.py                  # Artifact generation (Ansible/Bash/PS1/GPO)
│   │   ├── artifacts/                        # Generated download artifacts
│   │   └── requirements.txt
│   └── frontend/                             # Vite + React + TS
│       └── src/
│           ├── App.tsx
│           ├── types.ts                      # Mirrors backend Pydantic models
│           ├── components/                   # React components
│           ├── context/                      # React Context state management
│           ├── pages/
│           ├── services/                     # API client
│           └── index.css                     # Global styles (Vanilla CSS)
├── Tools/                                    # Python CLI tools
├── docs/                                     # Architecture docs
│   └── WINDOWS_HARDENING_ARCHITECTURE.md     # Essential reference for Windows rules
└── dontremediate/                            # Ubuntu rules excluded from remediation
```

## Windows Rule JSON Schema

Rules live in `platforms/windows/rules/S*_*/X.X.X.json`. Required fields:

```json
{
  "rule_id": "X.X.X",
  "title": "CIS rule title",
  "description": "Detailed description",
  "cis_level": 1,
  "category": "Category Name",
  "subcategory": "Subcategory Name",
  "applies_to": ["Windows 11", "Windows Server 2022"],
  "automated": true,
  "registry_config": { "path": "HKLM:\\...", "value_name": "...", "value_type": "REG_DWORD", "value_data": 1, "comparison": "equals" },
  "gpo_config": { "policy_path": "Computer Configuration\\...", "setting_name": "...", "setting_value": 1, "admx_category": "..." },
  "implementation_local": { "powershell_command": "...", "powershell_script": "...", "requires_admin": true, "requires_reboot": false },
  "implementation_gpo": { "inf_section": "[System Access]", "inf_key": "...", "inf_value": "..." },
  "audit_logic": { "powershell_script": "... return $true/$false", "expected_result": true },
  "remediation_rollback": { "powershell_command": "...", "original_value": null },
  "impact": { "severity": "low|medium|high", "description": "..." },
  "rationale": "...",
  "references": [],
  "tags": []
}
```

**Important constraints:**
- `registry_config.path` must start with `HKLM:\\`
- `value_type` options: `REG_DWORD`, `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_QWORD`
- `comparison` options: `equals`, `less_than_or_equal`, `greater_than_or_equal`, `not_equals`, `exists`, `not_exists`
- `audit_logic` must return `$true` or `$false`
- PowerShell scripts must use `-ErrorAction SilentlyContinue`
- Manual (non-automatable) rules go in `platforms/windows/rules/Manual/`

## Linux Rule Structure

Each rule is a directory: `platforms/linux/ubuntu/{desktop,server}/rules/SX/X.X/X.X.X/`
- `audit.sh` — exits 0 (PASS) or 1 (FAIL)
- `remediation.sh` — applies the fix
- `README.md` — documentation

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/rules/{os_name}` | List rules grouped by section (`ubuntu` or `windows`) |
| `POST` | `/api/resolve` | Validate rule selection (dependencies/conflicts) |
| `POST` | `/api/generate` | Generate artifact (format: `ansible`, `bash`, `gpo`, `powershell`) |
| `GET` | `/api/download/{artifact_id}` | Download generated artifact |

## Running Locally

```bash
# Backend
cd web/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd web/frontend
npm install
npm run dev          # Vite dev server on :5173
npm run build        # Production build
npm run lint         # ESLint
```

## Conventions

- **Language**: Turkish for UI text, error messages, and comments; English for code identifiers and docs
- **Windows rule naming**: `S{N}_{Category}/{rule_id}.json` (e.g., `S1_Account_Policies/1.1.1.json`)
- **Frontend types** in `src/types.ts` must mirror backend `models.py` Pydantic schemas
- **No Tailwind** — use Vanilla CSS only (`index.css`)
- **Architecture doc**: Always read `docs/WINDOWS_HARDENING_ARCHITECTURE.md` before creating Windows rules
- **Workflow**: Use `/windows-hardening-rule` workflow for creating new Windows CIS rules

## Key Files to Know

- `docs/WINDOWS_HARDENING_ARCHITECTURE.md` — Windows hardening system design
- `platforms/windows/tools/generator.ps1` — Entry point for Windows script/GPO generation
- `platforms/windows/tools/ps_script_builder.ps1` — PowerShell standalone script builder
- `platforms/windows/tools/gpo_builder.ps1` — GPO backup package builder
- `web/backend/services/generator.py` — Backend artifact generation logic
- `web/backend/services/rule_loader.py` — Loads and parses rule files from disk
- `web/backend/services/resolver.py` — Dependency/conflict resolution engine
