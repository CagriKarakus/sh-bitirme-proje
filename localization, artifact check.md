# Localization & Artifact Persistence — Session Notes

## What Was Done

This session covered two feature areas: **artifact persistence with cleanup** and **UI/UX refinement of the Save & Share control**.

---

## 1. Artifact Persistence & Cleanup System

### Problem
Artifacts were stored indefinitely in `web/backend/artifacts/{artifact_id}/`. Users who only needed a one-time download were wasting server storage permanently.

### Solution: Marker-File Approach
A `.permanent` empty file inside `artifacts/{artifact_id}/` distinguishes permanent from temporary artifacts. No database is required.

### Files Changed

#### `web/backend/services/generator.py`
- Added `_mark_permanent(artifact_id)` — creates `.permanent` marker file.
- Added `is_artifact_permanent(artifact_id)` — checks for marker existence.
- Added `delete_artifact(artifact_id)` — removes the entire artifact directory (used as a FastAPI `BackgroundTask`).
- Added `_find_permanent_by_sha256(sha256)` — scans all permanent artifacts and returns a matching `artifact_id` if an identical file (by SHA-256) already exists. Used for duplicate prevention.
- Modified `generate(os_name, rule_ids, fmt, permanent=False)`:
  - When `permanent=True`: checks for a duplicate via SHA-256 first.
    - **Duplicate found**: deletes the newly generated directory, returns the existing `artifact_id`.
    - **No duplicate**: marks the new artifact as permanent.
- Modified `get_artifact_info(artifact_id)` — now returns `None` for non-permanent artifacts, so temporary artifacts are invisible to the search panel.

#### `web/backend/models.py`
- `GenerateRequest` — added `permanent: bool = False`.
- `GenerateResponse` — added `artifact_id: str | None = None` (only populated when `permanent=True`).

#### `web/backend/routers/rules.py`
- `POST /api/generate` — passes `permanent=req.permanent` to `generate()`; returns `artifact_id` in response only when permanent.
- `GET /api/download/{artifact_id}` — added `BackgroundTasks` parameter; schedules `delete_artifact()` to run after the `FileResponse` is fully sent for temporary artifacts. Permanent artifacts are left untouched.

#### `web/frontend/src/types.ts`
- `GenerateRequest` — added `permanent: boolean`.
- `GenerateResponse` — added `artifact_id: string | null`.

#### `web/frontend/src/services/api.ts`
- `generateConfig()` — added `permanent: boolean = false` parameter; included in POST body.

#### `web/frontend/src/context/HardeningContext.tsx`
- `runGenerate(permanent?: boolean)` — signature updated to accept and forward the flag to `generateConfig()`.

#### `web/frontend/src/components/ValidationPanel.tsx`
- Added `useState<boolean>(false)` for the `permanent` flag.
- Added the Save & Share toggle UI.
- Download button calls `runGenerate(permanent)`.
- Share code box appears below the download button when `generateResult.artifact_id` is truthy, showing the 12-character code with a copy-to-clipboard button.

#### `web/frontend/src/locales/tr.json` + `en.json`
Added 5 new keys under `validation`:

| Key | TR | EN |
|---|---|---|
| `shareable_toggle` | Kaydet & Paylaş | Save & Share |
| `shareable_hint` | Diğer kullanıcıların bu artifact'ı bulup indirebilmesi için paylaşım kodu oluşturur. | Generates a share code so others can find and download this artifact. |
| `shareable_code_label` | Paylaşım Kodu: | Share Code: |
| `shareable_code_hint` | Bu kodu 'Artifact Ara' panelinde girerek artifact'ı yeniden indirebilirsiniz. | Enter this code in the 'Find Artifact' panel to download it again. |
| `shareable_copy` | Kopyala | Copy |

#### `web/frontend/src/index.css`
Added two CSS blocks:
- `.vp-shareable-toggle` — initially a prominent bordered card; later replaced (see Section 2).
- `.vp-share-box` — the share code display box with copy button.

---

## 2. Save & Share UI Refinement

### Changes Requested
1. Move toggle **below** the Generate Artifact button (was above it).
2. Make it significantly smaller and more subtle.
3. Rename label — remove the word "Permanently".
4. Add SHA-256-based duplicate prevention on the backend.

### Files Changed

#### `web/backend/services/generator.py`
- Duplicate check logic added via `_find_permanent_by_sha256()` (see above).
- `generate()` updated: on duplicate detection, the newly created artifact directory is deleted and the existing `artifact_id` is returned transparently.

#### `web/frontend/src/components/ValidationPanel.tsx`
- Toggle block moved to appear **after** the Generate Artifact `<button>`.
- Simplified markup: `checkbox + 🔗 icon + label` in a single flat row (no nested `<div>`).
- The hint text is surfaced as a native `title` tooltip on the `<label>` instead of rendered inline, keeping the control compact.

#### `web/frontend/src/index.css`
`.vp-shareable-toggle` restyled to be small and unobtrusive:
- `inline-flex`, `align-self: flex-start` — does not stretch to full width.
- No border, no background panel.
- Font size `0.72rem`, colour `var(--text-muted)` — turns `var(--accent)` when checked.
- 12×12 px checkbox.
- `:hover` reduces opacity slightly as the only interaction cue.

#### `web/frontend/src/locales/tr.json` + `en.json`
- `shareable_toggle`: `"Kalıcı Kaydet & Paylaş"` → `"Kaydet & Paylaş"`
- `shareable_toggle`: `"Save & Share Permanently"` → `"Save & Share"`

---

## Flow Summary

### Temporary artifact (default)
1. User generates without checking the toggle.
2. Backend returns `artifact_id: null` in `GenerateResponse`.
3. User downloads → `BackgroundTask` deletes the artifact directory after the response is sent.
4. Re-visiting the download URL returns **404**.
5. Entering the ID in ArtifactSearchPanel returns **not found** (search isolation via `get_artifact_info`).

### Permanent artifact
1. User checks "Kaydet & Paylaş" before clicking Generate.
2. Backend generates the file, checks for a SHA-256 duplicate among existing permanent artifacts.
   - **Duplicate**: discards new directory, reuses existing `artifact_id`.
   - **New**: stamps `.permanent` marker.
3. `GenerateResponse.artifact_id` is populated with the 12-character code.
4. Share code box appears in the UI with a copy button.
5. Download does **not** delete the artifact.
6. The code can be entered in ArtifactSearchPanel to retrieve the artifact later.
