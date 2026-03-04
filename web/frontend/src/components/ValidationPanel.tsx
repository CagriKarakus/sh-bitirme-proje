/* ValidationPanel – resolve results, format selection, generate, SHA256, download, verify checklist */

import { useState } from "react";
import { useHardening } from "../context/HardeningContext";
import { useLocale } from "../context/LocaleContext";
import { useToast } from "../context/ToastContext";
import { downloadArtifact } from "../services/api";

export default function ValidationPanel() {
    const { state, runResolve, runGenerate, setFormat } = useHardening();
    const { t } = useLocale();
    const { addToast } = useToast();
    const [permanent, setPermanent] = useState(false);
    const {
        selectedRuleIds,
        validationResult,
        isResolving,
        isGenerating,
        generateResult,
        selectedOS,
        selectedFormat,
    } = state;

    const FORMAT_OPTIONS = {
        ubuntu: [
            { value: "ansible", label: "Ansible Playbook", ext: ".yml", icon: "📘" },
            { value: "bash", label: "Bash Script", ext: ".sh", icon: "🐧" },
        ],
        windows: [
            { value: "powershell", label: "PowerShell Script", ext: ".ps1", icon: "⚡" },
            { value: "gpo", label: "GPO Backup", ext: ".zip", icon: "🏛️" },
        ],
    } as const;

    const count = selectedRuleIds.size;
    const hasErrors = validationResult?.errors && validationResult.errors.length > 0;
    const isValid = validationResult && !hasErrors;
    const formats = FORMAT_OPTIONS[selectedOS] || [];

    return (
        <div className="validation-panel">
            {/* ── Resolve (Hesapla) ──────────────────────────────────── */}
            <div className="vp-section">
                <h3 className="vp-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M9 11l3 3L22 4" />
                        <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
                    </svg>
                    {t("validation.title")}
                </h3>

                <button
                    className="vp-btn vp-btn--resolve"
                    disabled={count === 0 || isResolving}
                    onClick={runResolve}
                    id="btn-resolve"
                >
                    {isResolving ? (
                        <>
                            <span className="spinner" />
                            {t("validation.calculating")}
                        </>
                    ) : (
                        <>{t("validation.calculate", { count })}</>
                    )}
                </button>

                {validationResult && (
                    <div className="vp-results">
                        {validationResult.warnings.map((w, i) => (
                            <div key={`w-${i}`} className="vp-msg vp-msg--warn">
                                <span className="vp-icon">⚠️</span>
                                <div>
                                    <strong>{w.rule_id}</strong>
                                    <p>{w.message}</p>
                                    {w.missing_dependency && (
                                        <code>{t("validation.missing_dep", { missing: w.missing_dependency })}</code>
                                    )}
                                </div>
                            </div>
                        ))}

                        {validationResult.errors.map((e, i) => (
                            <div key={`e-${i}`} className="vp-msg vp-msg--error">
                                <span className="vp-icon">❌</span>
                                <div>
                                    <strong>{e.rule_id}</strong>
                                    <p>{e.message}</p>
                                    <code>{t("validation.conflicting_rule", { conflicting: e.conflicting_rule })}</code>
                                </div>
                            </div>
                        ))}

                        {isValid && validationResult.warnings.length === 0 && (
                            <div className="vp-msg vp-msg--success">
                                <span className="vp-icon">✅</span>
                                <p>{t("validation.success")}</p>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* ── Generate Artifact ─────────────────────────────────── */}
            {isValid && (
                <div className="vp-section vp-generate">
                    <h3 className="vp-title">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="12" y1="18" x2="12" y2="12" />
                            <line x1="9" y1="15" x2="12" y2="12" />
                            <line x1="15" y1="15" x2="12" y2="12" />
                        </svg>
                        {t("validation.generate_title")}
                    </h3>

                    {/* ── Format Selector ──────────────────────────────── */}
                    <div className="vp-format-selector">
                        <span className="vp-format-label">{t("validation.format_label")}</span>
                        <div className="vp-format-options">
                            {formats.map((f) => (
                                <label
                                    key={f.value}
                                    className={`vp-format-option ${selectedFormat === f.value ? "vp-format-option--active" : ""}`}
                                >
                                    <input
                                        type="radio"
                                        name="generate-format"
                                        value={f.value}
                                        checked={selectedFormat === f.value}
                                        onChange={() => setFormat(f.value)}
                                    />
                                    <span className="vp-format-icon">{f.icon}</span>
                                    <span className="vp-format-name">{f.label}</span>
                                    <span className="vp-format-ext">{f.ext}</span>
                                </label>
                            ))}
                        </div>
                    </div>

                    <button
                        className="vp-btn vp-btn--generate"
                        disabled={isGenerating}
                        onClick={() => runGenerate(permanent)}
                        id="btn-generate"
                    >
                        {isGenerating ? (
                            <>
                                <span className="spinner" />
                                {t("validation.generating")}
                            </>
                        ) : (
                            <>
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                                    <polyline points="7 10 12 15 17 10" />
                                    <line x1="12" y1="15" x2="12" y2="3" />
                                </svg>
                                {t("validation.generate_btn")}
                            </>
                        )}
                    </button>

                    {/* ── Save & Share Toggle (subtle, below primary action) ── */}
                    <label className="vp-shareable-toggle" title={t("validation.shareable_hint")}>
                        <input
                            type="checkbox"
                            checked={permanent}
                            onChange={(e) => setPermanent(e.target.checked)}
                        />
                        <span className="vp-shareable-toggle__icon">🔗</span>
                        <span className="vp-shareable-toggle__label">{t("validation.shareable_toggle")}</span>
                    </label>

                    {/* ── Generate Result ──────────────────────────────── */}
                    {generateResult && generateResult.success && (
                        <div className="vp-artifact-result">
                            <div className="vp-msg vp-msg--success">
                                <span className="vp-icon">🎉</span>
                                <p>{generateResult.message}</p>
                            </div>

                            <div className="vp-file-info">
                                <div className="vp-file-row">
                                    <span className="vp-label">{t("validation.file_label")}</span>
                                    <code className="vp-value">{generateResult.filename}</code>
                                </div>
                                <div className="vp-file-row">
                                    <span className="vp-label">{t("validation.sha_label")}</span>
                                    <code className="vp-value vp-sha256">{generateResult.sha256}</code>
                                </div>
                            </div>

                            {generateResult.download_url && (
                                <button
                                    className="vp-btn vp-btn--download"
                                    onClick={() => downloadArtifact(generateResult.download_url!)}
                                    id="btn-download"
                                >
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                                        <polyline points="7 10 12 15 17 10" />
                                        <line x1="12" y1="15" x2="12" y2="3" />
                                    </svg>
                                    {t("validation.download_btn")}
                                </button>
                            )}

                            {generateResult.artifact_id ? (
                                <div className="vp-share-box">
                                    <span className="vp-label">{t("validation.shareable_code_label")}</span>
                                    <code className="vp-share-box__code">{generateResult.artifact_id}</code>
                                    <button
                                        className="vp-share-box__copy"
                                        onClick={() => {
                                            navigator.clipboard.writeText(generateResult.artifact_id!);
                                            addToast(t("toast.copy_success"), "success");
                                        }}
                                    >
                                        {t("validation.shareable_copy")}
                                    </button>
                                    <p className="vp-share-box__hint">{t("validation.shareable_code_hint")}</p>
                                </div>
                            ) : (
                                <p className="vp-not-saved-hint">{t("validation.not_saved_hint")}</p>
                            )}

                            {/* ── Verify Checklist ────────────────────────── */}
                            <div className="vp-checklist">
                                <h4 className="vp-checklist-title">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                                        <path d="M9 11l3 3L22 4" />
                                    </svg>
                                    {t("validation.checklist_title")}
                                </h4>

                                <ul className="vp-checklist-list">
                                    <li>
                                        <span className="vp-check">☐</span>
                                        {t("validation.checklist_sha")}
                                    </li>
                                    <li>
                                        <span className="vp-check">☐</span>
                                        {selectedFormat === "ansible"
                                            ? t("validation.checklist_ansible")
                                            : selectedFormat === "bash"
                                                ? t("validation.checklist_bash")
                                                : selectedFormat === "gpo"
                                                    ? t("validation.checklist_gpo")
                                                    : t("validation.checklist_powershell")}
                                    </li>
                                    <li>
                                        <span className="vp-check">☐</span>
                                        {t("validation.checklist_verify")}
                                    </li>
                                    <li>
                                        <span className="vp-check">☐</span>
                                        {t("validation.checklist_backup")}
                                    </li>
                                    <li>
                                        <span className="vp-check">☐</span>
                                        {t("validation.checklist_audit")}
                                    </li>
                                </ul>
                            </div>
                        </div>
                    )}

                    {generateResult && !generateResult.success && (
                        <div className="vp-msg vp-msg--error">
                            <span className="vp-icon">❌</span>
                            <p>{generateResult.message}</p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
