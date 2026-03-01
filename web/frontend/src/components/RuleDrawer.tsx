/* RuleDrawer – sliding panel that opens when a rule's info button is clicked */

import { useEffect } from "react";
import type { RuleItem } from "../types";
import { useLocale } from "../context/LocaleContext";

interface Props {
    rule: RuleItem | null;
    onClose: () => void;
    onOpenDetail: (rule: RuleItem) => void;
}

export default function RuleDrawer({ rule, onClose, onOpenDetail }: Props) {
    const { t } = useLocale();
    const isOpen = rule !== null;

    // Close on Escape key
    useEffect(() => {
        const handleKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") onClose();
        };
        if (isOpen) document.addEventListener("keydown", handleKey);
        return () => document.removeEventListener("keydown", handleKey);
    }, [isOpen, onClose]);

    // Prevent body scroll when open
    useEffect(() => {
        document.body.style.overflow = isOpen ? "hidden" : "";
        return () => { document.body.style.overflow = ""; };
    }, [isOpen]);

    return (
        <>
            {/* Backdrop */}
            <div
                className={`drawer-backdrop${isOpen ? " drawer-backdrop--visible" : ""}`}
                onClick={onClose}
            />

            {/* Panel */}
            <aside className={`rule-drawer${isOpen ? " rule-drawer--open" : ""}`}>
                {rule && (
                    <>
                        {/* Header */}
                        <div className="rule-drawer__header">
                            <div className="rule-drawer__header-left">
                                <span className="rule-drawer__rule-id">{rule.rule_id}</span>
                                {rule.cis_level && (
                                    <span className={`rule-card__badge rule-card__badge--level-${rule.cis_level}`}>
                                        L{rule.cis_level}
                                    </span>
                                )}
                                <span className={`rule-card__badge ${rule.automated ? "rule-card__badge--automated" : "rule-card__badge--manual"}`}>
                                    {rule.automated ? t("drawer.automated") : t("drawer.manual")}
                                </span>
                            </div>
                            <button className="rule-drawer__close" onClick={onClose} aria-label={t("drawer.close_aria")}>
                                <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
                                    <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
                                </svg>
                            </button>
                        </div>

                        {/* Title */}
                        <h2 className="rule-drawer__title">{rule.title}</h2>

                        {/* Meta row */}
                        <div className="rule-drawer__meta">
                            {rule.severity && (
                                <div className="rule-drawer__meta-item">
                                    <span className="rule-drawer__meta-label">{t("drawer.severity_label")}</span>
                                    <span className={`rule-card__severity rule-card__severity--${rule.severity}`}>
                                        {rule.severity}
                                    </span>
                                </div>
                            )}
                            {rule.category && (
                                <div className="rule-drawer__meta-item">
                                    <span className="rule-drawer__meta-label">{t("drawer.category_label")}</span>
                                    <span className="rule-drawer__meta-value">{rule.category}</span>
                                </div>
                            )}
                            {rule.subcategory && (
                                <div className="rule-drawer__meta-item">
                                    <span className="rule-drawer__meta-label">{t("drawer.subcategory_label")}</span>
                                    <span className="rule-drawer__meta-value">{rule.subcategory}</span>
                                </div>
                            )}
                            <div className="rule-drawer__meta-item">
                                <span className="rule-drawer__meta-label">{t("drawer.section_label")}</span>
                                <span className="rule-drawer__meta-value">{rule.section}</span>
                            </div>
                        </div>

                        {/* Brief description placeholder */}
                        <div className="rule-drawer__section">
                            <h3 className="rule-drawer__section-title">{t("drawer.description_title")}</h3>
                            <p className="rule-drawer__placeholder">
                                {t("drawer.description_placeholder")}
                            </p>
                        </div>

                        {/* Spacer */}
                        <div style={{ flex: 1 }} />

                        {/* Footer */}
                        <div className="rule-drawer__footer">
                            <button
                                className="rule-drawer__detail-btn"
                                onClick={() => {
                                    onClose();
                                    onOpenDetail(rule);
                                }}
                            >
                                <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />
                                </svg>
                                {t("drawer.detail_btn")}
                            </button>
                        </div>
                    </>
                )}
            </aside>
        </>
    );
}
