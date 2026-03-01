/* RuleCard – individual rule display with checkbox and info button */

import type { RuleItem } from "../types";
import { useHardening } from "../context/HardeningContext";
import { useLocale } from "../context/LocaleContext";

interface Props {
    rule: RuleItem;
    onInfoClick: (rule: RuleItem) => void;
}

export default function RuleCard({ rule, onInfoClick }: Props) {
    const { state, toggleRule } = useHardening();
    const { t } = useLocale();
    const isSelected = state.selectedRuleIds.has(rule.rule_id);

    return (
        <div
            className={`rule-card${isSelected ? " rule-card--selected" : ""}`}
            onClick={() => toggleRule(rule.rule_id)}
        >
            {/* Checkbox */}
            <label className="rule-card__checkbox" onClick={(e) => e.stopPropagation()}>
                <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggleRule(rule.rule_id)}
                />
                <span className="rule-card__checkbox-visual" />
            </label>

            {/* Body */}
            <div className="rule-card__body">
                <div className="rule-card__header">
                    <span className="rule-card__id">{rule.rule_id}</span>
                </div>
                <div className="rule-card__title">{rule.title}</div>

                <div className="rule-card__meta">
                    {/* CIS Level badge */}
                    {rule.cis_level && (
                        <span
                            className={`rule-card__badge rule-card__badge--level-${rule.cis_level}`}
                        >
                            L{rule.cis_level}
                        </span>
                    )}

                    {/* Automated / Manual */}
                    <span
                        className={`rule-card__badge ${rule.automated
                                ? "rule-card__badge--automated"
                                : "rule-card__badge--manual"
                            }`}
                    >
                        {rule.automated ? t("rule_card.automated") : t("rule_card.manual")}
                    </span>

                    {/* Severity */}
                    {rule.severity && (
                        <span className={`rule-card__severity rule-card__severity--${rule.severity}`}>
                            {rule.severity}
                        </span>
                    )}

                    {/* Category as small text */}
                    {rule.subcategory && (
                        <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>
                            {rule.subcategory}
                        </span>
                    )}
                </div>
            </div>

            {/* Info button */}
            <button
                className="rule-card__info-btn"
                title={t("rule_card.info_title")}
                onClick={(e) => {
                    e.stopPropagation();
                    onInfoClick(rule);
                }}
                aria-label={t("rule_card.info_aria")}
            >
                <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />
                </svg>
            </button>
        </div>
    );
}
