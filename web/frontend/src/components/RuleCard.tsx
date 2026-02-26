/* RuleCard – individual rule display with checkbox */

import type { RuleItem } from "../types";
import { useHardening } from "../context/HardeningContext";

interface Props {
    rule: RuleItem;
}

export default function RuleCard({ rule }: Props) {
    const { state, toggleRule } = useHardening();
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
                        {rule.automated ? "Otomatik" : "Manuel"}
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
        </div>
    );
}
