/* RuleList – groups rules by section with accordion expand/collapse */

import { useState, useMemo } from "react";
import { useHardening } from "../context/HardeningContext";
import RuleCard from "./RuleCard";
import type { RuleItem } from "../types";

interface Props {
    onInfoClick: (rule: RuleItem) => void;
}

export default function RuleList({ onInfoClick }: Props) {
    const { state, selectSection } = useHardening();
    const [openSections, setOpenSections] = useState<Set<string>>(new Set());

    // Apply filters
    const filteredSections = useMemo(() => {
        const result: Record<string, RuleItem[]> = {};
        const q = state.searchQuery.toLowerCase().trim();

        for (const [section, rules] of Object.entries(state.sections)) {
            const filtered = rules.filter((r) => {
                // Search filter
                if (q) {
                    const matchId = r.rule_id.toLowerCase().includes(q);
                    const matchTitle = r.title.toLowerCase().includes(q);
                    const matchCategory = r.category?.toLowerCase().includes(q);
                    if (!matchId && !matchTitle && !matchCategory) return false;
                }
                // Level filter
                if (state.levelFilter !== null && r.cis_level !== state.levelFilter) return false;
                // Automation filter
                if (state.automatedFilter !== null && r.automated !== state.automatedFilter) return false;
                return true;
            });
            if (filtered.length > 0) {
                result[section] = filtered;
            }
        }
        return result;
    }, [state.sections, state.searchQuery, state.levelFilter, state.automatedFilter]);

    const toggleSection = (section: string) => {
        setOpenSections((prev) => {
            const next = new Set(prev);
            if (next.has(section)) next.delete(section);
            else next.add(section);
            return next;
        });
    };

    const sectionKeys = Object.keys(filteredSections).sort();

    if (state.isLoading) {
        return (
            <div className="loading-container">
                <div className="loading-dots">
                    <span /><span /><span />
                </div>
                <span>Kurallar yükleniyor...</span>
            </div>
        );
    }

    if (state.error) {
        return (
            <div className="empty-state">
                <svg className="empty-state__icon" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" />
                </svg>
                <div className="empty-state__title">Hata</div>
                <div className="empty-state__text">{state.error}</div>
            </div>
        );
    }

    if (sectionKeys.length === 0) {
        return (
            <div className="empty-state">
                <svg className="empty-state__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <div className="empty-state__title">Kural bulunamadı</div>
                <div className="empty-state__text">Arama veya filtre kriterlerini değiştirin.</div>
            </div>
        );
    }

    return (
        <div>
            {sectionKeys.map((section) => {
                const rules = filteredSections[section];
                const isOpen = openSections.has(section);
                const allSelected = rules.every((r) => state.selectedRuleIds.has(r.rule_id));

                return (
                    <div key={section} className="section-group">
                        <div className="section-header" onClick={() => toggleSection(section)}>
                            <svg
                                className={`section-header__chevron${isOpen ? " section-header__chevron--open" : ""}`}
                                viewBox="0 0 24 24"
                                fill="currentColor"
                            >
                                <path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6z" />
                            </svg>
                            <span className="section-header__title">{section}</span>
                            <span className="section-header__count">{rules.length}</span>
                            <button
                                className="section-header__select-all"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    selectSection(section);
                                }}
                            >
                                {allSelected ? "Kaldır" : "Tümünü Seç"}
                            </button>
                        </div>

                        {isOpen && (
                            <div className="section-rules">
                                {rules.map((rule) => (
                                    <RuleCard key={rule.rule_id} rule={rule} onInfoClick={onInfoClick} />
                                ))}
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
}
