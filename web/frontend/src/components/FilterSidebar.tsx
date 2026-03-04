/* FilterSidebar – search, CIS level filter, automated/manual toggle */

import { useHardening } from "../context/HardeningContext";
import { useLocale } from "../context/LocaleContext";
import LanguageToggle from "./LanguageToggle";

interface Props {
    mobileOpen?: boolean;
}

export default function FilterSidebar({ mobileOpen }: Props) {
    const {
        state,
        setSearch,
        setLevelFilter,
        setAutomatedFilter,
        selectAll,
        clearAll,
        resetAll,
    } = useHardening();
    const { t } = useLocale();

    const selectedCount = state.selectedRuleIds.size;
    const totalCount = state.rules.length;

    return (
        <aside className={`sidebar${mobileOpen ? " sidebar--mobile-open" : ""}`}>
            {/* Search */}
            <div>
                <div className="sidebar__section-title">{t("filter.search_title")}</div>
                <div className="search-box">
                    <svg className="search-box__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" />
                        <line x1="21" y1="21" x2="16.65" y2="16.65" />
                    </svg>
                    <input
                        type="text"
                        className="search-box__input"
                        placeholder={t("filter.search_placeholder")}
                        value={state.searchQuery}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
            </div>

            {/* CIS Level filter */}
            <div className="filter-group">
                <div className="sidebar__section-title">{t("filter.cis_level_title")}</div>
                <div className="filter-chips">
                    <button
                        className={`filter-chip${state.levelFilter === null ? " filter-chip--active" : ""}`}
                        onClick={() => setLevelFilter(null)}
                    >
                        {t("filter.all")}
                    </button>
                    <button
                        className={`filter-chip${state.levelFilter === 1 ? " filter-chip--active" : ""}`}
                        onClick={() => setLevelFilter(1)}
                    >
                        Level 1
                    </button>
                    <button
                        className={`filter-chip${state.levelFilter === 2 ? " filter-chip--active" : ""}`}
                        onClick={() => setLevelFilter(2)}
                    >
                        Level 2
                    </button>
                </div>
            </div>

            {/* Automated / Manual */}
            <div className="filter-group">
                <div className="sidebar__section-title">{t("filter.automation_title")}</div>
                <div className="filter-chips">
                    <button
                        className={`filter-chip${state.automatedFilter === null ? " filter-chip--active" : ""}`}
                        onClick={() => setAutomatedFilter(null)}
                    >
                        {t("filter.all")}
                    </button>
                    <button
                        className={`filter-chip${state.automatedFilter === true ? " filter-chip--active" : ""}`}
                        onClick={() => setAutomatedFilter(true)}
                    >
                        {t("filter.automated")}
                    </button>
                    <button
                        className={`filter-chip${state.automatedFilter === false ? " filter-chip--active" : ""}`}
                        onClick={() => setAutomatedFilter(false)}
                    >
                        {t("filter.manual")}
                    </button>
                </div>
            </div>

            {/* Quick actions */}
            <div className="filter-group">
                <div className="sidebar__section-title">
                    {t("filter.selection_title", { selected: selectedCount, total: totalCount })}
                </div>
                <button className="btn btn--secondary" onClick={selectAll} style={{ fontSize: "0.8rem", padding: "8px" }}>
                    {t("actions.select_all")}
                </button>
                <button className="btn btn--secondary" onClick={clearAll} style={{ fontSize: "0.8rem", padding: "8px" }}>
                    {t("actions.clear_selection")}
                </button>
                <button className="btn btn--danger" onClick={resetAll} style={{ fontSize: "0.8rem", padding: "8px" }}>
                    {t("actions.reset_all")}
                </button>
            </div>

            {/* Language toggle – pushed to bottom via margin-top: auto */}
            <LanguageToggle />
        </aside>
    );
}
