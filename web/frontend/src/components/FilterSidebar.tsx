/* FilterSidebar – search, CIS level filter, automated/manual toggle */

import { useHardening } from "../context/HardeningContext";

export default function FilterSidebar() {
    const {
        state,
        setSearch,
        setLevelFilter,
        setAutomatedFilter,
        selectAll,
        clearAll,
    } = useHardening();

    const selectedCount = state.selectedRuleIds.size;
    const totalCount = state.rules.length;

    return (
        <aside className="sidebar">
            {/* Search */}
            <div>
                <div className="sidebar__section-title">Ara</div>
                <div className="search-box">
                    <svg className="search-box__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" />
                        <line x1="21" y1="21" x2="16.65" y2="16.65" />
                    </svg>
                    <input
                        type="text"
                        className="search-box__input"
                        placeholder="Kural ID veya başlık ara..."
                        value={state.searchQuery}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
            </div>

            {/* CIS Level filter */}
            <div className="filter-group">
                <div className="sidebar__section-title">CIS Seviyesi</div>
                <div className="filter-chips">
                    <button
                        className={`filter-chip${state.levelFilter === null ? " filter-chip--active" : ""}`}
                        onClick={() => setLevelFilter(null)}
                    >
                        Tümü
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
                <div className="sidebar__section-title">Otomasyon</div>
                <div className="filter-chips">
                    <button
                        className={`filter-chip${state.automatedFilter === null ? " filter-chip--active" : ""}`}
                        onClick={() => setAutomatedFilter(null)}
                    >
                        Tümü
                    </button>
                    <button
                        className={`filter-chip${state.automatedFilter === true ? " filter-chip--active" : ""}`}
                        onClick={() => setAutomatedFilter(true)}
                    >
                        Otomatik
                    </button>
                    <button
                        className={`filter-chip${state.automatedFilter === false ? " filter-chip--active" : ""}`}
                        onClick={() => setAutomatedFilter(false)}
                    >
                        Manuel
                    </button>
                </div>
            </div>

            {/* Quick actions */}
            <div className="filter-group">
                <div className="sidebar__section-title">
                    Seçim ({selectedCount} / {totalCount})
                </div>
                <button className="btn btn--secondary" onClick={selectAll} style={{ fontSize: "0.8rem", padding: "8px" }}>
                    Tümünü Seç
                </button>
                <button className="btn btn--secondary" onClick={clearAll} style={{ fontSize: "0.8rem", padding: "8px" }}>
                    Seçimi Temizle
                </button>
            </div>
        </aside>
    );
}
