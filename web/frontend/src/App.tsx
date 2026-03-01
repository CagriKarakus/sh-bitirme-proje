/* Main App component – assembles the full dashboard layout */

import { useState } from "react";
import { HardeningProvider, useHardening } from "./context/HardeningContext";
import { LocaleProvider, useLocale } from "./context/LocaleContext";
import OsSelector from "./components/OsSelector";
import FilterSidebar from "./components/FilterSidebar";
import RuleList from "./components/RuleList";
import ValidationPanel from "./components/ValidationPanel";
import ArtifactSearchPanel from "./components/ArtifactSearchPanel";
import RuleDrawer from "./components/RuleDrawer";
import RuleDetailPage from "./pages/RuleDetailPage";
import type { RuleItem } from "./types";
import "./index.css";

function Dashboard() {
  const { state, runResolve } = useHardening();
  const { t } = useLocale();
  const selectedCount = state.selectedRuleIds.size;

  const [drawerRule, setDrawerRule] = useState<RuleItem | null>(null);
  const [detailRule, setDetailRule] = useState<RuleItem | null>(null);

  return (
    <>
      {/* Header */}
      <header className="app-header">
        <div className="app-header__logo">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
          </svg>
          <div>
            <div className="app-header__title">CIS Hardening Platform</div>
            <div className="app-header__subtitle">{t("app.subtitle")}</div>
          </div>
        </div>
        <div className="app-header__spacer" />
        <OsSelector />
      </header>

      {/* Sidebar */}
      <FilterSidebar />

      {/* Main content */}
      <main className="main-content">
        {/* Stats bar */}
        <div className="stats-bar">
          <div className="stats-bar__item">
            <span className="stats-bar__value">{state.rules.length}</span>
            <span className="stats-bar__label">{t("stats.total_rules")}</span>
          </div>
          <div className="stats-bar__divider" />
          <div className="stats-bar__item">
            <span className="stats-bar__value">{selectedCount}</span>
            <span className="stats-bar__label">{t("stats.selected")}</span>
          </div>
          <div className="stats-bar__divider" />
          <div className="stats-bar__item">
            <span className="stats-bar__value">{Object.keys(state.sections).length}</span>
            <span className="stats-bar__label">{t("stats.sections")}</span>
          </div>

          <div style={{ flex: 1 }} />

          {/* Calculate (Hesapla) button */}
          <button
            className="btn btn--primary"
            onClick={runResolve}
            disabled={selectedCount === 0 || state.isResolving}
          >
            {state.isResolving ? (
              <>
                <span className="btn__spinner" />
                {t("actions.calculating")}
              </>
            ) : (
              <>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.6 3.6 0 0112 15.6z" />
                </svg>
                {t("actions.calculate", { count: selectedCount })}
              </>
            )}
          </button>
        </div>

        {/* Artifact search */}
        <ArtifactSearchPanel />

        {/* Validation results */}
        <ValidationPanel />

        {/* Rule list */}
        <RuleList onInfoClick={setDrawerRule} />
      </main>

      {/* Rule info drawer */}
      <RuleDrawer
        rule={drawerRule}
        onClose={() => setDrawerRule(null)}
        onOpenDetail={(rule) => setDetailRule(rule)}
      />

      {/* Rule detail full-page overlay */}
      {detailRule && (
        <RuleDetailPage rule={detailRule} onClose={() => setDetailRule(null)} />
      )}
    </>
  );
}

export default function App() {
  return (
    <LocaleProvider>
      <HardeningProvider>
        <div className="app-layout">
          <Dashboard />
        </div>
      </HardeningProvider>
    </LocaleProvider>
  );
}
