/* ComplianceDashboard – main compliance overview grid */

import { useLocale } from "../context/LocaleContext";
import { useComplianceStats } from "../hooks/useComplianceStats";
import ScoreRing from "./ScoreRing";
import SectionCoverage from "./SectionCoverage";
import LevelBreakdown from "./LevelBreakdown";
import SeverityBreakdown from "./SeverityBreakdown";

export default function ComplianceDashboard() {
  const { t } = useLocale();
  const stats = useComplianceStats();

  if (stats.selectedCount === 0) {
    return (
      <div className="dashboard-empty">
        <div className="dashboard-empty__icon">📊</div>
        <div className="dashboard-empty__title">{t("dashboard.no_selection")}</div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      {/* Score section */}
      <div className="dashboard__score-section">
        <h2 className="dashboard__title">{t("dashboard.title")}</h2>
        <div className="dashboard__score-wrap">
          <ScoreRing score={stats.overallScore} size={160} label={t("dashboard.overall_score")} />
          <div className="dashboard__score-meta">
            <div className="dashboard__meta-item">
              <span className="dashboard__meta-value">{stats.selectedCount}</span>
              <span className="dashboard__meta-label">{t("stats.selected")}</span>
            </div>
            <div className="dashboard__meta-divider" />
            <div className="dashboard__meta-item">
              <span className="dashboard__meta-value">{stats.totalRules}</span>
              <span className="dashboard__meta-label">{t("stats.total_rules")}</span>
            </div>
            <div className="dashboard__meta-divider" />
            <div className="dashboard__meta-item">
              <span className="dashboard__meta-value">{stats.automatedCount}</span>
              <span className="dashboard__meta-label">{t("dashboard.automated_vs_manual")}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Panels grid */}
      <div className="dashboard__panels">
        <SectionCoverage sections={stats.sections} />
        <div className="dashboard__panels-right">
          <LevelBreakdown level1={stats.level1} level2={stats.level2} />
          <SeverityBreakdown high={stats.high} medium={stats.medium} low={stats.low} />
        </div>
      </div>
    </div>
  );
}
