/* LevelBreakdown – L1 vs L2 comparison cards */

import { useLocale } from "../context/LocaleContext";

interface LevelStat {
  selected: number;
  total: number;
}

interface Props {
  level1: LevelStat;
  level2: LevelStat;
}

function LevelCard({ label, stat, color }: { label: string; stat: LevelStat; color: string }) {
  const pct = stat.total > 0 ? Math.round((stat.selected / stat.total) * 100) : 0;
  return (
    <div className="level-card">
      <div className="level-card__header">
        <span className="level-card__label" style={{ color }}>{label}</span>
        <span className="level-card__pct" style={{ color }}>{pct}%</span>
      </div>
      <div className="level-card__bar-wrap">
        <div className="level-card__bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <div className="level-card__count">
        {stat.selected} / {stat.total}
      </div>
    </div>
  );
}

export default function LevelBreakdown({ level1, level2 }: Props) {
  const { t } = useLocale();

  return (
    <div className="dashboard-panel">
      <h3 className="dashboard-panel__title">{t("dashboard.level_breakdown")}</h3>
      <div className="level-grid">
        <LevelCard label={t("dashboard.level_1")} stat={level1} color="var(--accent)" />
        <LevelCard label={t("dashboard.level_2")} stat={level2} color="var(--warning)" />
      </div>
    </div>
  );
}
