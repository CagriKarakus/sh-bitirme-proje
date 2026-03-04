/* SeverityBreakdown – high/medium/low distribution */

import { useLocale } from "../context/LocaleContext";

interface SeverityStat {
  selected: number;
  total: number;
}

interface Props {
  high: SeverityStat;
  medium: SeverityStat;
  low: SeverityStat;
}

function SeverityRow({
  label,
  stat,
  color,
}: {
  label: string;
  stat: SeverityStat;
  color: string;
}) {
  const pct = stat.total > 0 ? Math.round((stat.selected / stat.total) * 100) : 0;
  return (
    <div className="severity-row">
      <div className="severity-row__label" style={{ color }}>{label}</div>
      <div className="severity-row__bar-wrap">
        <div className="severity-row__bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <div className="severity-row__stat">
        {stat.selected}/{stat.total}
      </div>
    </div>
  );
}

export default function SeverityBreakdown({ high, medium, low }: Props) {
  const { t } = useLocale();

  return (
    <div className="dashboard-panel">
      <h3 className="dashboard-panel__title">{t("dashboard.severity_dist")}</h3>
      <div className="severity-list">
        <SeverityRow label={t("dashboard.high")} stat={high} color="var(--error)" />
        <SeverityRow label={t("dashboard.medium")} stat={medium} color="var(--warning)" />
        <SeverityRow label={t("dashboard.low")} stat={low} color="var(--success)" />
      </div>
    </div>
  );
}
