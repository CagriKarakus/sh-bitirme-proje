/* SectionCoverage – horizontal bar chart per section */

import { useLocale } from "../context/LocaleContext";
import type { SectionStat } from "../hooks/useComplianceStats";

interface Props {
  sections: SectionStat[];
}

export default function SectionCoverage({ sections }: Props) {
  const { t } = useLocale();

  return (
    <div className="dashboard-panel">
      <h3 className="dashboard-panel__title">{t("dashboard.section_coverage")}</h3>
      <div className="section-coverage">
        {sections.map((sec) => (
          <div key={sec.name} className="section-coverage__row">
            <div className="section-coverage__label" title={sec.name}>
              {sec.name}
            </div>
            <div className="section-coverage__bar-wrap">
              <div
                className="section-coverage__bar-fill"
                style={{ width: `${sec.percentage}%` }}
              />
            </div>
            <div className="section-coverage__stat">
              {t("dashboard.selected_of_total", { selected: sec.selected, total: sec.total })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
