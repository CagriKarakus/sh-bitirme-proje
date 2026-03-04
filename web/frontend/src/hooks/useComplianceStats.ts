/* useComplianceStats – derives compliance metrics from HardeningContext state */

import { useMemo } from "react";
import { useHardening } from "../context/HardeningContext";

export interface SectionStat {
  name: string;
  selected: number;
  total: number;
  percentage: number;
}

export interface ComplianceStats {
  overallScore: number;
  totalRules: number;
  selectedCount: number;
  sections: SectionStat[];
  level1: { selected: number; total: number };
  level2: { selected: number; total: number };
  high: { selected: number; total: number };
  medium: { selected: number; total: number };
  low: { selected: number; total: number };
  automatedCount: number;
  manualCount: number;
}

export function useComplianceStats(): ComplianceStats {
  const { state } = useHardening();
  const { rules, sections, selectedRuleIds } = state;

  return useMemo(() => {
    const selectedCount = selectedRuleIds.size;
    const totalRules = rules.length;
    const overallScore = totalRules > 0 ? Math.round((selectedCount / totalRules) * 100) : 0;

    const sectionStats: SectionStat[] = Object.entries(sections).map(([name, sectionRules]) => {
      const total = sectionRules.length;
      const selected = sectionRules.filter((r) => selectedRuleIds.has(r.rule_id)).length;
      return { name, selected, total, percentage: total > 0 ? Math.round((selected / total) * 100) : 0 };
    });

    const level1 = { selected: 0, total: 0 };
    const level2 = { selected: 0, total: 0 };
    const high = { selected: 0, total: 0 };
    const medium = { selected: 0, total: 0 };
    const low = { selected: 0, total: 0 };
    let automatedCount = 0;
    let manualCount = 0;

    for (const rule of rules) {
      const isSelected = selectedRuleIds.has(rule.rule_id);

      if (rule.cis_level === 1) { level1.total++; if (isSelected) level1.selected++; }
      else if (rule.cis_level === 2) { level2.total++; if (isSelected) level2.selected++; }

      const severity = rule.severity ?? "low";
      if (severity === "high") { high.total++; if (isSelected) high.selected++; }
      else if (severity === "medium") { medium.total++; if (isSelected) medium.selected++; }
      else { low.total++; if (isSelected) low.selected++; }

      if (rule.automated) automatedCount++;
      else manualCount++;
    }

    return { overallScore, totalRules, selectedCount, sections: sectionStats, level1, level2, high, medium, low, automatedCount, manualCount };
  }, [rules, sections, selectedRuleIds]);
}
