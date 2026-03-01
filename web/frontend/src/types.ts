/* TypeScript types matching the backend Pydantic models */

export interface RuleItem {
  rule_id: string;
  title: string;
  section: string;
  os: string;
  cis_level: number | null;
  category: string | null;
  subcategory: string | null;
  description: string | null;
  automated: boolean;
  severity: string | null;
  tags: string[];
}

export interface RulesResponse {
  os: string;
  total: number;
  sections: Record<string, RuleItem[]>;
}

export interface Warning {
  rule_id: string;
  message: string;
  missing_dependency: string | null;
}

export interface ErrorItem {
  rule_id: string;
  conflicting_rule: string;
  message: string;
}

export interface ResolveResult {
  valid: boolean;
  warnings: Warning[];
  errors: ErrorItem[];
}

export interface ResolveRequest {
  os: string;
  rule_ids: string[];
}

export interface GenerateRequest {
  os: string;
  rule_ids: string[];
  format: string;
  permanent: boolean;
}

export interface GenerateResponse {
  success: boolean;
  message: string;
  download_url: string | null;
  filename: string | null;
  sha256: string | null;
  artifact_id: string | null;
}

export interface ArtifactInfoResponse {
  found: boolean;
  artifact_id: string | null;
  filename: string | null;
  sha256: string | null;
  download_url: string | null;
}
