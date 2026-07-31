export interface Finding {
  rule_id: string;
  title: string;
  description: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  language?: string;
  file?: string;
  line?: number;
  location: {
    file_path: string;
    line: number;
    end_line?: number;
    column?: number;
    code_snippet?: string;
    function?: string;
    class?: string;
  };
  cwe?: string;
  cwe_name?: string;
  owasp?: { code: string; title?: string } | null;
  cvss_score?: number;
  cvss?: { score: number; vector: string; severity: string };
  exploitability?: string;
  reachability?: string;
  evidence?: Array<{ type: string; detail: string; matched?: string; line?: number }>;
  fix_suggestion?: string;
  fixed_code?: string;
  root_cause?: string;
  why_vulnerable?: string;
  impact?: string;
  exploit_scenario?: string;
  confidence_reasoning?: string;
  references?: string[];
  tags?: string[];
  fingerprint?: string;
  is_false_positive?: boolean;
  raw_secret?: string;
  occurrences?: number;
  locations?: Array<{
    file?: string;
    line?: number;
    end_line?: number;
    column?: number;
    file_path?: string;
  }>;
  state?: {
    suppressed?: boolean;
    is_false_positive?: boolean;
    assignee?: string;
    issue_url?: string;
    notes?: string;
  };
  metadata?: Record<string, unknown>;
}

export interface FindingsMetadata {
  scan_id: string;
  repository: string;
  branch: string;
  commit: string;
  target: string;
  scan_time: string;
  completed_at: string;
  scan_duration: number;
  scanner_version: string;
  scanner_tool: string;
  enterprise: boolean;
  files_scanned: number;
  lines_scanned: number;
  rules_executed: number;
  repo_size_bytes: number;
  languages: Record<string, number>;
  occurrences_total: number;
  findings_total: number;
  risk_score: number;
  grade: string;
}

export interface FindingsResponse {
  job_id: string;
  total: number;
  offset: number;
  limit: number;
  findings: Finding[];
  metadata: FindingsMetadata;
}

export interface FindingState {
  suppressed?: boolean;
  is_false_positive?: boolean;
  assignee?: string;
  issue_url?: string;
  notes?: string;
}

export interface ScanResult {
  total_findings: number;
  security_findings: number;
  quality_findings: number;
  secret_findings: number;
  risk_score: number;
  grade: string;
  severity_counts: Record<string, number>;
  files_scanned: number;
  lines_scanned: number;
  languages: string[];
  scan_duration: number;
  findings: Finding[];
  enterprise_metrics?: Record<string, unknown>;
  summary?: {
    total_findings: number;
    security_findings: number;
    quality_findings: number;
    secret_findings: number;
    risk_score: number;
    grade: string;
    severity_counts: Record<string, number>;
    files_scanned: number;
    lines_scanned: number;
    languages: string[];
    scan_duration: number;
  };
}

export interface ScanJob {
  job_id: string;
  status: "pending" | "running" | "completed" | "failed";
  target: string;
  enterprise: boolean;
  started_at: string;
  completed_at: string;
  finding_count: number;
  error?: string;
  result?: ScanResult;
}

export interface Stats {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  total_findings: number;
  severity_totals: Record<string, number>;
  category_totals: Record<string, number>;
  avg_findings_per_scan: number;
}

export interface HistoryEntry {
  job_id: string;
  target: string;
  status: string;
  enterprise: boolean;
  started_at: string;
  completed_at: string;
  finding_count: number;
}
