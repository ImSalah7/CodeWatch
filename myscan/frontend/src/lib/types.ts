export interface Finding {
  rule_id: string;
  title: string;
  description: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  location: {
    file_path: string;
    line: number;
    end_line?: number;
    column?: number;
    code_snippet?: string;
  };
  cwe?: string;
  owasp?: string;
  cvss_score?: number;
  exploitability?: string;
  reachability?: string;
  evidence?: Array<{ type: string; detail: string }>;
  fix_suggestion?: string;
  root_cause?: string;
  metadata?: Record<string, unknown>;
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
