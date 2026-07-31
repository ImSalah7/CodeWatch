import type { ScanJob, Stats, Finding } from "./types";

const BASE = "";

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export interface SecurityScore {
  score: number;
  grade: string;
  trend: Array<{ date: string; score: number }>;
  components: {
    critical_findings: number;
    high_findings: number;
    secrets: number;
    total_findings: number;
    scans_completed: number;
  };
}

export interface SearchResult {
  type: string;
  fingerprint: string;
  title: string;
  rule_id: string;
  severity: string;
  file: string;
  line: number;
  category: string;
  cwe: string;
  scan_id: string;
}

export interface ScanSettings {
  threads: number;
  min_confidence: number;
  enterprise_mode: boolean;
  secret_display: string;
  max_file_size_kb: number;
  include_tests: boolean;
  include_docs: boolean;
  include_examples: boolean;
  max_history: number;
  report_format: string;
  notifications: {
    scan_complete: boolean;
    critical_findings: boolean;
    scan_failed: boolean;
  };
}

export async function healthCheck(): Promise<{ status: string; version: string }> {
  return fetchJSON(`${BASE}/health`);
}

export async function startScan(opts: {
  target: string;
  enterprise?: boolean;
  threads?: number;
  min_confidence?: number;
  secret_display?: string;
}): Promise<{ job_id: string; status: string; target: string }> {
  return fetchJSON(`${BASE}/api/v1/scan`, {
    method: "POST",
    body: JSON.stringify(opts),
  });
}

export async function getScanStatus(jobId: string): Promise<ScanJob> {
  return fetchJSON(`${BASE}/api/v1/scan/${jobId}`);
}

export async function getFindings(opts: {
  job_id?: string;
  category?: string;
  severity?: string;
  min_confidence?: number;
  limit?: number;
  offset?: number;
  search?: string;
} = {}): Promise<{ job_id: string; total: number; findings: Finding[] }> {
  const params = new URLSearchParams();
  if (opts.job_id) params.set("job_id", opts.job_id);
  if (opts.category) params.set("category", opts.category);
  if (opts.severity) params.set("severity", opts.severity);
  if (opts.min_confidence) params.set("min_confidence", String(opts.min_confidence));
  if (opts.limit) params.set("limit", String(opts.limit));
  if (opts.offset) params.set("offset", String(opts.offset));
  if (opts.search) params.set("search", opts.search);
  return fetchJSON(`${BASE}/api/v1/findings?${params}`);
}

export interface FindingDetail {
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  category: string;
  language?: string;
  cwe?: string;
  cwe_name?: string;
  owasp?: { code: string; title: string };
  cvss?: { score: number; vector: string; severity: string };
  location: {
    file_path: string;
    line: number;
    end_line?: number;
    column?: number;
    code_snippet?: string;
    function?: string;
    class?: string;
  };
  fix_suggestion?: string;
  fixed_code?: string;
  references?: string[];
  exploit_scenario?: string;
  impact?: string;
  why_vulnerable?: string;
  is_false_positive?: boolean;
  confidence_reasoning?: string;
  tags?: string[];
  raw_secret?: string;
  reachability?: string;
  root_cause?: string;
  fingerprint?: string;
  scan_id: string;
  scan_target: string;
  scan_date: string;
}

export async function getFindingDetail(fingerprint: string): Promise<FindingDetail> {
  return fetchJSON(`${BASE}/api/v1/findings/${encodeURIComponent(fingerprint)}`);
}

export async function getStats(): Promise<Stats> {
  return fetchJSON(`${BASE}/api/v1/stats`);
}

export async function getHistory(limit = 20): Promise<{ history: ScanJob[]; total: number }> {
  return fetchJSON(`${BASE}/api/v1/history?limit=${limit}`);
}

export async function getSecurityScore(): Promise<SecurityScore> {
  return fetchJSON(`${BASE}/api/v1/security-score`);
}

export async function globalSearch(q: string): Promise<{ results: SearchResult[]; total: number }> {
  return fetchJSON(`${BASE}/api/v1/search?q=${encodeURIComponent(q)}`);
}

export async function cancelScan(jobId: string): Promise<{ status: string }> {
  return fetchJSON(`${BASE}/api/v1/scan/${jobId}/cancel`, { method: "POST" });
}

export async function pauseScan(jobId: string): Promise<{ status: string }> {
  return fetchJSON(`${BASE}/api/v1/scan/${jobId}/pause`, { method: "POST" });
}

export async function resumeScan(jobId: string): Promise<{ status: string }> {
  return fetchJSON(`${BASE}/api/v1/scan/${jobId}/resume`, { method: "POST" });
}

export async function getSettings(): Promise<{ settings: ScanSettings }> {
  return fetchJSON(`${BASE}/api/v1/settings`);
}

export async function saveSettings(
  settings: Partial<ScanSettings>
): Promise<{ settings: ScanSettings }> {
  return fetchJSON(`${BASE}/api/v1/settings`, {
    method: "PUT",
    body: JSON.stringify({ settings }),
  });
}

export async function getReport(jobId: string, format = "json"): Promise<unknown> {
  if (format === "json") return fetchJSON(`${BASE}/api/v1/report/${jobId}?format=json`);
  const res = await fetch(`${BASE}/api/v1/report/${jobId}?format=${format}`);
  return res.text();
}

export async function downloadReport(
  jobId: string,
  format: string,
  filename: string
): Promise<void> {
  const res = await fetch(`${BASE}/api/v1/report/${jobId}?format=${format}`);
  if (!res.ok) throw new Error(`Failed to download report (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function generateFixes(
  jobId: string,
  findingIds?: string[]
): Promise<{
  fixes: Array<{
    rule_id: string;
    title: string;
    file: string;
    line: number;
    fingerprint: string;
    fixes: Array<{
      description: string;
      before: string;
      after: string;
      effort: string;
    }>;
  }>;
}> {
  return fetchJSON(`${BASE}/api/v1/fix`, {
    method: "POST",
    body: JSON.stringify({ job_id: jobId, finding_ids: findingIds }),
  });
}

export async function scanDependencies(target: string): Promise<{
  manifests: Array<Record<string, unknown>>;
  total_manifests: number;
  total_dependencies: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  target: string;
}> {
  return fetchJSON(`${BASE}/api/v1/dependencies`, {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function generateSBOM(
  target: string,
  format: "cyclonedx" | "spdx" = "cyclonedx"
): Promise<Record<string, unknown>> {
  return fetchJSON(`${BASE}/api/v1/sbom`, {
    method: "POST",
    body: JSON.stringify({ target, format: format === "spdx" ? "spdx" : "json" }),
  });
}

export function subscribeToScanEvents(
  jobId: string,
  handlers: {
    onProgress?: (data: Record<string, unknown>) => void;
    onFinding?: (data: Record<string, unknown>) => void;
    onComplete?: (data: Record<string, unknown>) => void;
    onError?: (data: Record<string, unknown>) => void;
    onFile?: (data: Record<string, unknown>) => void;
    onPaused?: (data: Record<string, unknown>) => void;
    onResumed?: (data: Record<string, unknown>) => void;
    onCancelled?: (data: Record<string, unknown>) => void;
    onRule?: (data: Record<string, unknown>) => void;
    onInit?: (data: Record<string, unknown>) => void;
  }
): () => void {
  const es = new EventSource(`${BASE}/api/v1/scan/${jobId}/events`);
  es.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      const data = msg.data || {};
      switch (msg.event) {
        case "progress": handlers.onProgress?.(data); break;
        case "finding": handlers.onFinding?.(data); break;
        case "complete": handlers.onComplete?.(data); es.close(); break;
        case "error": handlers.onError?.(data); es.close(); break;
        case "file": handlers.onFile?.(data); break;
        case "paused": handlers.onPaused?.(data); break;
        case "resumed": handlers.onResumed?.(data); break;
        case "cancelled": handlers.onCancelled?.(data); es.close(); break;
        case "rule": handlers.onRule?.(data); break;
        case "init": handlers.onInit?.(data); break;
        case "heartbeat": break;
      }
    } catch {
      // ignore malformed events
    }
  };
  es.onerror = () => {
    // server will terminate the stream on completion; ignore
  };
  return () => es.close();
}
