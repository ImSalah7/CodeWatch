"use client";

import { useEffect, useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { MetricCard } from "@/components/ui/MetricCard";
import {
  AlertTriangle,
  AlertCircle,
  AlertOctagon,
  Info,
  ShieldAlert,
  Download,
  ChevronLeft,
  ChevronRight,
  Link2,
} from "lucide-react";
import { getFindings, getScanStatus, downloadReport } from "@/lib/api";
import type { LucideIcon } from "lucide-react";

interface Finding {
  rule_id: string;
  title: string;
  severity: string;
  confidence: number;
  category: string;
  location: { file_path: string; line: number; code_snippet?: string };
  cwe: string;
  description: string;
  fingerprint: string;
}

const PAGE_SIZE = 50;

export function ResultsClient() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const initialJobId = searchParams.get("job_id") || "";

  const [jobId, setJobId] = useState(initialJobId);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async (jid: string, sev: string, q: string, off: number) => {
    if (!jid) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await getFindings({
        job_id: jid,
        severity: sev === "all" ? undefined : sev,
        search: q || undefined,
        limit: PAGE_SIZE,
        offset: off,
      });
      setFindings(res.findings as Finding[]);
      setTotal(res.total);
      setJobId(res.job_id);
      const status = await getScanStatus(jid).catch(() => null);
      if (status?.result?.summary) setSummary(status.result.summary);
      setError("");
    } catch (e: any) {
      setError(e.message || "Failed to load findings");
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load(initialJobId, filter, search, 0);
  }, [initialJobId]);

  useEffect(() => {
    load(jobId, filter, search, offset);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, search, offset]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.floor(offset / PAGE_SIZE) + 1;

  const handleExport = async (format: string) => {
    if (!jobId) return;
    const ext = format === "markdown" ? "md" : format;
    try {
      await downloadReport(jobId, format, `myscan-report-${jobId.slice(0, 8)}.${ext}`);
    } catch {
      // ignore
    }
  };

  const severityData = summary?.severity_counts || {};

  if (loading && findings.length === 0)
    return <div className="p-8 text-zinc-400">Loading results...</div>;
  if (error && findings.length === 0)
    return <div className="p-8 text-red-400">{error}</div>;
  if (!jobId)
    return (
      <div className="p-8 text-zinc-500">
        No scan selected. Run a scan first or select one from the Reports page.
      </div>
    );

  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const sorted = [...findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan Results</h1>
          <p className="text-xs text-zinc-500 mt-1 font-mono">Job: {jobId}</p>
        </div>
        <div className="flex items-center gap-2">
          {["json", "html", "markdown", "csv", "sarif"].map((f) => (
            <button
              key={f}
              onClick={() => handleExport(f)}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 transition"
            >
              <Download className="w-3 h-3" />
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {severityOrder.map((s) => {
          const icons: Record<string, LucideIcon> = {
            critical: AlertOctagon,
            high: AlertTriangle,
            medium: AlertCircle,
            low: ShieldAlert,
            info: Info,
          };
          const colors: Record<string, string> = {
            critical: "#ef4444",
            high: "#f97316",
            medium: "#eab308",
            low: "#3b82f6",
            info: "#71717a",
          };
          const count = summary?.severity_counts?.[s] ?? 0;
          return (
            <MetricCard
              key={s}
              title={s.charAt(0).toUpperCase() + s.slice(1)}
              value={count ?? 0}
              icon={icons[s]}
              accentColor={colors[s]}
            />
          );
        })}
      </div>

      <div className="flex gap-4 items-center">
        <select
          className="bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-white"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value);
            setOffset(0);
          }}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <input
          className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-white placeholder-zinc-500"
          placeholder="Search findings..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
        />
        <span className="text-xs text-zinc-500 whitespace-nowrap">
          {total} total
        </span>
      </div>

      <div className="space-y-2">
        {sorted.map((f) => {
          const id = f.fingerprint || `${f.rule_id}-${f.location.file_path}-${f.location.line}`;
          const isExpanded = expanded === id;
          return (
            <div
              key={id}
              className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:border-zinc-700 transition"
            >
              <div className="flex items-start justify-between gap-4">
                <button
                  className="flex-1 min-w-0 text-left"
                  onClick={() => setExpanded(isExpanded ? null : id)}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-xs text-zinc-500 font-mono">{f.rule_id}</span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{f.category}</span>
                  </div>
                  <p className="text-sm text-white font-medium truncate">{f.title}</p>
                  <p className="text-xs text-zinc-500 mt-1 font-mono">
                    {f.location.file_path}:{f.location.line}
                  </p>
                  {f.cwe && <p className="text-xs text-zinc-600 mt-0.5">{f.cwe}</p>}
                </button>
                <div className="flex flex-col items-end gap-2 shrink-0">
                  <span className="text-xs text-zinc-600 whitespace-nowrap">
                    {(f.confidence * 100).toFixed(0)}% confidence
                  </span>
                  <a
                    href={`/findings/${encodeURIComponent(f.fingerprint)}`}
                    onClick={(e) => e.stopPropagation()}
                    className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 transition"
                  >
                    <Link2 className="w-3 h-3" />
                    Details
                  </a>
                </div>
              </div>
              {isExpanded && f.location.code_snippet && (
                <pre className="mt-3 p-3 rounded bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-400 font-mono overflow-x-auto">
                  {f.location.code_snippet}
                </pre>
              )}
            </div>
          );
        })}
        {sorted.length === 0 && (
          <p className="text-zinc-500 text-center py-8">No findings match your filters.</p>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 disabled:opacity-30 hover:border-zinc-500 transition"
          >
            <ChevronLeft className="w-3 h-3" />
            Prev
          </button>
          <span className="text-xs text-zinc-500">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={offset + PAGE_SIZE >= total}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 disabled:opacity-30 hover:border-zinc-500 transition"
          >
            Next
            <ChevronRight className="w-3 h-3" />
          </button>
        </div>
      )}
    </div>
  );
}
