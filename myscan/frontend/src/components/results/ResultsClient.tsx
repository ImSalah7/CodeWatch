"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { MetricCard } from "@/components/ui/MetricCard";
import { cn, formatNumber, gradeColor, timeAgo } from "@/lib/utils";
import {
  AlertTriangle,
  AlertCircle,
  AlertOctagon,
  Info,
  ShieldAlert,
  Download,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronUp,
  ChevronDown,
  Link2,
  SlidersHorizontal,
  RotateCcw,
  EyeOff,
  Eye,
  User,
  Bug,
  CheckCircle2,
  Clock,
  Database,
  GitBranch,
  Search,
  X,
  FileText,
  Box,
  Layers,
} from "lucide-react";
import {
  getFindings,
  bulkFindingAction,
  downloadReport,
  type FindingsQuery,
} from "@/lib/api";
import type { Finding, FindingsMetadata } from "@/lib/types";
import type { LucideIcon } from "lucide-react";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SORT_OPTIONS = [
  { value: "severity", label: "Severity" },
  { value: "cvss", label: "CVSS" },
  { value: "confidence", label: "Confidence" },
  { value: "file", label: "File" },
  { value: "rule", label: "Rule" },
  { value: "line", label: "Line" },
] as const;

interface Filters {
  severity: string;
  category: string;
  status: string;
  language: string;
  rule_id: string;
  cwe: string;
  min_cvss: string;
  min_confidence: string;
  include_suppressed: boolean;
  search: string;
}

const DEFAULT_FILTERS: Filters = {
  severity: "all",
  category: "all",
  status: "all",
  language: "all",
  rule_id: "",
  cwe: "",
  min_cvss: "",
  min_confidence: "",
  include_suppressed: false,
  search: "",
};

function severityIcon(sev: string): { icon: LucideIcon; color: string } {
  const map: Record<string, { icon: LucideIcon; color: string }> = {
    critical: { icon: AlertOctagon, color: "#ef4444" },
    high: { icon: AlertTriangle, color: "#f97316" },
    medium: { icon: AlertCircle, color: "#eab308" },
    low: { icon: ShieldAlert, color: "#3b82f6" },
    info: { icon: Info, color: "#71717a" },
  };
  return map[sev] || map.info;
}

function formatSize(bytes: number): string {
  if (!bytes) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function ResultsClient({ initialJobId }: { initialJobId?: string }) {
  const [jobId, setJobId] = useState(initialJobId || "");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [metadata, setMetadata] = useState<FindingsMetadata | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [sort, setSort] = useState("severity");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [pageSize, setPageSize] = useState(50);
  const [offset, setOffset] = useState(0);
  const [pageInput, setPageInput] = useState("1");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [actionMsg, setActionMsg] = useState("");
  const [actionError, setActionError] = useState("");
  const [assignValue, setAssignValue] = useState("");
  const [busy, setBusy] = useState(false);
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Debounce the free-text search field.
  useEffect(() => {
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => setDebouncedSearch(filters.search), 400);
    return () => {
      if (searchTimer.current) clearTimeout(searchTimer.current);
    };
  }, [filters.search]);

  const query = useMemo<FindingsQuery>(() => {
    const q: FindingsQuery = {
      job_id: jobId || undefined,
      limit: pageSize,
      offset,
      sort,
      order,
    };
    if (filters.severity !== "all") q.severity = filters.severity;
    if (filters.category !== "all") q.category = filters.category;
    if (filters.status !== "all") q.status = filters.status;
    if (filters.language !== "all") q.language = filters.language;
    if (filters.rule_id.trim()) q.rule_id = filters.rule_id.trim();
    if (filters.cwe.trim()) q.cwe = filters.cwe.trim();
    if (filters.min_cvss) q.min_cvss = Number(filters.min_cvss);
    if (filters.min_confidence) q.min_confidence = Number(filters.min_confidence);
    if (filters.include_suppressed) q.include_suppressed = true;
    if (debouncedSearch.trim()) q.search = debouncedSearch.trim();
    return q;
  }, [jobId, pageSize, offset, sort, order, filters, debouncedSearch]);

  const signature = useMemo(() => JSON.stringify(query), [query]);

  const load = async (jid: string, sig: string, keepResults: boolean) => {
    if (!jid) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await getFindings(JSON.parse(sig) as FindingsQuery);
      setFindings(res.findings);
      setTotal(res.total);
      setMetadata(res.metadata);
      setJobId(res.job_id);
      setSelected(new Set());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load findings");
      if (!keepResults) setFindings([]);
    } finally {
      setLoading(false);
    }
  };

  // Reload whenever the query signature changes.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- async fetch on query change
    void load(jobId, signature, findings.length > 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature]);

  const updateFilter = <K extends keyof Filters>(key: K, value: Filters[K]) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setOffset(0);
  };

  const resetFilters = () => {
    setFilters(DEFAULT_FILTERS);
    setDebouncedSearch("");
    setOffset(0);
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.floor(offset / pageSize) + 1;

  const goToPage = (p: number) => {
    const clamped = Math.min(Math.max(1, p), totalPages);
    setPageInput(String(clamped));
    setOffset((clamped - 1) * pageSize);
  };

  const handleExport = async (format: string) => {
    if (!jobId) return;
    const ext = format === "markdown" ? "md" : format;
    try {
      await downloadReport(jobId, format, `myscan-report-${jobId.slice(0, 8)}.${ext}`);
    } catch {
      // ignore
    }
  };

  const toggleSelected = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    setSelected((prev) => {
      if (prev.size === findings.length) return new Set();
      return new Set(findings.map((f) => f.fingerprint || `${f.rule_id}:${f.location?.file_path}:${f.location?.line}`));
    });
  };

  const applyAction = async (
    action: "suppress" | "unsuppress" | "mark_false_positive" | "unmark_false_positive" | "mark_real" | "assign" | "create_issue",
    fingerprints: string[],
    value?: string
  ) => {
    if (!jobId || fingerprints.length === 0 || busy) return;
    setBusy(true);
    setActionError("");
    setActionMsg("");
    try {
      await bulkFindingAction({ scan_id: jobId, action, fingerprints, value });
      setActionMsg(
        `${action.replace(/_/g, " ")} applied to ${fingerprints.length} finding${fingerprints.length === 1 ? "" : "s"}`
      );
      setSelected(new Set());
      setExpanded(null);
      await load(jobId, signature, true);
      window.setTimeout(() => setActionMsg(""), 3000);
    } catch (e: unknown) {
      setActionError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const idOf = (f: Finding) => f.fingerprint || `${f.rule_id}:${f.location?.file_path}:${f.location?.line}`;

  const languages = useMemo(() => Object.keys(metadata?.languages || {}), [metadata]);

  if (!jobId)
    return (
      <div className="p-8 text-zinc-500">
        No scan selected. Run a scan first or select one from the Reports page.
      </div>
    );

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white">Scan Results</h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-xs text-zinc-500">
            <span className="font-mono">{jobId.slice(0, 8)}</span>
            {metadata?.target && <span className="font-mono truncate max-w-[320px]">{metadata.target}</span>}
            {metadata?.completed_at && <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{timeAgo(metadata.completed_at)}</span>}
          </div>
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

      {/* Repository / scan metadata block */}
      {metadata && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium">Risk Score</p>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-white">{metadata.risk_score}</span>
                <span className={cn("text-lg font-bold", gradeColor(metadata.grade))}>{metadata.grade}</span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
              <MetaRow icon={GitBranch} label="Repository" value={metadata.repository || metadata.branch ? `${metadata.repository}${metadata.branch ? ` · ${metadata.branch}` : ""}` : "—"} mono />
              <MetaRow icon={Database} label="Files" value={`${metadata.files_scanned}`} />
              <MetaRow icon={FileText} label="Lines" value={formatNumber(metadata.lines_scanned)} />
              <MetaRow icon={Box} label="Rules" value={`${metadata.rules_executed}`} />
              <MetaRow icon={Layers} label="Repo size" value={formatSize(metadata.repo_size_bytes)} />
              <MetaRow icon={Clock} label="Duration" value={`${metadata.scan_duration?.toFixed(1)}s`} />
              <MetaRow icon={AlertTriangle} label="Occurrences" value={`${metadata.occurrences_total}`} />
            </div>
            {metadata.commit && (
              <span className="text-[10px] font-mono text-zinc-600 truncate max-w-[180px] ml-auto" title={metadata.commit}>
                {metadata.commit.slice(0, 12)}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Severity metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {SEVERITY_ORDER.map((s) => {
          const { icon, color } = severityIcon(s);
          const canonical = metadata?.severity_counts?.[s];
          const count = canonical !== undefined ? canonical : findings.filter((f) => f.severity === s).length;
          return (
            <button key={s} onClick={() => updateFilter("severity", s)} className="text-left hover:opacity-90 transition">
              <MetricCard title={s.charAt(0).toUpperCase() + s.slice(1)} value={count} icon={icon} accentColor={color} />
            </button>
          );
        })}
      </div>

      {/* Toolbar: filters / sort / pagination */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-3 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShowFilters((v) => !v)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs transition",
              showFilters
                ? "bg-zinc-700 border-zinc-500 text-white"
                : "bg-zinc-800 border-zinc-700 text-zinc-300 hover:border-zinc-500"
            )}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            Filters
          </button>

          <div className="flex-1 min-w-[180px] relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder-zinc-500"
              placeholder="Search title, rule, file, CWE, description..."
              value={filters.search}
              onChange={(e) => updateFilter("search", e.target.value)}
            />
            {filters.search && (
              <button
                onClick={() => updateFilter("search", "")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <select
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-2 text-xs text-white"
            value={sort}
            onChange={(e) => { setSort(e.target.value); setOffset(0); }}
            aria-label="Sort by"
          >
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <button
            onClick={() => setOrder((v) => (v === "asc" ? "desc" : "asc"))}
            className="px-3 py-2 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 transition"
            title={order === "asc" ? "Ascending" : "Descending"}
          >
            {order === "asc" ? "↑ ASC" : "↓ DESC"}
          </button>

          <select
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-2 text-xs text-white"
            value={pageSize}
            onChange={(e) => { setPageSize(Number(e.target.value)); setOffset(0); }}
            aria-label="Page size"
          >
            {[25, 50, 100, 200].map((n) => (
              <option key={n} value={n}>{n} / page</option>
            ))}
          </select>

          <span className="text-xs text-zinc-500 whitespace-nowrap ml-auto">
            {total === 0 ? "0 findings" : `${offset + 1}–${Math.min(offset + pageSize, total)} of ${total}`}
          </span>
        </div>

        {/* Advanced filters */}
        {showFilters && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-2 border-t border-zinc-800">
            <FilterSelect
              label="Severity"
              value={filters.severity}
              onChange={(v) => updateFilter("severity", v)}
              options={[
                { value: "all", label: "All" },
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
                { value: "info", label: "Info" },
              ]}
            />
            <FilterSelect
              label="Category"
              value={filters.category}
              onChange={(v) => updateFilter("category", v)}
              options={[
                { value: "all", label: "All" },
                { value: "security", label: "Security" },
                { value: "quality", label: "Quality" },
                { value: "secret", label: "Secrets" },
              ]}
            />
            <FilterSelect
              label="Triage status"
              value={filters.status}
              onChange={(v) => updateFilter("status", v)}
              options={[
                { value: "all", label: "All" },
                { value: "real", label: "Confirmed real" },
                { value: "false_positive", label: "False positives" },
                { value: "likely_fp", label: "Likely false positives" },
              ]}
            />
            <FilterSelect
              label="Language"
              value={filters.language}
              onChange={(v) => updateFilter("language", v)}
              options={[
                { value: "all", label: "All" },
                ...languages.map((l) => ({ value: l, label: l })),
              ]}
            />
            <FilterInput label="Rule ID" value={filters.rule_id} onChange={(v) => updateFilter("rule_id", v)} placeholder="e.g. SEC001" />
            <FilterInput label="CWE" value={filters.cwe} onChange={(v) => updateFilter("cwe", v)} placeholder="e.g. CWE-89" />
            <FilterInput
              label="Min CVSS"
              value={filters.min_cvss}
              onChange={(v) => updateFilter("min_cvss", v)}
              placeholder="0.0"
              type="number"
              min={0}
              max={10}
              step={0.1}
            />
            <FilterInput
              label="Min confidence"
              value={filters.min_confidence}
              onChange={(v) => updateFilter("min_confidence", v)}
              placeholder="0.0"
              type="number"
              min={0}
              max={1}
              step={0.05}
            />
            <label className="flex items-center gap-2 text-xs text-zinc-300 col-span-2 md:col-span-4 pt-1">
              <input
                type="checkbox"
                checked={filters.include_suppressed}
                onChange={(e) => updateFilter("include_suppressed", e.target.checked)}
                className="accent-emerald-500"
              />
              Include suppressed findings
            </label>
            <div className="col-span-2 md:col-span-4 flex justify-end">
              <button
                onClick={resetFilters}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 transition"
              >
                <RotateCcw className="w-3 h-3" />
                Reset filters
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Action feedback */}
      {actionMsg && (
        <div className="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
          <CheckCircle2 className="w-3.5 h-3.5" /> {actionMsg}
        </div>
      )}
      {actionError && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          <AlertTriangle className="w-3.5 h-3.5" /> {actionError}
        </div>
      )}

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="sticky top-16 z-20 flex flex-wrap items-center gap-2 bg-zinc-800/95 backdrop-blur border border-zinc-600 rounded-xl px-4 py-2.5">
          <span className="text-xs text-zinc-300 mr-1">{selected.size} selected</span>
          <BulkButton onClick={() => applyAction("suppress", [...selected])} icon={<EyeOff className="w-3 h-3" />}>Suppress</BulkButton>
          <BulkButton onClick={() => applyAction("unsuppress", [...selected])} icon={<Eye className="w-3 h-3" />}>Unsuppress</BulkButton>
          <BulkButton onClick={() => applyAction("mark_false_positive", [...selected])} icon={<Bug className="w-3 h-3" />}>Mark FP</BulkButton>
          <BulkButton onClick={() => applyAction("mark_real", [...selected])} icon={<CheckCircle2 className="w-3 h-3" />}>Mark real</BulkButton>
          <div className="flex items-center gap-1.5">
            <input
              className="bg-zinc-900 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-white placeholder-zinc-500 w-36"
              placeholder="Assignee"
              value={assignValue}
              onChange={(e) => setAssignValue(e.target.value)}
            />
            <BulkButton onClick={() => { if (assignValue.trim()) { void applyAction("assign", [...selected], assignValue.trim()); setAssignValue(""); } }} icon={<User className="w-3 h-3" />}>Assign</BulkButton>
          </div>
          <button
            onClick={() => setSelected(new Set())}
            className="ml-auto text-xs text-zinc-400 hover:text-white transition"
          >
            Clear ({selected.size})
          </button>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && findings.length === 0 && (
        <div className="space-y-2" aria-label="Loading findings">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 animate-pulse">
              <div className="h-3 w-1/4 bg-zinc-800 rounded mb-2" />
              <div className="h-4 w-3/4 bg-zinc-800 rounded" />
            </div>
          ))}
        </div>
      )}

      {/* Error state */}
      {error && findings.length === 0 && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-8 text-center">
          <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
          <p className="text-red-400 text-sm mb-4">{error}</p>
          <button
            onClick={() => void load(jobId, signature, false)}
            className="flex items-center gap-1.5 mx-auto px-4 py-2 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 transition"
          >
            <RotateCcw className="w-3 h-3" />
            Retry
          </button>
        </div>
      )}

      {/* Findings table */}
      {!loading && findings.length > 0 && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
          <div className="overflow-auto max-h-[65vh]">
            <table className="w-full text-sm min-w-[900px]">
              <thead className="bg-zinc-800/80">
                <tr className="text-left text-[11px] uppercase tracking-wider text-zinc-400">
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5 w-8">
                    <input
                      type="checkbox"
                      className="accent-emerald-500"
                      checked={findings.length > 0 && selected.size === findings.length}
                      onChange={toggleSelectAll}
                      aria-label="Select all on page"
                    />
                  </th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5">Severity</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5">Finding</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5">CWE</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5 text-right">CVSS</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5 text-right">Confidence</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5 text-right">Occurrences</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5">State</th>
                  <th className="sticky top-0 bg-zinc-800/95 backdrop-blur px-3 py-2.5 w-10" />
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => {
                  const id = idOf(f);
                  const isExpanded = expanded === id;
                  const isSelected = selected.has(id);
                  const state = f.state || {};
                  const file = f.file || f.location?.file_path || "";
                  const line = f.line || f.location?.line || 0;
                  const isSuppressed = Boolean(state.suppressed);
                  const isFp = Boolean(state.is_false_positive || f.is_false_positive);
                  const likelyFp = Boolean(f.likely_false_positive) && !isFp && !Boolean(state.verified);
                  return (
                    <FragmentRow
                      key={id}
                      finding={f}
                      id={id}
                      file={file}
                      line={line}
                      isExpanded={isExpanded}
                      isSelected={isSelected}
                      isSuppressed={isSuppressed}
                      isFp={isFp}
                      likelyFp={likelyFp}
                      state={state}
                      onToggleExpand={() => setExpanded(isExpanded ? null : id)}
                      onToggleSelect={() => toggleSelected(id)}
                      onAction={applyAction}
                      busy={busy}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && findings.length === 0 && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center">
          <Search className="w-8 h-8 text-zinc-600 mx-auto mb-3" />
          <p className="text-zinc-400 text-sm">No findings match your filters.</p>
          <button
            onClick={resetFilters}
            className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 transition"
          >
            <RotateCcw className="w-3 h-3" />
            Reset filters
          </button>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => goToPage(1)}
            disabled={page === 1}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 disabled:opacity-30 hover:border-zinc-500 transition"
            aria-label="First page"
          >
            <ChevronsLeft className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => goToPage(page - 1)}
            disabled={page === 1}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 disabled:opacity-30 hover:border-zinc-500 transition"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            Prev
          </button>
          <span className="text-xs text-zinc-500 flex items-center gap-1.5">
            Page
            <input
              className="w-12 bg-zinc-800 border border-zinc-700 rounded px-1.5 py-1 text-xs text-center text-white"
              value={pageInput}
              onChange={(e) => setPageInput(e.target.value.replace(/\D/g, ""))}
              onBlur={() => { const p = parseInt(pageInput, 10); if (!Number.isNaN(p)) goToPage(p); else setPageInput(String(page)); }}
              onKeyDown={(e) => { if (e.key === "Enter") { const p = parseInt(pageInput, 10); if (!Number.isNaN(p)) goToPage(p); } }}
              aria-label="Jump to page"
            />
            of {totalPages}
          </span>
          <button
            onClick={() => goToPage(page + 1)}
            disabled={page === totalPages}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 disabled:opacity-30 hover:border-zinc-500 transition"
          >
            Next
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => goToPage(totalPages)}
            disabled={page === totalPages}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 disabled:opacity-30 hover:border-zinc-500 transition"
            aria-label="Last page"
          >
            <ChevronsRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Small presentational helpers                                        */
/* ------------------------------------------------------------------ */

function MetaRow({ icon: Icon, label, value, mono }: { icon: LucideIcon; label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium flex items-center gap-1">
        <Icon className="w-3 h-3" /> {label}
      </p>
      <p className={cn("text-sm text-zinc-200", mono && "font-mono")}>{value}</p>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <label className="block">
      <span className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium">{label}</span>
      <select
        className="w-full mt-0.5 bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-white"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  );
}

function FilterInput({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  min,
  max,
  step,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  min?: number;
  max?: number;
  step?: number;
}) {
  return (
    <label className="block">
      <span className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium">{label}</span>
      <input
        type={type}
        min={min}
        max={max}
        step={step}
        className="w-full mt-0.5 bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-white placeholder-zinc-600"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function BulkButton({ onClick, icon, children }: { onClick: () => void; icon: ReactNode; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 hover:border-emerald-500/50 hover:text-emerald-300 transition"
    >
      {icon}
      {children}
    </button>
  );
}

function StateChip({ active, label, tone }: { active: boolean; label: string; tone: "emerald" | "amber" | "blue" | "red" }) {
  if (!active) return null;
  const tones = {
    emerald: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    amber: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    blue: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    red: "bg-red-500/10 text-red-400 border-red-500/20",
  };
  return (
    <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded border text-[10px]", tones[tone])}>
      {label}
    </span>
  );
}

function FragmentRow({
  finding: f,
  id,
  file,
  line,
  isExpanded,
  isSelected,
  isSuppressed,
  isFp,
  likelyFp,
  state,
  onToggleExpand,
  onToggleSelect,
  onAction,
  busy,
}: {
  finding: Finding;
  id: string;
  file: string;
  line: number;
  isExpanded: boolean;
  isSelected: boolean;
  isSuppressed: boolean;
  isFp: boolean;
  likelyFp: boolean;
  state: Record<string, unknown>;
  onToggleExpand: () => void;
  onToggleSelect: () => void;
  onAction: (action: "suppress" | "unsuppress" | "mark_false_positive" | "unmark_false_positive" | "mark_real", fingerprints: string[]) => void;
  busy: boolean;
}) {
  const locations = f.locations || [];
  const evidence = f.evidence || [];
  const fileForUrl = f.fingerprint ? encodeURIComponent(f.fingerprint) : "";
  return (
    <>
      <tr
        className={cn(
          "border-t border-zinc-800 hover:bg-zinc-800/40 transition cursor-pointer",
          isExpanded && "bg-zinc-800/30",
          isSuppressed && "opacity-50"
        )}
        onClick={onToggleExpand}
      >
        <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
          <input type="checkbox" className="accent-emerald-500" checked={isSelected} onChange={onToggleSelect} aria-label={`Select ${f.title}`} />
        </td>
        <td className="px-3 py-2.5"><SeverityBadge severity={f.severity} /></td>
        <td className="px-3 py-2.5 min-w-[260px]">
          <p className="text-sm text-white font-medium truncate max-w-[380px]">{f.title}</p>
          <p className="text-[11px] text-zinc-500 font-mono mt-0.5">
            {f.rule_id} · {file}:{line}
            {f.language && <span className="text-zinc-600"> · {f.language}</span>}
          </p>
        </td>
        <td className="px-3 py-2.5 text-xs text-zinc-400">{f.cwe || "—"}</td>
        <td className="px-3 py-2.5 text-right text-xs text-zinc-300">
          {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
        </td>
        <td className="px-3 py-2.5 text-right text-xs text-zinc-300">{(f.confidence * 100).toFixed(0)}%</td>
        <td className="px-3 py-2.5 text-right text-xs text-zinc-300">
          {f.occurrences && f.occurrences > 1 ? (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono">
              ×{f.occurrences}
            </span>
          ) : (
            "1"
          )}
        </td>
        <td className="px-3 py-2.5">
          <div className="flex flex-wrap gap-1">
            <StateChip active={isSuppressed} label="Suppressed" tone="amber" />
            <StateChip active={isFp} label="FP" tone="emerald" />
            <StateChip active={likelyFp} label="Likely FP" tone="red" />
            <StateChip active={Boolean(state.assignee)} label={String(state.assignee)} tone="blue" />
          </div>
        </td>
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
            {fileForUrl && (
              <a
                href={`/findings/${fileForUrl}`}
                onClick={(e) => e.stopPropagation()}
                className="p-1 rounded text-zinc-500 hover:text-emerald-400 transition"
                title="View details"
              >
                <Link2 className="w-3.5 h-3.5" />
              </a>
            )}
            {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-zinc-500" /> : <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />}
          </div>
        </td>
      </tr>
      {isExpanded && (
        <tr className="border-t border-zinc-800 bg-zinc-950/60">
          <td colSpan={9} className="px-4 py-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="space-y-3">
                <p className="text-sm text-zinc-300 leading-relaxed">{f.description}</p>
                {f.why_vulnerable && <DetailBlock label="Why vulnerable" text={f.why_vulnerable} />}
                {f.root_cause && <DetailBlock label="Root cause" text={f.root_cause} />}
                {f.impact && <DetailBlock label="Impact" text={f.impact} />}
                {f.exploit_scenario && <DetailBlock label="Exploit scenario" text={f.exploit_scenario} />}
                {f.confidence_reasoning && <DetailBlock label="Confidence reasoning" text={f.confidence_reasoning} />}
                {likelyFp && f.likely_false_positive_reason && (
                  <DetailBlock label="Why it may be a false positive" text={f.likely_false_positive_reason} />
                )}
              </div>
              <div className="space-y-3">
                {f.location?.code_snippet && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">Vulnerable code</p>
                    <pre className="p-3 rounded-lg bg-zinc-900 border border-zinc-800 text-[11px] text-zinc-300 font-mono overflow-x-auto whitespace-pre-wrap">
                      {f.location.code_snippet}
                    </pre>
                  </div>
                )}
                {evidence.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">Evidence</p>
                    <ul className="space-y-1">
                      {evidence.slice(0, 5).map((e, i) => (
                        <li key={i} className="text-[11px] text-zinc-400 font-mono">{e.detail}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {locations.length > 1 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">
                      All occurrences ({locations.length})
                    </p>
                    <ul className="space-y-1">
                      {locations.map((loc, i) => (
                        <li key={i} className="text-[11px] text-zinc-400 font-mono">
                          {loc.file || loc.file_path}:{loc.line}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {f.fix_suggestion && <DetailBlock label="How to fix" text={f.fix_suggestion} />}
                {f.fixed_code && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">Fixed code</p>
                    <pre className="p-3 rounded-lg bg-zinc-900 border border-emerald-500/15 text-[11px] text-emerald-200/90 font-mono overflow-x-auto whitespace-pre-wrap">
                      {f.fixed_code}
                    </pre>
                  </div>
                )}
                {f.references && f.references.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1.5">References</p>
                    <ul className="space-y-1">
                      {f.references.slice(0, 5).map((r, i) => (
                        <li key={i}>
                          <a href={r} target="_blank" rel="noopener noreferrer" className="text-[11px] text-blue-400 hover:underline break-all">
                            {r}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {f.tags && f.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {f.tags.map((t) => (
                      <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{t}</span>
                    ))}
                  </div>
                )}
                {/* Triage actions */}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <button
                    disabled={busy}
                    onClick={() => onAction(isSuppressed ? "unsuppress" : "suppress", [id])}
                    className="px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 disabled:opacity-40 transition"
                  >
                    {isSuppressed ? "Unsuppress" : "Suppress"}
                  </button>
                  <button
                    disabled={busy}
                    onClick={() => onAction(isFp ? "unmark_false_positive" : "mark_real", [id])}
                    className="px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300 hover:border-zinc-500 disabled:opacity-40 transition"
                  >
                    {isFp ? "Mark as real" : "Confirm real"}
                  </button>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function DetailBlock({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-medium mb-1">{label}</p>
      <p className="text-xs text-zinc-400 leading-relaxed whitespace-pre-wrap">{text}</p>
    </div>
  );
}
