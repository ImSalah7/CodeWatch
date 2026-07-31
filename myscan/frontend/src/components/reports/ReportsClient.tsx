"use client";

import { useEffect, useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  Download,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Copy,
  MapPin,
  Shield,
  X,
  Wrench,
} from "lucide-react";
import { getFindings, getHistory, generateFixes, downloadReport } from "@/lib/api";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { cn, severityColor } from "@/lib/utils";
import type { Finding, ScanJob } from "@/lib/types";

const categories = ["All", "Security", "Quality", "Secret", "Configuration", "Dependency"];

interface GeneratedFix {
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
}

export function ReportsClient() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [categoryFilter, setCategoryFilter] = useState("All");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [fixes, setFixes] = useState<GeneratedFix[]>([]);
  const [fixLoading, setFixLoading] = useState(false);
  const [fixExpanded, setFixExpanded] = useState<string | null>(null);

  useEffect(() => {
    getHistory(20)
      .then((h) => {
        const history = h.history || [];
        setJobs(history);
        const completed = history.filter((j) => j.status === "completed");
        if (completed.length > 0) {
          setSelectedJob(completed[0].job_id);
        } else {
          setLoading(false);
        }
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedJob) return;
    getFindings({ job_id: selectedJob, limit: 200 })
      .then((res) => {
        setFindings(res.findings || []);
        setTotal(res.total || 0);
      })
      .catch(() => {
        setFindings([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  }, [selectedJob]);

  const handleExport = async (format: string) => {
    if (!selectedJob) return;
    const ext = format === "markdown" ? "md" : format;
    try {
      await downloadReport(
        selectedJob,
        format,
        `myscan-report-${selectedJob.slice(0, 8)}.${ext}`
      );
    } catch {
      // ignore
    }
  };

  const handleGenerateFixes = async () => {
    if (!selectedJob || fixLoading) return;
    setFixLoading(true);
    setFixes([]);
    try {
      const res = await generateFixes(selectedJob);
      setFixes(res.fixes || []);
    } catch {
      // ignore
    } finally {
      setFixLoading(false);
    }
  };

  const filtered = useMemo(() => {
    let list = findings;
    if (severityFilter !== "All") {
      list = list.filter(
        (f) => f.severity.toLowerCase() === severityFilter.toLowerCase()
      );
    }
    if (categoryFilter !== "All") {
      list = list.filter(
        (f) => f.category.toLowerCase() === categoryFilter.toLowerCase()
      );
    }
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          f.location.file_path.toLowerCase().includes(q) ||
          (f.cwe || "").toLowerCase().includes(q)
      );
    }
    return list;
  }, [findings, severityFilter, categoryFilter, search]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }, [findings]);

  return (
    <div className="space-y-5 max-w-[1600px]">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-xl font-bold text-foreground">Security Findings</h1>
        <p className="text-sm text-muted mt-0.5">
          Browse and analyze detected vulnerabilities
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="grid grid-cols-5 gap-2"
      >
        {["critical", "high", "medium", "low", "info"].map((s) => (
          <button
            key={s}
            onClick={() =>
              setSeverityFilter(
                severityFilter === s.charAt(0).toUpperCase() + s.slice(1) ? "All" : s.charAt(0).toUpperCase() + s.slice(1)
              )
            }
            className={cn(
              "p-2.5 rounded-lg border text-center transition-all",
              severityFilter.toLowerCase() === s
                ? "border-accent/30 bg-accent/5"
                : "border-border bg-card hover:bg-card-hover"
            )}
          >
            <p
              className="text-lg font-bold font-[family-name:var(--font-geist-mono)]"
              style={{ color: severityColor(s) }}
            >
              {severityCounts[s] || 0}
            </p>
            <p className="text-[10px] text-muted uppercase tracking-wider font-medium">
              {s}
            </p>
          </button>
        ))}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card-elevated"
      >
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              type="text"
              placeholder="Search findings, rules, files, CWE..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-9 h-9 text-sm"
            />
          </div>

          <select
            value={selectedJob}
            onChange={(e) => {
              setSelectedJob(e.target.value);
              setLoading(true);
              setFixes([]);
            }}
            className="input h-9 w-48 text-xs bg-surface"
          >
            {jobs
              .filter((j) => j.status === "completed")
              .map((j) => (
                <option key={j.job_id} value={j.job_id}>
                  {j.target.split(/[/\\]/).pop()} — {j.finding_count} findings
                </option>
              ))}
          </select>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="input h-9 w-36 text-xs bg-surface"
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <button
            onClick={handleGenerateFixes}
            disabled={!selectedJob || fixLoading}
            className="flex items-center gap-1.5 px-3 h-9 rounded-lg text-xs font-medium bg-emerald-600/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-600/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Wrench className="w-3.5 h-3.5" />
            {fixLoading ? "Generating..." : "Fix Suggestions"}
          </button>

          <div className="flex items-center gap-1">
            {["json", "html", "markdown", "csv", "sarif"].map((fmt) => (
              <button
                key={fmt}
                onClick={() => handleExport(fmt)}
                title={`Export ${fmt.toUpperCase()}`}
                className="p-2 rounded-lg bg-surface border border-border text-muted hover:text-foreground hover:border-border-light transition-all"
              >
                <Download className="w-3.5 h-3.5" />
              </button>
            ))}
          </div>

          <span className="text-xs text-muted ml-auto">
            {filtered.length} of {total} findings
          </span>
        </div>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-14 shimmer rounded-lg" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center">
            <Shield className="w-10 h-10 text-muted/30 mx-auto mb-3" />
            <p className="text-sm text-muted">No findings match your filters</p>
            <p className="text-xs text-muted/60 mt-1">
              Try adjusting your search or filters
            </p>
          </div>
        ) : (
          <div className="space-y-0">
            <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-3 px-3 py-2 text-[11px] text-muted uppercase tracking-wider font-medium border-b border-border">
              <span className="w-20">Severity</span>
              <span>Finding</span>
              <span className="w-24">File</span>
              <span className="w-12 text-right">Line</span>
              <span className="w-16 text-right">CVSS</span>
              <span className="w-16 text-right">Conf.</span>
            </div>

            {filtered.map((f) => {
              const id = `${f.rule_id}-${f.location.file_path}-${f.location.line}`;
              const expanded = expandedId === id;
              return (
                <div key={id}>
                  <button
                    onClick={() => setExpandedId(expanded ? null : id)}
                    className="w-full grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-3 px-3 py-3 text-left border-b border-border/50 table-row items-center"
                  >
                    <div className="w-20">
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-foreground truncate">
                        {f.title}
                      </p>
                      <p className="text-[11px] text-muted truncate">{f.rule_id}</p>
                    </div>
                    <div className="w-24">
                      <p className="text-[11px] text-muted font-mono truncate">
                        {f.location.file_path.split(/[/\\]/).pop()}
                      </p>
                    </div>
                    <div className="w-12 text-right">
                      <span className="text-[11px] font-mono text-muted">
                        {f.location.line}
                      </span>
                    </div>
                    <div className="w-16 text-right">
                      <span className="text-[11px] font-mono text-muted">
                        {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                      </span>
                    </div>
                    <div className="w-16 text-right flex items-center justify-end gap-1">
                      <span className="text-[11px] font-mono text-muted">
                        {Math.round((f.confidence || 0) * 100)}%
                      </span>
                      {expanded ? (
                        <ChevronUp className="w-3 h-3 text-muted" />
                      ) : (
                        <ChevronDown className="w-3 h-3 text-muted" />
                      )}
                    </div>
                  </button>

                  <AnimatePresence>
                    {expanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <div className="px-4 py-3 bg-surface border-b border-border">
                          <FindingDetail finding={f} />
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        )}
      </motion.div>

      {fixes.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="card-elevated"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Wrench className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-foreground">
                Fix Suggestions ({fixes.length})
              </h3>
            </div>
            <button
              onClick={() => setFixes([])}
              className="text-muted hover:text-foreground transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-2">
            {fixes.map((fx, i) => {
              const fid = `${fx.rule_id}-${fx.file}-${fx.line}`;
              const open = fixExpanded === fid;
              return (
                <div key={i} className="border border-border rounded-lg overflow-hidden">
                  <button
                    onClick={() => setFixExpanded(open ? null : fid)}
                    className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-surface-elevated/50 transition-colors"
                  >
                    <SeverityBadge severity={findings.find((f) => f.rule_id === fx.rule_id)?.severity || "info"} />
                    <span className="text-xs font-medium text-foreground flex-1 truncate">{fx.title}</span>
                    <span className="text-[11px] font-mono text-muted truncate max-w-[200px]">
                      {fx.file.split(/[/\\]/).pop()}:{fx.line}
                    </span>
                    {open ? <ChevronUp className="w-3.5 h-3.5 text-muted" /> : <ChevronDown className="w-3.5 h-3.5 text-muted" />}
                  </button>
                  {open && (
                    <div className="px-3 pb-3 space-y-3">
                      {fx.fixes.map((fix, fi) => (
                        <div key={fi} className="space-y-1.5">
                          <div className="flex items-center gap-2">
                            <p className="text-xs text-foreground">{fix.description}</p>
                            {fix.effort && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-elevated text-muted">
                                effort: {fix.effort}
                              </span>
                            )}
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <div className="rounded-lg border border-red-500/20 bg-red-500/5 overflow-hidden">
                              <p className="text-[10px] text-red-400 px-3 py-1 border-b border-red-500/20 uppercase tracking-wider font-medium">Before</p>
                              <pre className="p-3 text-[11px] font-mono text-red-200/80 overflow-x-auto">{fix.before}</pre>
                            </div>
                            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 overflow-hidden">
                              <p className="text-[10px] text-emerald-400 px-3 py-1 border-b border-emerald-500/20 uppercase tracking-wider font-medium">After</p>
                              <pre className="p-3 text-[11px] font-mono text-emerald-200/80 overflow-x-auto">{fix.after}</pre>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </motion.div>
      )}
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  const [copied, setCopied] = useState(false);

  const copySnippet = () => {
    if (finding.location.code_snippet) {
      navigator.clipboard.writeText(finding.location.code_snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-3">
      {finding.fingerprint && (
        <a
          href={`/findings/${encodeURIComponent(finding.fingerprint)}`}
          className="inline-flex items-center gap-1 text-[11px] text-accent hover:underline"
        >
          View Full Details
          <ExternalLink className="w-3 h-3" />
        </a>
      )}
      <p className="text-xs text-foreground leading-relaxed">{finding.description}</p>

      <div className="flex flex-wrap gap-2">
        {finding.cwe && (
          <a
            href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}
            target="_blank"
            rel="noopener noreferrer"
            className="badge bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20 transition-colors"
          >
            {finding.cwe}
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
        {finding.owasp && (
          <span className="badge bg-purple-500/10 text-purple-400 border-purple-500/20">
            {typeof finding.owasp === "string" ? finding.owasp : `${finding.owasp.code}${finding.owasp.title ? ` · ${finding.owasp.title}` : ""}`}
          </span>
        )}
        {finding.exploitability && (
          <span className="badge bg-amber-500/10 text-amber-400 border-amber-500/20">
            Exploit: {finding.exploitability}
          </span>
        )}
        {finding.reachability && (
          <span className="badge bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
            {finding.reachability}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2 text-[11px] text-muted">
        <MapPin className="w-3 h-3" />
        <span className="font-mono">
          {finding.location.file_path}:{finding.location.line}
        </span>
      </div>

      {finding.location.code_snippet && (
        <div className="relative rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-3 py-1.5 bg-surface-elevated border-b border-border">
            <span className="text-[11px] text-muted font-mono">Code Snippet</span>
            <button
              onClick={copySnippet}
              className="text-muted hover:text-foreground transition-colors"
            >
              {copied ? (
                <span className="text-emerald-400 text-[11px]">Copied!</span>
              ) : (
                <Copy className="w-3 h-3" />
              )}
            </button>
          </div>
          <pre className="p-3 text-[11px] font-mono text-foreground/80 overflow-x-auto bg-background">
            {finding.location.code_snippet}
          </pre>
        </div>
      )}

      {finding.root_cause && (
        <div className="p-3 rounded-lg bg-surface border border-border">
          <p className="text-[11px] text-muted uppercase tracking-wider font-medium mb-1">
            Root Cause
          </p>
          <p className="text-xs text-foreground">{finding.root_cause}</p>
        </div>
      )}

      {finding.fix_suggestion && (
        <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/15">
          <p className="text-[11px] text-emerald-400 uppercase tracking-wider font-medium mb-1">
            Remediation
          </p>
          <p className="text-xs text-foreground">{finding.fix_suggestion}</p>
        </div>
      )}
    </div>
  );
}
