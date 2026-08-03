"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { getFindingDetail, bulkFindingAction } from "@/lib/api";
import type { FindingDetail } from "@/lib/api";
import {
  ArrowLeft,
  Copy,
  ExternalLink,
  MapPin,
  ShieldAlert,
  FileCode,
  Lightbulb,
  Target,
  Waves,
  GitBranch,
  Tag,
  Cpu,
  CheckCircle2,
  Loader2,
  ScanSearch,
  XCircle,
  AlertTriangle,
  Bug,
} from "lucide-react";

export function FindingDetailClient({ fingerprint }: { fingerprint: string }) {
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [actionMsg, setActionMsg] = useState("");

  const reload = () => {
    getFindingDetail(fingerprint)
      .then((d) => {
        setFinding(d);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message || "Finding not found");
        setLoading(false);
      });
  };

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fingerprint]);

  const verify = async (action: "mark_real" | "mark_false_positive") => {
    if (!finding || busy) return;
    setBusy(true);
    setActionError("");
    setActionMsg("");
    try {
      await bulkFindingAction({
        scan_id: finding.scan_id,
        action,
        fingerprints: [finding.fingerprint || ""],
      });
      setActionMsg(action === "mark_real" ? "Marked as a real finding" : "Marked as a false positive");
      reload();
      window.setTimeout(() => setActionMsg(""), 3000);
    } catch (e: unknown) {
      setActionError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  if (loading)
    return (
      <div className="flex items-center justify-center py-24 text-zinc-400">
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        Loading finding...
      </div>
    );

  if (error || !finding)
    return (
      <div className="py-24 text-center">
        <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-red-400">{error || "Finding not found"}</p>
        <Link href="/results" className="inline-block mt-4 text-xs text-emerald-400 hover:underline">
          Back to results
        </Link>
      </div>
    );

  const copySnippet = () => {
    if (finding.location.code_snippet) {
      navigator.clipboard.writeText(finding.location.code_snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <Link
          href={`/results?job_id=${finding.scan_id}`}
          className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white transition"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Results
        </Link>
        <div className="flex items-center gap-2 text-[11px] text-zinc-500">
          <span>Scan: {finding.scan_id?.slice(0, 8)}</span>
          <span>·</span>
          <span>{finding.scan_date ? new Date(finding.scan_date).toLocaleDateString() : ""}</span>
        </div>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-2">
          <SeverityBadge severity={finding.severity} size="md" />
          <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">{finding.category}</span>
          {finding.language && (
            <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">{finding.language}</span>
          )}
        </div>
        <h1 className="text-xl font-bold text-white mb-1">{finding.title}</h1>
        <p className="text-xs font-mono text-zinc-500 mb-4">{finding.rule_id}</p>
        <p className="text-sm text-zinc-300 leading-relaxed">{finding.description}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-[11px] text-zinc-500 uppercase tracking-wider font-medium mb-1">Severity</p>
          <p className="text-lg font-bold text-white capitalize">{finding.severity}</p>
        </div>
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-[11px] text-zinc-500 uppercase tracking-wider font-medium mb-1">CVSS Score</p>
          <p className="text-lg font-bold text-white">
            {finding.cvss?.score?.toFixed(1) ?? "N/A"}
          </p>
          {finding.cvss?.vector && (
            <p className="text-[10px] font-mono text-zinc-600 mt-1 break-all">{finding.cvss.vector}</p>
          )}
        </div>
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-[11px] text-zinc-500 uppercase tracking-wider font-medium mb-1">Confidence</p>
          <p className="text-lg font-bold text-white">{(finding.confidence * 100).toFixed(0)}%</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {finding.cwe && (
          <a
            href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 transition"
          >
            {finding.cwe}
            {finding.cwe_name && <span className="text-blue-400/70">· {finding.cwe_name}</span>}
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
        {finding.owasp && (
          <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <ShieldAlert className="w-3 h-3" />
            {finding.owasp.code} · {finding.owasp.title}
          </span>
        )}
        {finding.reachability && (
          <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <GitBranch className="w-3 h-3" />
            {finding.reachability}
          </span>
        )}
        {finding.verification_level && finding.verification_level !== "unverified" && (
          <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" />
            Verified: {finding.verification_level}
          </span>
        )}
        {finding.is_false_positive && (
          <span className="text-xs px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3 inline mr-1" />
            Verified
          </span>
        )}
      </div>

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

      {finding.likely_false_positive && !finding.is_false_positive && !finding.state?.verified && (
        <div className="bg-amber-500/5 border border-amber-500/25 rounded-xl p-4">
          <div className="flex items-start gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-[11px] text-amber-400 uppercase tracking-wider font-medium">
                Likely False Positive
              </p>
              {finding.likely_false_positive_reason && (
                <p className="text-xs text-zinc-300 leading-relaxed mt-1">{finding.likely_false_positive_reason}</p>
              )}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-1">
            <button
              disabled={busy}
              onClick={() => void verify("mark_real")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-200 hover:border-emerald-500/50 hover:text-emerald-300 disabled:opacity-40 transition"
            >
              <CheckCircle2 className="w-3 h-3" />
              Confirm real
            </button>
            <button
              disabled={busy}
              onClick={() => void verify("mark_false_positive")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-200 hover:border-red-500/50 hover:text-red-300 disabled:opacity-40 transition"
            >
              <Bug className="w-3 h-3" />
              Mark as false positive
            </button>
          </div>
        </div>
      )}

      {finding.is_false_positive && (
        <div className="flex items-center justify-between gap-3 bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4">
          <p className="text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Marked as a false positive
          </p>
          <button
            disabled={busy}
            onClick={() => void verify("mark_real")}
            className="px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-200 hover:border-emerald-500/50 hover:text-emerald-300 disabled:opacity-40 transition"
          >
            Mark as real
          </button>
        </div>
      )}

      {finding.state?.verified && !finding.is_false_positive && !finding.likely_false_positive && (
        <div className="flex items-center gap-2 bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <p className="text-xs text-emerald-400">Verified as a real finding</p>
        </div>
      )}

      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <MapPin className="w-4 h-4 text-zinc-500" />
            <span className="text-sm text-white font-mono">{finding.location.file_path}:{finding.location.line}</span>
            {finding.location.function && (
              <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">
                fn: {finding.location.function}
              </span>
            )}
          </div>
          {finding.location.code_snippet && (
            <button
              onClick={copySnippet}
              className="text-xs text-zinc-500 hover:text-white transition flex items-center gap-1"
            >
              {copied ? <span className="text-emerald-400">Copied!</span> : <Copy className="w-3.5 h-3.5" />}
            </button>
          )}
        </div>
        {finding.location.code_snippet && (
          <pre className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-300 overflow-x-auto">
            {finding.location.code_snippet}
          </pre>
        )}
      </div>

      {finding.raw_secret && (
        <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4">
          <p className="text-[11px] text-yellow-400 uppercase tracking-wider font-medium mb-2">
            Detected Secret
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono text-yellow-200 bg-zinc-950 rounded px-3 py-2">
              {showSecret ? finding.raw_secret : "••••••••••••••••••••"}
            </code>
            <button
              onClick={() => setShowSecret(!showSecret)}
              className="text-xs text-yellow-400 hover:text-yellow-300 transition px-3 py-2 rounded-lg border border-yellow-500/20"
            >
              {showSecret ? "Hide" : "Reveal"}
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {finding.why_vulnerable && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Waves className="w-4 h-4 text-red-400" />
              <p className="text-[11px] text-red-400 uppercase tracking-wider font-medium">Why Vulnerable</p>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">{finding.why_vulnerable}</p>
          </div>
        )}
        {finding.root_cause && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Cpu className="w-4 h-4 text-orange-400" />
              <p className="text-[11px] text-orange-400 uppercase tracking-wider font-medium">Root Cause</p>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">{finding.root_cause}</p>
          </div>
        )}
        {finding.impact && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-4 h-4 text-purple-400" />
              <p className="text-[11px] text-purple-400 uppercase tracking-wider font-medium">Impact</p>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">{finding.impact}</p>
          </div>
        )}
        {finding.exploit_scenario && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <p className="text-[11px] text-amber-400 uppercase tracking-wider font-medium">Exploit Scenario</p>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">{finding.exploit_scenario}</p>
          </div>
        )}
      </div>

      {(finding.fix_suggestion || finding.fixed_code) && (
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Lightbulb className="w-4 h-4 text-emerald-400" />
            <p className="text-[11px] text-emerald-400 uppercase tracking-wider font-medium">Remediation</p>
          </div>
          {finding.fix_suggestion && (
            <p className="text-sm text-zinc-200 leading-relaxed mb-3">{finding.fix_suggestion}</p>
          )}
          {finding.fixed_code && (
            <pre className="p-3 rounded-lg bg-zinc-950 border border-emerald-500/15 text-xs font-mono text-emerald-200/90 overflow-x-auto">
              {finding.fixed_code}
            </pre>
          )}
        </div>
      )}

      {finding.confidence_reasoning && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <FileCode className="w-4 h-4 text-zinc-500" />
            <p className="text-[11px] text-zinc-500 uppercase tracking-wider font-medium">Analysis Reasoning</p>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed whitespace-pre-line">{finding.confidence_reasoning}</p>
        </div>
      )}

      {(finding.matched_pattern || (finding.evidence && finding.evidence.length > 0)) && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <ScanSearch className="w-4 h-4 text-blue-400" />
            <p className="text-[11px] text-blue-400 uppercase tracking-wider font-medium">Detection Evidence</p>
          </div>
          {finding.matched_pattern && (
            <div className="mb-3">
              <p className="text-[11px] text-zinc-500 mb-1">Matched pattern</p>
              <pre className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-xs font-mono text-blue-300/90 overflow-x-auto">
                {finding.matched_pattern}
              </pre>
            </div>
          )}
          {finding.evidence && finding.evidence.length > 0 && (
            <ul className="space-y-2">
              {finding.evidence.map((ev, i) => {
                const wrapper = ev as unknown as {
                  evidences?: Array<{ reason: string; strength: string; type: string }>;
                  negativeEvidences?: Array<{ reason: string; strength: string }>;
                };
                if (wrapper?.evidences || wrapper?.negativeEvidences) {
                  return (
                    <li key={i} className="space-y-1.5">
                      {wrapper.evidences?.map((e, j) => (
                        <p key={`p-${j}`} className="text-xs text-emerald-400/90 leading-relaxed flex gap-2">
                          <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                          <span>
                            {e.reason}
                            <span className="text-zinc-600 ml-1">· {e.strength}{e.type ? ` · ${e.type}` : ""}</span>
                          </span>
                        </p>
                      ))}
                      {wrapper.negativeEvidences?.map((e, j) => (
                        <p key={`n-${j}`} className="text-xs text-amber-400/90 leading-relaxed flex gap-2">
                          <XCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                          <span>
                            {e.reason}
                            <span className="text-zinc-600 ml-1">· {e.strength}</span>
                          </span>
                        </p>
                      ))}
                    </li>
                  );
                }
                const plain = ev as { type?: string; detail?: string; matched?: string; line?: number };
                return (
                  <li key={i} className="text-xs text-zinc-400 leading-relaxed flex gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-emerald-400/80" />
                    <span>
                      {plain.detail}
                      {plain.matched && (
                        <code className="block mt-1 px-2 py-1 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-zinc-300">
                          {plain.matched}
                        </code>
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      {finding.tags && finding.tags.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <Tag className="w-3.5 h-3.5 text-zinc-500" />
          {finding.tags.map((t) => (
            <span key={t} className="text-xs px-2 py-0.5 rounded-lg bg-zinc-800 text-zinc-400">
              {t}
            </span>
          ))}
        </div>
      )}

      {finding.references && finding.references.length > 0 && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <p className="text-[11px] text-zinc-500 uppercase tracking-wider font-medium mb-3">
            References
          </p>
          <ul className="space-y-2">
            {finding.references.map((ref, i) => (
              <li key={i}>
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-400 hover:text-blue-300 hover:underline break-all flex items-center gap-1"
                >
                  {ref}
                  <ExternalLink className="w-3 h-3 flex-shrink-0" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
