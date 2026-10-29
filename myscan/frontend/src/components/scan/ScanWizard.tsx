"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FolderOpen,
  Settings2,
  Rocket,
  CheckCircle2,
  Loader2,
  AlertCircle,
  ChevronRight,
  ChevronLeft,
  Zap,
  Lock,
  FileCode,
  GitBranch,
  GitPullRequest,
  Clock,
  Sliders,
  Globe,
} from "lucide-react";
import { startScan, getScanStatus, subscribeToScanEvents, cancelScan, pauseScan, resumeScan, getHistory } from "@/lib/api";
import type { Finding, ScanJob, ScanResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/ui/SeverityBadge";

interface ScanConfig {
  target: string;
  enterprise: boolean;
  threads: number;
  minConfidence: number;
  secretDisplay: string;
}

const steps = [
  { id: 0, label: "Repository", icon: FolderOpen },
  { id: 1, label: "Scan Profile", icon: Settings2 },
  { id: 2, label: "Options", icon: Sliders },
  { id: 3, label: "Launch", icon: Rocket },
];

const presets = [
  {
    name: "Quick Scan",
    desc: "Fast analysis with essential rules",
    enterprise: false,
    threads: 2,
    confidence: 0.3,
    icon: Zap,
    color: "#22C55E",
  },
  {
    name: "Standard Scan",
    desc: "Balanced depth and speed",
    enterprise: false,
    threads: 4,
    confidence: 0.2,
    icon: FileCode,
    color: "#3B82F6",
  },
  {
    name: "Enterprise Scan",
    desc: "Deep analysis with all engines",
    enterprise: true,
    threads: 8,
    confidence: 0.15,
    icon: Lock,
    color: "#00E5FF",
  },
];

function isUrl(s: string): boolean {
  return /^(https?:\/\/|git@|ssh:\/\/|git:\/\/).+/i.test(s.trim());
}

function repoName(url: string): string {
  const parts = url.replace(/\.git$/, "").split("/");
  return parts[parts.length - 1] || url;
}

export function ScanWizard() {
  const [step, setStep] = useState(0);
  const [recentRepos, setRecentRepos] = useState<string[]>([]);
  const [config, setConfig] = useState<ScanConfig>({
    target: "",
    enterprise: false,
    threads: 4,
    minConfidence: 0.2,
    secretDisplay: "smart",
  });

  useEffect(() => {
    getHistory(15)
      .then((res) => {
        if (res && res.history) {
          const unique = Array.from(new Set(res.history.map((j) => j.target).filter(Boolean))).slice(0, 5);
          setRecentRepos(unique);
        }
      })
      .catch(() => {});
  }, []);
  const [scanning, setScanning] = useState(false);
  const scanningRef = useRef(false);
  const [result, setResult] = useState<ScanJob | null>(null);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);
  const [jobId, setJobId] = useState("");
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [currentFile, setCurrentFile] = useState("");
  const [scanPhase, setScanPhase] = useState("");
  const [paused, setPaused] = useState(false);
  const [eta, setEta] = useState(0);
  const [severityLive, setSeverityLive] = useState<Record<string, number>>({
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  });

  const canNext = useCallback(() => {
    if (step === 0) return config.target.trim().length > 0;
    return true;
  }, [step, config.target]);

  const launchScan = async () => {
    setScanning(true);
    scanningRef.current = true;
    setError("");
    setProgress(5);
    setLiveFindings([]);
    setPaused(false);
    setSeverityLive({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    const remote = isUrl(config.target);
    try {
      const res = await startScan({
        target: config.target,
        enterprise: config.enterprise,
        threads: config.threads,
        min_confidence: config.minConfidence,
        secret_display: config.secretDisplay,
      });
      setJobId(res.job_id);
      setProgress(remote ? 10 : 15);

      const unsubscribe = subscribeToScanEvents(res.job_id, {
        onInit: (d) => {
          if (typeof d.total_files === "number") {
            setProgress(remote ? 12 : 20);
          }
        },
        onProgress: (d) => {
          if (typeof d.percent === "number") {
            setProgress(remote ? 10 + (d.percent as number) * 0.8 : d.percent as number);
          }
          if (typeof d.eta === "number") setEta(d.eta);
          if (typeof d.phase === "string" && d.phase) setScanPhase(d.phase);
        },
        onFinding: (d) => {
          const f = d.finding as Finding | undefined;
          if (f) {
            setLiveFindings((prev) => [f, ...prev].slice(0, 20));
            setSeverityLive((prev) => {
              const sev = f.severity || "info";
              return { ...prev, [sev]: (prev[sev] || 0) + 1 };
            });
          }
        },
        onFile: (d) => {
          if (typeof d.file === "string") {
            setCurrentFile(d.file);
          }
        },
        onPaused: () => setPaused(true),
        onResumed: () => setPaused(false),
        onCancelled: () => {
          setError("Scan cancelled");
          setScanning(false);
        },
        onError: (d) => {
          setError((d.error as string) || "Scan failed");
          setScanning(false);
        },
        onComplete: (d) => {
          setProgress(100);
          setScanPhase("completed");
          setTimeout(async () => {
            try {
              const status = await getScanStatus(res.job_id);
              setResult(status);
            } catch {
              const data = d as Partial<ScanResult>;
              const summary = {
                total_findings: data.total_findings ?? 0,
                security_findings: data.security_findings ?? 0,
                quality_findings: data.quality_findings ?? 0,
                secret_findings: data.secret_findings ?? 0,
                risk_score: data.risk_score ?? 0,
                grade: data.grade ?? "N/A",
                severity_counts: data.severity_counts ?? {},
                files_scanned: data.files_scanned ?? 0,
                lines_scanned: data.lines_scanned ?? 0,
                languages: data.languages ?? [],
                scan_duration: data.scan_duration ?? 0,
              };
              setResult({
                job_id: res.job_id,
                status: "completed",
                target: config.target,
                enterprise: config.enterprise,
                started_at: new Date().toISOString(),
                completed_at: new Date().toISOString(),
                finding_count: summary.total_findings,
                result: {
                  ...summary,
                  findings: data.findings ?? [],
                  summary,
                },
              });
            }
            setScanning(false);
          }, 300);
        },
      });

      // Fallback: if SSE fails silently, poll as backup
      let attempts = 0;
      const maxAttempts = remote ? 300 : 120;
      const poll = async () => {
        if (!scanningRef.current) return;
        attempts++;
        try {
          const status = await getScanStatus(res.job_id);
          if (status.status === "completed") {
            unsubscribe();
            setProgress(100);
            setResult(status);
            setScanning(false);
            return;
          }
          if (status.status === "failed") {
            unsubscribe();
            setError(status.error || "Scan failed");
            setScanning(false);
            return;
          }
        } catch {
          // ignore poll errors
        }
        if (attempts < maxAttempts) {
          setTimeout(poll, remote ? 2000 : 1000);
        }
      };
      setTimeout(poll, remote ? 2000 : 500);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to start scan");
      setScanning(false);
      scanningRef.current = false;
    }
  };

  const handleCancel = async () => {
    if (!jobId) return;
    try {
      await cancelScan(jobId);
      setError("Cancelling scan...");
    } catch {
      setScanning(false);
      scanningRef.current = false;
      setError("Failed to cancel scan");
    }
  };

  const handlePause = async () => {
    if (!jobId || paused) return;
    try {
      await pauseScan(jobId);
      setPaused(true);
    } catch {
      // ignore
    }
  };

  const handleResume = async () => {
    if (!jobId || !paused) return;
    try {
      await resumeScan(jobId);
      setPaused(false);
    } catch {
      // ignore
    }
  };

  const resetWizard = () => {
    setResult(null);
    setStep(0);
    setProgress(0);
    setLiveFindings([]);
    setCurrentFile("");
    setScanPhase("");
    setEta(0);
    setPaused(false);
    setScanning(false);
    scanningRef.current = false;
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-xl font-bold text-foreground">New Security Scan</h1>
        <p className="text-sm text-muted mt-0.5">
          Configure and launch a static analysis scan
        </p>
      </motion.div>

      <div className="flex items-center gap-1 bg-card border border-border rounded-xl p-1.5">
        {steps.map((s, i) => (
          <div key={s.id} className="flex items-center flex-1">
            <button
              onClick={() => !scanning && i < step && setStep(i)}
              className={cn(
                "flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all w-full",
                i === step
                  ? "bg-accent/10 text-accent"
                  : i < step
                  ? "text-emerald-400 hover:bg-surface-elevated"
                  : "text-muted"
              )}
            >
              {i < step ? (
                <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
              ) : (
                <s.icon className="w-3.5 h-3.5 flex-shrink-0" />
              )}
              <span className="hidden sm:inline">{s.label}</span>
            </button>
            {i < steps.length - 1 && (
              <ChevronRight className="w-3 h-3 text-muted/30 mx-1 flex-shrink-0" />
            )}
          </div>
        ))}
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={step}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.2 }}
        >
          {step === 0 && (
            <div className="card-elevated space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground mb-1">
                  Target Repository
                </h3>
                <p className="text-xs text-muted">
                  Enter a local path or paste a Git URL (GitHub, GitLab, etc.)
                </p>
              </div>

              <div className="relative">
                {isUrl(config.target) ? (
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-accent" />
                ) : (
                  <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
                )}
                <input
                  type="text"
                  className={cn(
                    "input pl-10 h-11 font-mono text-sm",
                    isUrl(config.target) && "border-accent/30"
                  )}
                  placeholder="/path/to/repo or https://github.com/user/repo"
                  value={config.target}
                  onChange={(e) =>
                    setConfig({ ...config, target: e.target.value })
                  }
                  onKeyDown={(e) => e.key === "Enter" && canNext() && setStep(1)}
                  autoFocus
                />
                {isUrl(config.target) && (
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-accent font-medium bg-accent/10 px-1.5 py-0.5 rounded">
                    REMOTE
                  </span>
                )}
              </div>

              {recentRepos.length > 0 && (
                <div>
                  <p className="text-[11px] text-muted font-medium uppercase tracking-wider mb-2">
                    Recent
                  </p>
                  <div className="space-y-1">
                    {recentRepos.map((repo) => {
                      const isRemote = isUrl(repo);
                      const name = isRemote ? repoName(repo) : repo;
                      return (
                        <button
                          key={repo}
                          onClick={() => setConfig({ ...config, target: repo })}
                          className={cn(
                            "flex items-center gap-2 w-full px-3 py-2 rounded-lg text-xs transition-all text-left",
                            config.target === repo
                              ? "bg-accent/10 text-accent border border-accent/20"
                              : "text-muted hover:bg-surface-elevated hover:text-foreground border border-transparent"
                          )}
                        >
                          {isRemote ? (
                            <GitPullRequest className="w-3.5 h-3.5 flex-shrink-0" />
                          ) : (
                            <GitBranch className="w-3.5 h-3.5 flex-shrink-0" />
                          )}
                          <span className="truncate font-mono">{name}</span>
                          {isRemote && (
                            <span className="ml-auto text-[10px] text-muted/50">remote</span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 1 && (
            <div className="card-elevated space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground mb-1">
                  Scan Profile
                </h3>
                <p className="text-xs text-muted">
                  Choose the analysis depth and engines
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {presets.map((preset) => (
                  <button
                    key={preset.name}
                    onClick={() =>
                      setConfig({
                        ...config,
                        enterprise: preset.enterprise,
                        threads: preset.threads,
                        minConfidence: preset.confidence,
                      })
                    }
                    className={cn(
                      "p-4 rounded-xl border text-left transition-all",
                      config.enterprise === preset.enterprise &&
                        config.threads === preset.threads
                        ? "border-accent/40 bg-accent/5"
                        : "border-border hover:border-border-light bg-card"
                    )}
                  >
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center mb-3"
                      style={{ background: `${preset.color}12` }}
                    >
                      <preset.icon
                        className="w-4 h-4"
                        style={{ color: preset.color }}
                      />
                    </div>
                    <p className="text-sm font-semibold text-foreground">
                      {preset.name}
                    </p>
                    <p className="text-xs text-muted mt-1">{preset.desc}</p>
                    <div className="flex items-center gap-2 mt-3 text-[11px] text-muted">
                      <span>{preset.threads} threads</span>
                      <span className="w-1 h-1 rounded-full bg-muted/30" />
                      <span>{(preset.confidence * 100).toFixed(0)}% min conf</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="card-elevated space-y-5">
              <div>
                <h3 className="text-sm font-semibold text-foreground mb-1">
                  Advanced Options
                </h3>
                <p className="text-xs text-muted">
                  Fine-tune the scan parameters
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="space-y-2">
                  <label className="text-xs font-medium text-foreground">
                    Thread Count: {config.threads}
                  </label>
                  <input
                    type="range"
                    min={1}
                    max={16}
                    value={config.threads}
                    onChange={(e) =>
                      setConfig({ ...config, threads: Number(e.target.value) })
                    }
                    className="w-full h-1.5 bg-surface-elevated rounded-full appearance-none cursor-pointer accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-muted">
                    <span>1 (Safe)</span>
                    <span>16 (Fast)</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium text-foreground">
                    Min Confidence: {(config.minConfidence * 100).toFixed(0)}%
                  </label>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={config.minConfidence * 100}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        minConfidence: Number(e.target.value) / 100,
                      })
                    }
                    className="w-full h-1.5 bg-surface-elevated rounded-full appearance-none cursor-pointer accent-accent"
                  />
                  <div className="flex justify-between text-[11px] text-muted">
                    <span>0% (All)</span>
                    <span>100% (Certain)</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium text-foreground">
                    Secret Display Mode
                  </label>
                  <div className="flex gap-2">
                    {["smart", "masked", "full"].map((mode) => (
                      <button
                        key={mode}
                        onClick={() =>
                          setConfig({ ...config, secretDisplay: mode })
                        }
                        className={cn(
                          "flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-all border",
                          config.secretDisplay === mode
                            ? "bg-accent/10 text-accent border-accent/20"
                            : "bg-card text-muted border-border hover:border-border-light"
                        )}
                      >
                        {mode.charAt(0).toUpperCase() + mode.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium text-foreground">
                    Enterprise Mode
                  </label>
                  <button
                    onClick={() =>
                      setConfig({ ...config, enterprise: !config.enterprise })
                    }
                    className={cn(
                      "flex items-center gap-3 w-full px-4 py-3 rounded-lg border transition-all",
                      config.enterprise
                        ? "bg-accent/5 border-accent/20 text-accent"
                        : "bg-card border-border text-muted hover:border-border-light"
                    )}
                  >
                    <Lock className="w-4 h-4" />
                    <div className="text-left flex-1">
                      <p className="text-xs font-semibold">
                        {config.enterprise ? "Enabled" : "Disabled"}
                      </p>
                      <p className="text-[11px] opacity-70">
                        Semantic analysis, call graphs, taint tracking
                      </p>
                    </div>
                    <div
                      className={cn(
                        "w-9 h-5 rounded-full transition-all relative",
                        config.enterprise ? "bg-accent" : "bg-surface-elevated"
                      )}
                    >
                      <div
                        className={cn(
                          "absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all",
                          config.enterprise ? "left-[18px]" : "left-0.5"
                        )}
                      />
                    </div>
                  </button>
                </div>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="card-elevated space-y-5">
              {scanning ? (
                <div className="space-y-5">
                  <div className="text-center pt-4">
                    <Loader2 className="w-10 h-10 text-accent mx-auto mb-4 animate-spin" />
                    <h3 className="text-sm font-semibold text-foreground mb-1">
                      Scanning in Progress
                    </h3>
                    <p className="text-xs text-muted mb-2">
                      {scanPhase === "cloning"
                        ? "Cloning remote repository..."
                        : scanPhase === "completed"
                        ? "Finalizing results..."
                        : currentFile
                        ? "Analyzing source code..."
                        : "Analyzing codebase for security vulnerabilities..."}
                    </p>
                    {currentFile && (
                      <p className="text-[11px] text-muted/70 font-mono truncate max-w-md mx-auto mb-3">
                        {currentFile}
                      </p>
                    )}
                    <div className="max-w-md mx-auto">
                      <div className="h-2 bg-surface-elevated rounded-full overflow-hidden">
                        <motion.div
                          className="h-full bg-accent rounded-full"
                          initial={{ width: "0%" }}
                          animate={{ width: `${progress}%` }}
                          transition={{ duration: 0.3 }}
                        />
                      </div>
                      <div className="flex justify-between mt-2">
                        <p className="text-[11px] text-muted">
                          {progress.toFixed(0)}% complete
                        </p>
                        {eta > 0 && (
                          <p className="text-[11px] text-muted">
                            ETA ~{Math.ceil(eta)}s
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-5 gap-2 max-w-md mx-auto">
                    {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                      <div key={s} className="text-center">
                        <p
                          className={`text-lg font-bold font-[family-name:var(--font-geist-mono)] ${
                            s === "critical" ? "text-red-400"
                            : s === "high" ? "text-orange-400"
                            : s === "medium" ? "text-yellow-400"
                            : s === "low" ? "text-blue-400"
                            : "text-zinc-400"
                          }`}
                        >
                          {severityLive[s]}
                        </p>
                        <p className="text-[10px] text-muted uppercase tracking-wider">{s}</p>
                      </div>
                    ))}
                  </div>

                  {liveFindings.length > 0 && (
                    <div className="max-w-md mx-auto space-y-1.5 max-h-40 overflow-y-auto">
                      <p className="text-[10px] text-muted uppercase tracking-wider text-center">
                        Live Findings
                      </p>
                      {liveFindings.map((f, i) => (
                        <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded bg-surface border border-border">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-[11px] text-foreground truncate flex-1">{f.title}</span>
                          <span className="text-[10px] text-muted font-mono shrink-0">
                            {f.location?.file_path?.split(/[/\\]/).pop()}:{f.location?.line}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex items-center justify-center gap-2">
                    {paused ? (
                      <button
                        onClick={handleResume}
                        className="btn-secondary text-xs flex items-center gap-1"
                      >
                        <Rocket className="w-3.5 h-3.5" />
                        Resume
                      </button>
                    ) : (
                      <button
                        onClick={handlePause}
                        className="btn-secondary text-xs flex items-center gap-1"
                      >
                        <Clock className="w-3.5 h-3.5" />
                        Pause
                      </button>
                    )}
                    <button
                      onClick={handleCancel}
                      className="px-4 py-2 rounded-lg text-xs font-medium border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-all flex items-center gap-1"
                    >
                      <AlertCircle className="w-3.5 h-3.5" />
                      Cancel
                    </button>
                  </div>
                </div>
              ) : result ? (
                <div className="space-y-4">
                  <div className="text-center pb-4 border-b border-border">
                    <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
                    <h3 className="text-sm font-semibold text-foreground">
                      Scan Complete
                    </h3>
                    <p className="text-xs text-muted">
                      Job ID: {jobId}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      {
                        label: "Findings",
                        value: result.result?.summary?.total_findings ?? result.finding_count ?? 0,
                        color: "#F59E0B",
                      },
                      {
                        label: "Critical",
                        value: result.result?.summary?.severity_counts?.critical ?? 0,
                        color: "#EF4444",
                      },
                      {
                        label: "Risk Score",
                        value: `${result.result?.summary?.risk_score ?? 0}/100`,
                        color: "#3B82F6",
                      },
                      {
                        label: "Grade",
                        value: result.result?.summary?.grade ?? "N/A",
                        color: "#22C55E",
                      },
                    ].map((m) => (
                      <div
                        key={m.label}
                        className="p-3 rounded-lg bg-surface border border-border text-center"
                      >
                        <p className="text-lg font-bold font-[family-name:var(--font-geist-mono)]" style={{ color: m.color }}>
                          {m.value}
                        </p>
                        <p className="text-[11px] text-muted mt-0.5">{m.label}</p>
                      </div>
                    ))}
                  </div>

                  {(result.result?.findings?.length ?? 0) > 0 && (
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      <p className="text-xs font-medium text-muted uppercase tracking-wider">
                        Top Findings
                      </p>
                      {result?.result?.findings?.slice(0, 5).map((f, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-3 p-3 rounded-lg bg-surface border border-border"
                        >
                          <SeverityBadge severity={f.severity} />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-medium text-foreground truncate">
                              {f.title}
                            </p>
                            <p className="text-[11px] text-muted font-mono truncate">
                              {f.location?.file_path}:{f.location?.line}
                            </p>
                          </div>
                          <span className="text-[11px] text-muted font-mono">
                            {Math.round((f.confidence || 0) * 100)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex gap-2">
                    <a href={`/results?job_id=${jobId}`} className="btn-primary text-xs">
                      View Findings
                    </a>
                    <a href="/reports" className="btn-secondary text-xs">
                      Full Report
                    </a>
                    <button
                      onClick={resetWizard}
                      className="btn-secondary text-xs"
                    >
                      New Scan
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-semibold text-foreground mb-1">
                      Review & Launch
                    </h3>
                    <p className="text-xs text-muted">
                      Confirm your scan configuration
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-surface border border-border">
                      <p className="text-[11px] text-muted mb-0.5">Target</p>
                      <div className="flex items-center gap-1.5">
                        {isUrl(config.target) ? (
                          <Globe className="w-3 h-3 text-accent flex-shrink-0" />
                        ) : (
                          <FolderOpen className="w-3 h-3 text-muted flex-shrink-0" />
                        )}
                        <p className="text-xs font-mono text-foreground truncate">
                          {isUrl(config.target) ? repoName(config.target) : config.target}
                        </p>
                      </div>
                      {isUrl(config.target) && (
                        <p className="text-[10px] text-muted/60 mt-0.5 truncate">{config.target}</p>
                      )}
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border">
                      <p className="text-[11px] text-muted mb-0.5">Profile</p>
                      <p className="text-xs text-foreground">
                        {config.enterprise ? "Enterprise" : config.threads > 4 ? "Standard" : "Quick"}
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border">
                      <p className="text-[11px] text-muted mb-0.5">Threads</p>
                      <p className="text-xs font-mono text-foreground">{config.threads}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border">
                      <p className="text-[11px] text-muted mb-0.5">Min Confidence</p>
                      <p className="text-xs font-mono text-foreground">
                        {(config.minConfidence * 100).toFixed(0)}%
                      </p>
                    </div>
                  </div>

                  {error && (
                    <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />
                      {error}
                    </div>
                  )}

                  <button onClick={launchScan} className="btn-primary w-full h-11">
                    <Rocket className="w-4 h-4 inline mr-2" />
                    Launch Scan
                  </button>
                </div>
              )}
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      {!scanning && !result && (
        <div className="flex justify-between">
          <button
            onClick={() => setStep(Math.max(0, step - 1))}
            disabled={step === 0}
            className="btn-secondary text-xs flex items-center gap-1 disabled:opacity-30"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            Back
          </button>
          {step < 3 && (
            <button
              onClick={() => canNext() && setStep(step + 1)}
              disabled={!canNext()}
              className="btn-primary text-xs flex items-center gap-1 disabled:opacity-30"
            >
              Continue
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}
    </div>
  );
}
