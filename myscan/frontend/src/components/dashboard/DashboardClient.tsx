"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { MetricCard } from "@/components/ui/MetricCard";
import {
  Shield,
  AlertTriangle,
  AlertOctagon,
  Activity,
  FolderOpen,
} from "lucide-react";
import { getStats, getHistory } from "@/lib/api";
import { formatNumber, timeAgo, severityColor } from "@/lib/utils";
import type { Stats, ScanJob } from "@/lib/types";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function SkeletonCard() {
  return (
    <div className="metric-card animate-pulse">
      <div className="w-9 h-9 rounded-lg bg-surface-elevated mb-3" />
      <div className="h-7 w-16 bg-surface-elevated rounded mb-1" />
      <div className="h-3 w-24 bg-surface-elevated rounded" />
    </div>
  );
}

function SkeletonTable() {
  return (
    <div className="space-y-3">
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="flex items-center gap-4 animate-pulse">
          <div className="w-2 h-2 rounded-full bg-surface-elevated" />
          <div className="h-3 flex-1 bg-surface-elevated rounded" />
          <div className="h-3 w-12 bg-surface-elevated rounded" />
          <div className="h-3 w-20 bg-surface-elevated rounded" />
        </div>
      ))}
    </div>
  );
}

export function DashboardClient() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getStats().catch(() => null),
      getHistory(10).catch(() => ({ history: [] as ScanJob[], total: 0 })),
    ]).then(([s, h]) => {
      setStats(s);
      setHistory(h.history || []);
      setLoading(false);
    });
  }, []);

  const severityData = stats
    ? SEVERITY_ORDER.map((s) => ({
        name: s.charAt(0).toUpperCase() + s.slice(1),
        count: stats.severity_totals[s] || 0,
        fill: severityColor(s),
      }))
    : [];

  return (
    <div className="space-y-6 max-w-[1600px]">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <p className="text-sm text-muted italic font-medium">
          Detect vulnerabilities. Validate risks. Secure your code.
        </p>
      </motion.div>

      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Total Scans"
            value={stats?.total_scans ?? 0}
            icon={Activity}
            accentColor="#3B82F6"
            index={0}
          />
          <MetricCard
            title="Total Findings"
            value={formatNumber(stats?.total_findings ?? 0)}
            subtitle={`${stats?.avg_findings_per_scan ?? 0} avg/scan`}
            icon={AlertTriangle}
            accentColor="#F59E0B"
            index={1}
          />
          <MetricCard
            title="Critical Issues"
            value={stats?.severity_totals?.critical ?? 0}
            icon={AlertOctagon}
            accentColor="#EF4444"
            index={2}
          />
          <MetricCard
            title="Success Rate"
            value={
              stats && stats.total_scans > 0
                ? `${Math.round(((stats.completed_scans || 0) / stats.total_scans) * 100)}%`
                : "0%"
            }
            icon={Shield}
            accentColor="#22C55E"
            index={3}
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card-elevated"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Severity Distribution</h3>
              <p className="text-xs text-muted mt-0.5">Aggregated findings across all scans</p>
            </div>
          </div>
          {loading ? (
            <div className="h-48 shimmer rounded-lg" />
          ) : severityData.some((d) => d.count > 0) ? (
            <div className="flex items-center gap-6 py-2">
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={38}
                    outerRadius={60}
                    paddingAngle={3}
                    dataKey="count"
                    strokeWidth={0}
                  >
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 flex-1">
                {severityData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ background: d.fill }} />
                      <span className="text-muted font-medium">{d.name}</span>
                    </div>
                    <span className="font-mono text-foreground font-semibold">{formatNumber(d.count)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-sm text-muted">
              No findings data recorded
            </div>
          )}
        </motion.div>

        {/* Recent Scans */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="card-elevated"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Recent Scans</h3>
              <p className="text-xs text-muted mt-0.5">Latest target analysis executions</p>
            </div>
            <a href="/reports" className="text-xs text-accent hover:underline font-medium">
              View all
            </a>
          </div>
          {loading ? (
            <SkeletonTable />
          ) : history.length > 0 ? (
            <div className="space-y-0">
              {history.slice(0, 6).map((job) => (
                <div
                  key={job.job_id}
                  className="flex items-center gap-3 py-2.5 border-b border-border/50 last:border-0 table-row"
                >
                  <span
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      job.status === "completed"
                        ? "bg-emerald-400"
                        : job.status === "failed"
                        ? "bg-red-400"
                        : "bg-amber-400"
                    }`}
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-foreground truncate">
                      {job.target.split(/[/\\]/).pop() || job.target}
                    </p>
                    <p className="text-[11px] text-muted truncate">{job.target}</p>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className="text-xs font-mono text-foreground font-medium">{job.finding_count} issues</p>
                    <p className="text-[11px] text-muted">{timeAgo(job.started_at)}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-48 flex flex-col items-center justify-center text-sm text-muted">
              <FolderOpen className="w-8 h-8 mb-2 opacity-40" />
              <p>No scans yet</p>
              <p className="text-xs mt-1 text-muted/60">Run your first scan to see results</p>
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
}
