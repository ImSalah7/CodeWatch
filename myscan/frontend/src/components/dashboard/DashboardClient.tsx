"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { MetricCard } from "@/components/ui/MetricCard";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Activity,
  FolderOpen,
  Clock,
  FileCode,
  TrendingUp,
} from "lucide-react";
import { getStats, getHistory, getSecurityScore } from "@/lib/api";
import { formatNumber, timeAgo, severityColor } from "@/lib/utils";
import type { Stats, ScanJob } from "@/lib/types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
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

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel px-3 py-2 text-xs">
      <p className="text-foreground font-medium mb-1">{label}</p>
      {payload.map((entry: any, i: number) => (
        <p key={i} style={{ color: entry.color }} className="font-mono">
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
};

export function DashboardClient() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [score, setScore] = useState<{ score: number; grade: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getStats().catch(() => null),
      getHistory(10).catch(() => ({ history: [] as ScanJob[], total: 0 })),
      getSecurityScore().catch(() => null),
    ]).then(([s, h, sc]) => {
      setStats(s);
      setHistory(h.history || []);
      setScore(sc);
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

  const categoryData = stats
    ? Object.entries(stats.category_totals).map(([name, count]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        count,
      }))
    : [];

  const trendData = history
    .slice()
    .reverse()
    .map((j, i) => ({
      name: `#${i + 1}`,
      findings: j.finding_count,
      status: j.status === "completed" ? 1 : 0,
    }));

  return (
    <div className="space-y-6 max-w-[1600px]">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-xl font-bold text-foreground">Security Overview</h1>
          <p className="text-sm text-muted mt-0.5">
            Real-time vulnerability monitoring and risk assessment
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Engine Online
        </div>
      </motion.div>

      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {[1, 2, 3, 4, 5].map((i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <MetricCard
            title="Security Score"
            value={score ? `${score.score} ${score.grade}` : "—"}
            icon={ShieldCheck}
            accentColor="#00E5FF"
            index={0}
          />
          <MetricCard
            title="Total Scans"
            value={stats?.total_scans ?? 0}
            icon={Activity}
            accentColor="#3B82F6"
            index={1}
          />
          <MetricCard
            title="Findings"
            value={formatNumber(stats?.total_findings ?? 0)}
            subtitle={`${stats?.avg_findings_per_scan ?? 0} avg/scan`}
            icon={AlertTriangle}
            accentColor="#F59E0B"
            index={2}
          />
          <MetricCard
            title="Critical Issues"
            value={stats?.severity_totals?.critical ?? 0}
            icon={AlertOctagon}
            accentColor="#EF4444"
            index={3}
          />
          <MetricCard
            title="Success Rate"
            value={
              stats
                ? `${Math.round(((stats.completed_scans || 0) / Math.max(stats.total_scans, 1)) * 100)}%`
                : "0%"
            }
            icon={Shield}
            accentColor="#22C55E"
            index={4}
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="card-elevated lg:col-span-2"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Findings Trend</h3>
              <p className="text-xs text-muted mt-0.5">Findings per scan over time</p>
            </div>
            <TrendingUp className="w-4 h-4 text-muted" />
          </div>
          {loading ? (
            <div className="h-48 shimmer rounded-lg" />
          ) : trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="findingsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#00E5FF" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#334155" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#334155" fontSize={11} tickLine={false} axisLine={false} width={30} />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="findings"
                  stroke="#00E5FF"
                  strokeWidth={2}
                  fill="url(#findingsGrad)"
                  name="Findings"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-sm text-muted">
              No scan data yet
            </div>
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card-elevated"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Severity Distribution</h3>
              <p className="text-xs text-muted mt-0.5">Across all scans</p>
            </div>
          </div>
          {loading ? (
            <div className="h-48 shimmer rounded-lg" />
          ) : severityData.some((d) => d.count > 0) ? (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width={120} height={120}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={32}
                    outerRadius={52}
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
              <div className="space-y-1.5 flex-1">
                {severityData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full" style={{ background: d.fill }} />
                      <span className="text-muted">{d.name}</span>
                    </div>
                    <span className="font-mono text-foreground font-medium">{d.count}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-sm text-muted">
              No findings data
            </div>
          )}
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
          className="card-elevated"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-foreground">Categories</h3>
          </div>
          {loading ? (
            <div className="h-48 shimmer rounded-lg" />
          ) : categoryData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={categoryData} layout="vertical">
                <XAxis type="number" stroke="#334155" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#334155"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  width={80}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} name="Count" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-sm text-muted">
              No category data
            </div>
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="card-elevated"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-foreground">Recent Scans</h3>
            <a href="/reports" className="text-xs text-accent hover:underline">
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
                    <p className="text-xs font-mono text-foreground">{job.finding_count}</p>
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
