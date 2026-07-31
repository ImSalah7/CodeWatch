"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { getStats, getHistory } from "@/lib/api";
import { cn, severityColor, timeAgo } from "@/lib/utils";
import type { Stats, ScanJob } from "@/lib/types";
import {
  BarChart3,
  TrendingUp,
  Activity,
  Globe,
  Layers,
  Shield,
} from "lucide-react";
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
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  Radar,
  CartesianGrid,
} from "recharts";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel px-3 py-2 text-xs">
      <p className="text-foreground font-medium mb-1">{label}</p>
      {payload.map((entry: any, i: number) => (
        <p key={i} style={{ color: entry.color || entry.fill }} className="font-mono">
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
};

export function AnalyticsClient() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getStats().catch(() => null),
      getHistory(30).catch(() => ({ history: [] as ScanJob[], total: 0 })),
    ]).then(([s, h]) => {
      setStats(s);
      setHistory(h.history || []);
      setLoading(false);
    });
  }, []);

  const severityData = stats
    ? SEV_ORDER.map((s) => ({
        subject: s.charAt(0).toUpperCase() + s.slice(1),
        A: stats.severity_totals[s] || 0,
        fullMark: Math.max(...Object.values(stats.severity_totals), 1),
      }))
    : [];

  const sevPieData = stats
    ? SEV_ORDER.map((s) => ({
        name: s.charAt(0).toUpperCase() + s.slice(1),
        value: stats.severity_totals[s] || 0,
        fill: severityColor(s),
      }))
    : [];

  const categoryBarData = stats
    ? Object.entries(stats.category_totals)
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({
          name: name.charAt(0).toUpperCase() + name.slice(1),
          count,
        }))
    : [];

  const trendData = history
    .slice()
    .reverse()
    .map((j, i) => ({
      name: `${i + 1}`,
      findings: j.finding_count,
      target: j.target.split(/[/\\]/).pop() || "",
    }));

  const statusData = stats
    ? [
        { name: "Completed", value: stats.completed_scans, fill: "#22C55E" },
        { name: "Failed", value: stats.failed_scans, fill: "#EF4444" },
      ]
    : [];

  const repoHealth = history.slice(0, 10).map((j) => ({
    name: (j.target.split(/[/\\]/).pop() || "unknown").substring(0, 12),
    findings: j.finding_count,
    risk: j.finding_count > 5 ? "High" : j.finding_count > 2 ? "Medium" : "Low",
  }));

  return (
    <div className="space-y-6 max-w-[1600px]">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-xl font-bold text-foreground">Analytics</h1>
        <p className="text-sm text-muted mt-0.5">
          Deep insights into your security posture
        </p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="card-elevated"
        >
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-foreground">Severity Radar</h3>
          </div>
          {loading ? (
            <div className="h-64 shimmer rounded-lg" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <RadarChart data={severityData}>
                <PolarGrid stroke="#1E293B" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: "#94A3B8", fontSize: 11 }} />
                <Radar
                  name="Findings"
                  dataKey="A"
                  stroke="#00E5FF"
                  fill="#00E5FF"
                  fillOpacity={0.15}
                  strokeWidth={2}
                />
              </RadarChart>
            </ResponsiveContainer>
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="card-elevated"
        >
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-foreground">Scan Trend</h3>
          </div>
          {loading ? (
            <div className="h-64 shimmer rounded-lg" />
          ) : trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3B82F6" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" />
                <XAxis dataKey="name" stroke="#334155" fontSize={11} tickLine={false} />
                <YAxis stroke="#334155" fontSize={11} tickLine={false} width={30} />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="findings"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  fill="url(#trendGrad)"
                  name="Findings"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-sm text-muted">
              No trend data
            </div>
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="card-elevated"
        >
          <div className="flex items-center gap-2 mb-4">
            <Layers className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-foreground">Category Breakdown</h3>
          </div>
          {loading ? (
            <div className="h-64 shimmer rounded-lg" />
          ) : categoryBarData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={categoryBarData}>
                <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" />
                <XAxis dataKey="name" stroke="#334155" fontSize={11} tickLine={false} />
                <YAxis stroke="#334155" fontSize={11} tickLine={false} width={30} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} name="Count" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-sm text-muted">
              No category data
            </div>
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card-elevated"
        >
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-foreground">Severity Distribution</h3>
          </div>
          {loading ? (
            <div className="h-64 shimmer rounded-lg" />
          ) : sevPieData.some((d) => d.value > 0) ? (
            <div className="flex items-center gap-6">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie
                    data={sevPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={3}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {sevPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2.5 flex-1">
                {sevPieData.map((d) => (
                  <div key={d.name}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-sm" style={{ background: d.fill }} />
                        <span className="text-muted">{d.name}</span>
                      </div>
                      <span className="font-mono text-foreground font-medium">{d.value}</span>
                    </div>
                    <div className="h-1 bg-surface-elevated rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${
                            (d.value /
                              Math.max(...sevPieData.map((x) => x.value), 1)) *
                            100
                          }%`,
                          background: d.fill,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-sm text-muted">
              No data
            </div>
          )}
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
        className="card-elevated"
      >
        <div className="flex items-center gap-2 mb-4">
          <Globe className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-semibold text-foreground">Repository Health</h3>
        </div>
        {loading ? (
          <div className="h-48 shimmer rounded-lg" />
        ) : repoHealth.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[11px] text-muted uppercase tracking-wider border-b border-border">
                  <th className="text-left py-2 px-3 font-medium">Repository</th>
                  <th className="text-left py-2 px-3 font-medium">Findings</th>
                  <th className="text-left py-2 px-3 font-medium">Risk Level</th>
                  <th className="text-left py-2 px-3 font-medium">Status</th>
                  <th className="text-left py-2 px-3 font-medium">Scanned</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 8).map((j) => (
                  <tr key={j.job_id} className="border-b border-border/50 table-row">
                    <td className="py-2.5 px-3 font-mono text-foreground truncate max-w-[200px]">
                      {j.target.split(/[/\\]/).pop() || j.target}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-foreground">
                      {j.finding_count}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={cn(
                          "badge text-[10px]",
                          j.finding_count > 5
                            ? "badge-critical"
                            : j.finding_count > 2
                            ? "badge-medium"
                            : "badge-low"
                        )}
                      >
                        {j.finding_count > 5 ? "High" : j.finding_count > 2 ? "Medium" : "Low"}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="flex items-center gap-1.5">
                        <span
                          className={cn(
                            "w-1.5 h-1.5 rounded-full",
                            j.status === "completed" ? "bg-emerald-400" : "bg-red-400"
                          )}
                        />
                        <span className="text-muted capitalize">{j.status}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-muted">{timeAgo(j.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="h-48 flex items-center justify-center text-sm text-muted">
            No scan history
          </div>
        )}
      </motion.div>
    </div>
  );
}
