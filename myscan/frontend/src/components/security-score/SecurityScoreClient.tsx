"use client";

import { useEffect, useState } from "react";
import { MetricCard } from "@/components/ui/MetricCard";
import { AlertTriangle, AlertOctagon, KeyRound, FileSearch, ScanSearch } from "lucide-react";

interface ScoreData {
  score: number;
  grade: string;
  trend: { date: string; score: number }[];
  components: {
    critical_findings: number;
    high_findings: number;
    secrets: number;
    total_findings: number;
    scans_completed: number;
  };
}

export function SecurityScoreClient() {
  const [data, setData] = useState<ScoreData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/v1/security-score")
      .then((r) => r.json())
      .then((j) => {
        setData(j);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="p-8 text-zinc-400">Loading security score...</div>;
  if (error) return <div className="p-8 text-red-400">{error}</div>;

  const gradeColor = (grade: string) => {
    if (grade === "A+" || grade === "A") return "text-emerald-400";
    if (grade === "B") return "text-blue-400";
    if (grade === "C") return "text-yellow-400";
    if (grade === "D") return "text-orange-400";
    return "text-red-400";
  };

  const scorePercent = data?.score ?? 0;
  const grade = data?.grade ?? "N/A";
  const components = data?.components ?? { critical_findings: 0, high_findings: 0, secrets: 0, total_findings: 0, scans_completed: 0 };

  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (scorePercent / 100) * circumference;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">Security Score</h1>

      <div className="flex flex-col items-center py-8">
        <div className="relative w-48 h-48">
          <svg className="transform -rotate-90 w-48 h-48" viewBox="0 0 160 160">
            <circle cx="80" cy="80" r={radius} fill="none" stroke="#27272a" strokeWidth="12" />
            <circle
              cx="80" cy="80" r={radius} fill="none"
              stroke="currentColor" strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              className={
                scorePercent >= 90 ? "text-emerald-500" :
                scorePercent >= 70 ? "text-blue-500" :
                scorePercent >= 50 ? "text-yellow-500" :
                scorePercent >= 30 ? "text-orange-500" : "text-red-500"
              }
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-5xl font-bold ${gradeColor(grade)}`}>{grade}</span>
            <span className="text-2xl text-zinc-400">{scorePercent}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard title="Critical Findings" value={components.critical_findings} icon={AlertOctagon} accentColor="#ef4444" />
        <MetricCard title="High Findings" value={components.high_findings} icon={AlertTriangle} accentColor="#f97316" />
        <MetricCard title="Secrets" value={components.secrets} icon={KeyRound} accentColor="#eab308" />
        <MetricCard title="Total Findings" value={components.total_findings} icon={FileSearch} accentColor="#3b82f6" />
        <MetricCard title="Scans Completed" value={components.scans_completed} icon={ScanSearch} accentColor="#71717a" />
      </div>

      {data?.trend && data.trend.length > 1 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">Score Trend</h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            {data.trend.map((t, i) => (
              <div key={i} className="flex items-center gap-4 text-sm py-1">
                <span className="text-zinc-500 w-40">{new Date(t.date).toLocaleDateString()}</span>
                <div className="flex-1 bg-zinc-800 rounded-full h-2">
                  <div
                    className="h-2 rounded-full bg-emerald-500 transition-all"
                    style={{ width: `${t.score}%` }}
                  />
                </div>
                <span className="text-zinc-400 w-8 text-right">{t.score}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
