"use client";

import { useEffect, useState } from "react";

interface HistoryEntry {
  job_id: string;
  target: string;
  status: string;
  enterprise: boolean;
  started_at: string;
  completed_at: string;
  finding_count: number;
  error: string;
}

export function HistoryClient() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/history?limit=50")
      .then((r) => r.json())
      .then((j) => {
        setHistory(j.history || []);
        setTotal(j.total || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const statusColor = (status: string) => {
    switch (status) {
      case "completed": return "text-emerald-400";
      case "running": return "text-blue-400";
      case "failed": return "text-red-400";
      case "pending": return "text-yellow-400";
      default: return "text-zinc-400";
    }
  };

  const statusDot = (status: string) => {
    switch (status) {
      case "completed": return "bg-emerald-500";
      case "running": return "bg-blue-500";
      case "failed": return "bg-red-500";
      case "pending": return "bg-yellow-500";
      default: return "bg-zinc-500";
    }
  };

  if (loading) return <div className="p-8 text-zinc-400">Loading history...</div>;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Scan History</h1>
        <span className="text-sm text-zinc-500">{total} total scan{total !== 1 ? "s" : ""}</span>
      </div>

      {history.length === 0 && (
        <div className="text-center py-16 text-zinc-500">
          <p className="text-lg mb-2">No scans yet</p>
          <p className="text-sm">Run a scan to see it appear here</p>
        </div>
      )}

      <div className="space-y-2">
        {history.map((entry) => (
          <div
            key={entry.job_id}
            className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:border-zinc-700 transition"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full ${statusDot(entry.status)}`} />
                <span className={`text-sm font-medium ${statusColor(entry.status)}`}>
                  {entry.status.charAt(0).toUpperCase() + entry.status.slice(1)}
                </span>
                <span className="text-sm text-zinc-300 font-mono">{entry.job_id.slice(0, 12)}</span>
                {entry.enterprise && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-400 border border-purple-800">
                    Enterprise
                  </span>
                )}
              </div>
              <span className="text-xs text-zinc-500">
                {entry.finding_count} finding{entry.finding_count !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="mt-2 flex items-center gap-4 text-xs text-zinc-500">
              <span className="truncate max-w-md">{entry.target}</span>
              <span>{entry.started_at ? new Date(entry.started_at).toLocaleString() : ""}</span>
            </div>
            {entry.error && <p className="mt-1 text-xs text-red-400">{entry.error}</p>}
          </div>
        ))}
      </div>
    </div>
  );
}
