"use client";

import { useState, useCallback } from "react";
import { SeverityBadge } from "@/components/ui/SeverityBadge";

interface SearchResult {
  type: string;
  fingerprint: string;
  title: string;
  rule_id: string;
  severity: string;
  file: string;
  line: number;
  category: string;
  cwe: string;
  scan_id: string;
}

export function SearchClient() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const doSearch = useCallback(async () => {
    const q = query.trim();
    if (q.length < 2) return;
    setLoading(true);
    setSearched(true);
    try {
      const res = await fetch("/api/v1/search?q=" + encodeURIComponent(q));
      const j = await res.json();
      setResults(j.results || []);
      setTotal(j.total || 0);
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") doSearch();
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">Global Search</h1>
      <p className="text-sm text-zinc-400">
        Search across findings, files, rules, CWE, and categories from all scans.
      </p>

      <div className="flex gap-3">
        <input
          className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-white placeholder-zinc-500 text-sm focus:outline-none focus:border-emerald-500"
          placeholder="Search by keyword (min 2 characters)..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button
          onClick={doSearch}
          disabled={loading || query.trim().length < 2}
          className="px-6 py-3 bg-emerald-600 text-white rounded-lg text-sm font-medium hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed transition"
        >
          {loading ? "Searching..." : "Search"}
        </button>
      </div>

      {searched && !loading && (
        <p className="text-sm text-zinc-500">{total} result{total !== 1 ? "s" : ""} found</p>
      )}

      <div className="space-y-2">
        {results.map((r, i) => (
          <div
            key={r.fingerprint + i}
            className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 hover:border-zinc-700 transition"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={r.severity} />
                  <span className="text-xs text-zinc-500 font-mono">{r.rule_id}</span>
                  <span className="text-xs px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{r.category}</span>
                </div>
                <p className="text-sm text-white font-medium truncate">{r.title}</p>
                <p className="text-xs text-zinc-500 mt-1 font-mono">
                  {r.file}:{r.line}
                </p>
                {r.cwe && <p className="text-xs text-zinc-600 mt-0.5">{r.cwe}</p>}
              </div>
              <span className="text-xs text-zinc-600 whitespace-nowrap">scan: {r.scan_id.slice(0, 8)}</span>
            </div>
          </div>
        ))}
        {searched && !loading && results.length === 0 && (
          <p className="text-zinc-500 text-center py-8">No results found for &ldquo;{query}&rdquo;</p>
        )}
      </div>
    </div>
  );
}
