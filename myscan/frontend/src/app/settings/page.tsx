"use client";

import { useEffect, useState } from "react";
import { Shield, Server, Key, Save, Loader2, CheckCircle2 } from "lucide-react";
import { motion } from "framer-motion";
import { getSettings, saveSettings } from "@/lib/api";
import type { ScanSettings } from "@/lib/api";

interface SettingItem {
  label: string;
  description: string;
  key: keyof ScanSettings;
  type: "number" | "toggle" | "select" | "text";
  min?: number;
  max?: number;
  options?: string[];
}

interface SettingSection {
  title: string;
  icon: typeof Server;
  items: SettingItem[];
}

const sections: SettingSection[] = [
  {
    title: "Engine Configuration",
    icon: Server,
    items: [
      { label: "Default Thread Count", description: "Worker threads used for scanning", key: "threads", type: "number", min: 1, max: 16 },
      { label: "Minimum Confidence", description: "Minimum confidence to report a finding (0-1)", key: "min_confidence", type: "number", min: 0, max: 1, },
      { label: "Enterprise Mode", description: "Enable AST, data flow, taint tracking", key: "enterprise_mode", type: "toggle" },
      { label: "Secret Display", description: "How secrets appear in reports", key: "secret_display", type: "select", options: ["smart", "masked", "full"] },
      { label: "Max File Size (KB)", description: "Skip files larger than this", key: "max_file_size_kb", type: "number", min: 1, max: 10240 },
      { label: "Include Tests", description: "Scan test and spec directories", key: "include_tests", type: "toggle" },
      { label: "Include Docs", description: "Scan documentation directories", key: "include_docs", type: "toggle" },
      { label: "Include Examples", description: "Scan example directories", key: "include_examples", type: "toggle" },
      { label: "Max History", description: "Number of scans kept in memory", key: "max_history", type: "number", min: 5, max: 500 },
    ],
  },
  {
    title: "API & Integrations",
    icon: Key,
    items: [
      { label: "Default Report Format", description: "Format for generated reports", key: "report_format", type: "select", options: ["markdown", "json", "html", "csv", "sarif"] },
    ],
  },
];

export default function SettingsPage() {
  const [settings, setSettings] = useState<ScanSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    getSettings()
      .then((res) => setSettings(res.settings))
      .catch((e) => setError(e.message || "Failed to load settings"));
  }, []);

  const update = (key: keyof ScanSettings, value: string | number | boolean) => {
    setSettings((prev) => {
      if (!prev) return prev;
      if (key === "min_confidence") {
        return { ...prev, min_confidence: Math.min(Math.max(Number(value), 0), 1) };
      }
      return { ...prev, [key]: value as never };
    });
    setSaved(false);
  };

  const save = async () => {
    if (!settings) return;
    setSaving(true);
    setError("");
    try {
      await saveSettings(settings);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return (
      <div className="flex items-center justify-center py-24 text-muted">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading settings...
      </div>
    );
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-center justify-between">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <h1 className="text-xl font-bold text-foreground">Settings</h1>
          <p className="text-sm text-muted mt-0.5">
            Configure your MyScan Enterprise platform
          </p>
        </motion.div>
        <button
          onClick={save}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-accent text-white text-xs font-medium hover:opacity-90 transition-all disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
          {saving ? "Saving..." : "Save Settings"}
        </button>
      </div>

      {saved && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
          <CheckCircle2 className="w-4 h-4" />
          Settings saved successfully
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
          {error}
        </div>
      )}

      {sections.map((section, si) => (
        <motion.div
          key={section.title}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: si * 0.08 }}
          className="card-elevated"
        >
          <div className="flex items-center gap-2 mb-4">
            <section.icon className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-foreground">{section.title}</h3>
          </div>
          <div className="space-y-3">
            {section.items.map((item) => {
              const value = settings[item.key] as string | number | boolean;
              return (
                <div
                  key={item.key}
                  className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                >
                  <div>
                    <span className="text-xs text-foreground">{item.label}</span>
                    <p className="text-[11px] text-muted/70">{item.description}</p>
                  </div>
                  {item.type === "toggle" ? (
                    <button
                      onClick={() => update(item.key, !value)}
                      className={`w-9 h-5 rounded-full relative cursor-pointer transition-colors ${
                        value ? "bg-accent" : "bg-surface-elevated"
                      }`}
                    >
                      <div
                        className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${
                          value ? "left-[18px]" : "left-0.5"
                        }`}
                      />
                    </button>
                  ) : item.type === "select" ? (
                    <select
                      value={String(value)}
                      onChange={(e) => update(item.key, e.target.value)}
                      className="input h-8 w-32 text-xs bg-surface text-right"
                    >
                      {(item.options || []).map((o) => (
                        <option key={o} value={o}>{o}</option>
                      ))}
                    </select>
                  ) : item.type === "number" ? (
                    <input
                      type="number"
                      value={Number(value)}
                      min={item.min}
                      max={item.max}
                      step={item.key === "min_confidence" ? 0.05 : 1}
                      onChange={(e) => update(item.key, Number(e.target.value))}
                      className="input h-8 w-24 text-xs bg-surface text-right font-mono"
                    />
                  ) : (
                    <input
                      value={String(value)}
                      onChange={(e) => update(item.key, e.target.value)}
                      className="input h-8 w-48 text-xs bg-surface text-right font-mono"
                    />
                  )}
                </div>
              );
            })}
          </div>
        </motion.div>
      ))}

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="card-elevated"
      >
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4 text-accent" />
          <h3 className="text-sm font-semibold text-foreground">System Info</h3>
        </div>
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: "Version", value: "3.0.1" },
            { label: "Engine", value: "Enterprise SAST" },
            { label: "Rules", value: "57 built-in" },
            { label: "Languages", value: "Python, JS, TS, Go" },
          ].map((item) => (
            <div key={item.label} className="p-3 rounded-lg bg-surface border border-border">
              <p className="text-[11px] text-muted mb-0.5">{item.label}</p>
              <p className="text-xs font-mono text-foreground">{item.value}</p>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
