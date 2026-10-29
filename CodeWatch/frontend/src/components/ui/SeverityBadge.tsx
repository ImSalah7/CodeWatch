"use client";

import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: string;
  size?: "sm" | "md";
}

const severityConfig: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: "badge-critical", text: "text-red-400", dot: "bg-red-400" },
  high: { bg: "badge-high", text: "text-orange-400", dot: "bg-orange-400" },
  medium: { bg: "badge-medium", text: "text-amber-400", dot: "bg-amber-400" },
  low: { bg: "badge-low", text: "text-blue-400", dot: "bg-blue-400" },
  info: { bg: "badge-info", text: "text-slate-400", dot: "bg-slate-400" },
};

export function SeverityBadge({ severity, size = "sm" }: SeverityBadgeProps) {
  const config = severityConfig[severity?.toLowerCase()] || severityConfig.info;
  return (
    <span
      className={cn(
        "badge border",
        config.bg,
        size === "md" && "text-xs px-2.5 py-1"
      )}
    >
      <span className={cn("severity-dot", config.dot)} />
      {severity?.charAt(0).toUpperCase() + severity?.slice(1)}
    </span>
  );
}
