"use client";

import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";
import { motion } from "framer-motion";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: { value: number; positive: boolean };
  accentColor?: string;
  index?: number;
}

export function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  accentColor = "var(--color-accent)",
  index = 0,
}: MetricCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.06, duration: 0.35, ease: "easeOut" }}
      className="metric-card group"
      style={{ "--accent-color": accentColor } as React.CSSProperties}
    >
      <div className="flex items-start justify-between mb-3">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ background: `${accentColor}12` }}
        >
          <Icon className="w-4.5 h-4.5" style={{ color: accentColor }} />
        </div>
        {trend && (
          <span
            className={cn(
              "text-xs font-semibold px-1.5 py-0.5 rounded",
              trend.positive ? "text-emerald-400 bg-emerald-500/10" : "text-red-400 bg-red-500/10"
            )}
          >
            {trend.positive ? "+" : ""}{trend.value}%
          </span>
        )}
      </div>
      <div className="text-2xl font-bold text-foreground tracking-tight font-[family-name:var(--font-geist-mono)]">
        {value}
      </div>
      <div className="text-xs text-muted mt-1 font-medium">{title}</div>
      {subtitle && (
        <div className="text-[11px] text-muted/60 mt-0.5">{subtitle}</div>
      )}
    </motion.div>
  );
}
