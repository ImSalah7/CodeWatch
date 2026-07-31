"use client";

import { Bell, Search, User } from "lucide-react";
import { usePathname } from "next/navigation";

const titles: Record<string, string> = {
  "/": "Dashboard",
  "/scan": "New Scan",
  "/reports": "Reports",
  "/analytics": "Analytics",
  "/settings": "Settings",
};

export function Header() {
  const pathname = usePathname();
  const title = titles[pathname] || "MyScan";

  return (
    <header className="h-[72px] border-b border-border bg-card/50 backdrop-blur-sm flex items-center justify-between px-6 flex-shrink-0 sticky top-0 z-40">
      <div>
        <h1 className="text-lg font-semibold text-foreground">{title}</h1>
        <p className="text-xs text-muted -mt-0.5">MyScan Enterprise SAST</p>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative hidden md:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            type="text"
            placeholder="Search findings, rules..."
            className="input pl-9 w-64 h-9 text-sm"
          />
        </div>

        <button className="relative p-2 rounded-lg hover:bg-surface-elevated transition-colors text-muted hover:text-foreground">
          <Bell className="w-4.5 h-4.5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-accent rounded-full" />
        </button>

        <div className="w-8 h-8 rounded-full bg-surface-elevated border border-border flex items-center justify-center">
          <User className="w-4 h-4 text-muted" />
        </div>
      </div>
    </header>
  );
}
