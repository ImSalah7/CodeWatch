"use client";

import { usePathname } from "next/navigation";

const titles: Record<string, string> = {
  "/": "Dashboard",
  "/scan": "New Scan",
  "/results": "Results",
  "/reports": "Reports",
  "/settings": "Settings",
};

export function Header() {
  const pathname = usePathname();
  const title = titles[pathname] || "CodeWatch";

  return (
    <header className="h-[72px] border-b border-border bg-card/50 backdrop-blur-sm flex items-center justify-between px-6 flex-shrink-0 sticky top-0 z-40">
      <div>
        <h1 className="text-lg font-semibold text-foreground">{title}</h1>
        <p className="text-xs text-muted -mt-0.5">CodeWatch SAST Platform</p>
      </div>
    </header>
  );
}
