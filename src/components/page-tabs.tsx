import React from "react";
import { useRouter } from "next/router";
import { cn } from "@/lib/utils";

export type PageTab = {
  href: string;
  label: string;
  icon?: React.ElementType;
};

export function PageTabs({ tabs }: { tabs: PageTab[] }) {
  const router = useRouter();
  const current = router.pathname;

  function isActive(href: string) {
    return current === href || current.endsWith(href);
  }

  return (
    <div className="flex items-center gap-1 mb-5 flex-wrap">
      {tabs.map(({ href, label, icon: Icon }) => {
        const active = isActive(href);
        return (
          <button
            key={href}
            type="button"
            onClick={() => router.push(href, undefined, { locale: false })}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold transition-all",
              active
                ? "bg-primary text-primary-foreground shadow-sm"
                : "bg-muted/70 text-muted-foreground hover:text-foreground hover:bg-muted"
            )}
          >
            {Icon && <Icon className="w-3 h-3 shrink-0" />}
            {label}
          </button>
        );
      })}
    </div>
  );
}
