/**
 * Shared style for every icon button in the top nav (theme, language, bell,
 * user, directory, history, menu). One definition so padding, the 44px touch
 * target, hover colour and corner radius can never drift apart again — the
 * previous per-button classes mixed `pr-0`/missing min-size/no hover colour,
 * which made the icon row uneven and cramped on mobile.
 */
export const NAV_ICON_BTN =
  "p-2 inline-flex items-center justify-center min-h-[44px] min-w-[44px] " +
  "rounded-full text-muted-foreground hover:text-foreground hover:bg-muted/60 " +
  "active:bg-muted/80 transition-colors touch-manipulation";
