import { useState, useEffect, useRef } from "react";

/**
 * Returns true while the user is at the top or has scrolled UP.
 * Returns false when the user scrolls DOWN past a small threshold.
 *
 * Pass `pathname` (from Next.js router) so the hook resets to visible
 * whenever the user navigates to a new page.
 */
export function useScrollDirection(pathname?: string) {
  const [isVisible, setIsVisible] = useState(true);
  const lastScrollY = useRef(0);

  // Reset to visible whenever the route changes so the nav is never
  // stuck hidden when landing on a fresh page.
  useEffect(() => {
    setIsVisible(true);
    lastScrollY.current = 0;
  }, [pathname]);

  useEffect(() => {
    const controlNavbar = (e: Event) => {
      const target = e.target as Element | null;

      // Ignore scroll events from small containers (dropdowns, textareas …).
      // Only react to the window or large viewports that cover most of the screen
      // (e.g. Radix ScrollArea used on about / faq / terms / etc.).
      const isMainScroll =
        !target ||
        target === document.documentElement ||
        target === document.body ||
        target.clientHeight > window.innerHeight * 0.5;

      if (!isMainScroll) return;

      const currentScrollY =
        target === document.documentElement ||
        target === document.body ||
        !target
          ? window.scrollY
          : (target as Element).scrollTop;

      if (currentScrollY < lastScrollY.current || currentScrollY < 10) {
        setIsVisible(true);
      } else if (currentScrollY > lastScrollY.current && currentScrollY > 10) {
        setIsVisible(false);
      }

      lastScrollY.current = currentScrollY;
    };

    window.addEventListener("scroll", controlNavbar, {
      capture: true,
      passive: true,
    });

    return () => {
      window.removeEventListener("scroll", controlNavbar, { capture: true });
    };
  }, []);

  return isVisible;
}
