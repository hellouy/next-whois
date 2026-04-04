import { useState, useEffect, useRef } from "react";

export function useScrollDirection() {
  const [isVisible, setIsVisible] = useState(true);
  const lastScrollY = useRef(0);

  useEffect(() => {
    const controlNavbar = (e: Event) => {
      const target = e.target as Element | null;

      // Filter: only react to the window/document or large containers that
      // cover the majority of the viewport (e.g. Radix ScrollArea, full-page
      // divs). Skip small scrollable areas like dropdowns, modals, textareas.
      const isMainScroll =
        !target ||
        target === document.documentElement ||
        target === document.body ||
        target.clientHeight > window.innerHeight * 0.5;

      if (!isMainScroll) return;

      // Read the correct Y position depending on the scroll source.
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

    // capture:true intercepts scroll events before they reach the target,
    // so we catch scrolling inside any element (including Radix ScrollArea)
    // not just window-level scrolling.
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
