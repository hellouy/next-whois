import { useState, useEffect, useRef } from "react";

export function useScrollDirection() {
  const [isVisible, setIsVisible] = useState(true);
  // Use a ref so the scroll handler always reads the latest value without
  // needing to be re-registered on every scroll (which caused stale-closure
  // bugs and listener stacking on fast mobile/iOS momentum scrolling).
  const lastScrollY = useRef(0);

  useEffect(() => {
    const controlNavbar = () => {
      const currentScrollY = window.scrollY;

      if (currentScrollY < lastScrollY.current || currentScrollY < 10) {
        setIsVisible(true);
      } else if (currentScrollY > lastScrollY.current && currentScrollY > 10) {
        setIsVisible(false);
      }

      lastScrollY.current = currentScrollY;
    };

    // passive:true tells the browser this handler never calls preventDefault,
    // allowing it to optimise scroll performance (especially on mobile).
    window.addEventListener("scroll", controlNavbar, { passive: true });

    return () => {
      window.removeEventListener("scroll", controlNavbar);
    };
  }, []); // register once — the ref keeps lastScrollY current

  return isVisible;
}
