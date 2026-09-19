import React from "react";
import { useRouter } from "next/router";

/**
 * Lightweight global route progress bar.
 *
 * Gives instant feedback the moment a navigation starts so a slow page never
 * feels unresponsive. The bar creeps toward ~90% while loading and completes
 * on routeChangeComplete. No external dependency; a single fixed div whose
 * width is animated through inline styles.
 */
export function RouteProgress() {
  const router = useRouter();
  const [visible, setVisible] = React.useState(false);
  const [progress, setProgress] = React.useState(0);
  const creepRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const doneRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimers = React.useCallback(() => {
    if (creepRef.current) { clearInterval(creepRef.current); creepRef.current = null; }
    if (doneRef.current) { clearTimeout(doneRef.current); doneRef.current = null; }
  }, []);

  React.useEffect(() => {
    const start = () => {
      clearTimers();
      setVisible(true);
      setProgress(8);
      // Creep toward 90% with a decelerating rate, never reaching 100%.
      creepRef.current = setInterval(() => {
        setProgress(p => {
          if (p >= 90) return p;
          const remaining = 90 - p;
          return p + Math.max(0.5, remaining * 0.08);
        });
      }, 180);
    };

    const done = () => {
      clearTimers();
      setProgress(100);
      doneRef.current = setTimeout(() => {
        setVisible(false);
        // Reset after the fade-out so the next run starts cleanly.
        setTimeout(() => setProgress(0), 220);
      }, 160);
    };

    const onError = () => done();

    router.events.on("routeChangeStart", start);
    router.events.on("routeChangeComplete", done);
    router.events.on("routeChangeError", onError);

    return () => {
      clearTimers();
      router.events.off("routeChangeStart", start);
      router.events.off("routeChangeComplete", done);
      router.events.off("routeChangeError", onError);
    };
  }, [router, clearTimers]);

  if (!visible && progress === 0) return null;

  return (
    <div
      aria-hidden
      className="pointer-events-none fixed left-0 top-0 z-[300] h-[2px] w-full"
      style={{ opacity: visible ? 1 : 0, transition: "opacity 0.2s ease" }}
    >
      <div
        className="h-full bg-gradient-to-r from-violet-500 via-primary to-sky-400 shadow-[0_0_8px_rgba(139,92,246,0.55)]"
        style={{
          width: `${progress}%`,
          transition: progress === 100 ? "width 0.16s ease-out" : "width 0.24s ease-out",
        }}
      />
    </div>
  );
}
