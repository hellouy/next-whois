import React from "react";

export function QueryProgressBar({ loading, refreshing }: { loading: boolean; refreshing?: boolean }) {
  const [width, setWidth] = React.useState(0);
  const [visible, setVisible] = React.useState(false);
  const [isDone, setIsDone] = React.useState(false);
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const rafRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (rafRef.current) cancelAnimationFrame(rafRef.current);

    if (loading) {
      setIsDone(false);
      setVisible(true);
      // Reset to 0 first (no transition), then in the next paint jump to 18%
      // so the CSS transition starts from a visible position.
      setWidth(0);
      rafRef.current = requestAnimationFrame(() => {
        rafRef.current = requestAnimationFrame(() => {
          setWidth(78);
        });
      });
    } else if (refreshing) {
      setIsDone(false);
      setVisible(true);
      setWidth(90);
    } else {
      // Done: snap to 100% with fast transition, then fade out
      setIsDone(true);
      setWidth(100);
      timerRef.current = setTimeout(() => setVisible(false), 480);
    }

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [loading, refreshing]);

  if (!visible) return null;

  return (
    <div className="absolute top-0 left-0 right-0 h-[2px] overflow-hidden rounded-t z-20 pointer-events-none">
      <div
        className={`h-full ${refreshing && !loading ? "bg-primary/40" : "bg-primary/70"}`}
        style={{
          width: `${width}%`,
          transition: isDone
            ? "width 0.22s ease-out, opacity 0.25s ease"
            : width === 0
            ? "none"
            : "width 9s cubic-bezier(0.02, 0.6, 0.18, 1)",
        }}
      />
    </div>
  );
}
