import React from "react";

export function QueryProgressBar({ loading, refreshing }: { loading: boolean; refreshing?: boolean }) {
  const [width, setWidth] = React.useState(0);
  const [visible, setVisible] = React.useState(false);
  const timerRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const doneRef  = React.useRef(false);

  React.useEffect(() => {
    if (loading) {
      doneRef.current = false;
      setWidth(0);
      setVisible(true);
      let w = 0;
      timerRef.current = setInterval(() => {
        if (doneRef.current) return;
        w += w < 40 ? 12 : w < 65 ? 4 : w < 82 ? 1 : 0;
        if (w > 85) w = 85;
        setWidth(w);
      }, 80);
    } else if (refreshing) {
      doneRef.current = false;
      setWidth(90);
      setVisible(true);
      let w = 90;
      let direction = 1;
      timerRef.current = setInterval(() => {
        if (doneRef.current) return;
        w += direction * 0.5;
        if (w >= 95) direction = -1;
        if (w <= 88) direction = 1;
        setWidth(w);
      }, 120);
    } else {
      doneRef.current = true;
      if (timerRef.current) clearInterval(timerRef.current);
      setWidth(100);
      const t = setTimeout(() => setVisible(false), 400);
      return () => clearTimeout(t);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [loading, refreshing]);

  if (!visible) return null;
  return (
    <div className="absolute top-0 left-0 right-0 h-[2px] overflow-hidden rounded-t z-20 pointer-events-none">
      <div
        className={`h-full transition-all ${refreshing && !loading ? "bg-primary/40" : "bg-primary/70"}`}
        style={{
          width: `${width}%`,
          transitionDuration: width === 100 ? "200ms" : refreshing ? "500ms" : "120ms",
          transitionTimingFunction: width === 100 ? "ease-out" : "linear",
        }}
      />
    </div>
  );
}
