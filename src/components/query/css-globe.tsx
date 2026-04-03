import React from "react";
import { GLOBE_COUNTRY_COORDS } from "@/data/query-page/globe-coords";

export function CssGlobe({ countryCode }: { countryCode?: string }) {
  const [labelVisible, setLabelVisible] = React.useState(false);

  const code = countryCode ? countryCode.toUpperCase().trim() : null;
  const coords = code ? GLOBE_COUNTRY_COORDS[code] : null;

  let svgMarginEm: number | undefined;
  let dotY = 60;

  if (coords) {
    const [lat, lng] = coords;
    const xFirst = (lng + 180) / 360 * 240;
    const marginPx = xFirst >= 60 ? -(xFirst - 60) : -(xFirst + 180);
    svgMarginEm = marginPx / 120;
    dotY = (90 - lat) / 180 * 120;
    dotY = Math.max(10, Math.min(110, dotY));
  }

  return (
    <div className="relative" style={{ width: 120, height: 120 }}>
      <svg aria-hidden="true"
        style={{ position: "absolute", width: 0, height: 0, overflow: "hidden" }}
        xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink">
        <defs>
          <symbol id="nw-icon-world" viewBox="0 0 216 100">
            <g fillRule="nonzero">
              <path d="M48 94l-3-4-2-14c0-3-1-5-3-8-4-5-6-9-4-11l1-4 1-3c2-1 9 0 11 1l3 2 2 3 1 2 8 2c1 1 2 2 0 7-1 5-2 7-4 7l-2 3-2 4-2 3-2 1c-2 2-2 9 0 10v1l-3-2zM188 90l3-2h1l-4 2zM176 87h2l-1 1-1-1zM195 86l3-2-2 2h-1zM175 83l-1-2-2-1-6 1c-5 1-5 1-5-2l1-4 2-2 4-3c5-4 9-5 9-3 0 3 3 3 4 1s1-2 1 0l3 4c2 4 1 6-2 10-4 3-7 4-8 1zM100 80c-2-4-4-11-3-14l-1-6c-1-1-2-3-1-4 0-2-4-3-9-3-4 0-5 0-7-3-1-2-2-4-1-7l3-6 3-3c1-2 10-4 11-2l6 3 5-1c3 1 4 0 5-1s-1-2-2-2l-4-1c0-1 3-3 6-2 3 0 3 0 2-2-2-2-6-2-7 0l-2 2-1 2-3-2-3-3c-1 0-1 1 1 2l1 2-2-1c-4-3-6-2-8 1-2 2-4 3-5 1-1-1 0-4 2-4l2-2 1-2 3-2 3-2 2 1c3 0 7-3 5-4l-1-3h-1l-1 3-2 2h-1l-2-1c-2-1-2-1 1-4 5-4 6-4 11-3 4 1 4 1 2 2v1l3-1 6-1c5 0 6-1 5-2l2 1c1 2 2 2 2 1-2-4 12-7 14-4l11 1 29 3 1 2-3 3c-2 0-2 0-1 1l1 3h-2c-1-1-2-3-1-4h-4l-6 2c-1 1-1 1 2 2 3 2 4 6 1 8v3c1 3 0 3-3 0s-4-1-2 3c3 4 3 7-2 8-5 2-4 1-2 5 2 3 0 5-3 4l-2-1-2-2-1-1-1-1-2-2c-1-2-1-2-4 0-2 1-3 4-3 5-1 3-1 3-3 1l-2-4c0-2-1-3-2-3l-1-1-4-2-6-1-4-2c-1 1 3 4 5 4h2c1 1 0 2-1 4-3 2-7 4-8 3l-7-10 5 10c2 2 3 3 5 2 3 0 2 1-2 7-4 4-4 5-4 8 1 3 1 4-1 6l-2 3c0 2-6 9-8 9l-3-2zm22-51l-2-3-1-1v-1c-2 0-2 2-1 4 2 3 4 4 4 1z" />
              <path d="M117 75c-1-2 0-6 2-7h2l-2 5c0 2-1 3-2 1zM186 64h-3c-2 0-6-3-5-5 1-1 6 1 7 3l2 3-2-1zM160 62h2c1 1 0 1-1 1l-1-1zM154 57l-1-2c2 2 3 1 2-2l-2-3 2 2 1 4 1 3v2l-3-4zM161 59c-1-1-1-2 1-4 3-3 4-3 4 0 0 4-2 6-5 4zM167 59l1-1 1 1-1 1-1-1zM176 59l1-1v2l-1-1zM141 52l1-1v2l-1-1zM170 52l1-1v2l-1-1zM32 50c-1-2-4-3-6-4-4-1-5-3-7-6l-3-5-2-2c-1-3-1-6 2-9 1-1 2-3 1-5 0-4-3-5-8-4H4l2-2 1-1 1-1 2-1c1-2 7-2 23-1 12 1 12 1 12-1h1c1 1 2 2 3 1l1 1-3 1c-2 0-8 4-8 5l2 1 2 3 4-3c3-4 4-4 5-3l3 1 1 2 1 2c3 0-1 2-4 2-2 0-2 0-2 2 1 1 0 2-2 2-4 1-12 9-12 12 0 2 0 2-1 1 0-2-2-3-6-2-3 0-4 1-4 3-2 4 0 6 3 4 3-1 3-1 2 1s-1 2 1 2l1 2 1 3 1 1-3-2zm8-24l1-1c0-1-4-3-5-2l1 1v2c-1 1-1 1 0 0h3zM167 47v-3l1 2c1 2 0 3-1 1z" />
              <path d="M41 43h2l-1 1-1-1zM37 42v-1l2 1h-2zM16 38l1-1v2l-1-1zM172 32l2-3h1c1 2 0 4-3 4v-1zM173 26h2l-1 1-1-1zM56 22h2l-2 1v-1zM87 19l1-2 1 3-1 1-1-2zM85 19l1-1v1l-1 1v-1zM64 12l1-3c2 0-1-4-3-4s-2 0 0-1V3l-6 2c-3 1-3 1-2-1 2-1 4-2 15-2h14c0 2-6 7-10 9l-5 2-2 1-2-2zM53 12l1-1c2 0-1-3-3-3-2-1-1-1 1-1l4 2c2 1 2 1 1 3-2 1-4 2-4 0zM80 12l1-1 1 1-1 1-1-1zM36 8h-2V7c1-1 7 0 7 1h-5zM116 7l1-1v1l-1 1V7zM50 5h2l-1 1-1-1zM97 5l2-1c0-1 1-1 0 0l-2 1z" />
            </g>
          </symbol>
          <symbol id="nw-icon-repeated-world" viewBox="0 0 432 100">
            <use href="#nw-icon-world" x="0" />
            <use href="#nw-icon-world" x="216" />
          </symbol>
        </defs>
      </svg>
      <style>{`
        @keyframes nw-world-scroll {
          from { margin-left: -2.75em; }
          to   { margin-left: -0.75em; }
        }
        @keyframes nw-dot-ping {
          0%   { transform: translate(-50%,-50%) scale(1); opacity: 0.8; }
          70%  { transform: translate(-50%,-50%) scale(2.6); opacity: 0; }
          100% { transform: translate(-50%,-50%) scale(2.6); opacity: 0; }
        }
        @keyframes nw-dot-pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(56,189,248,0.6); }
          50%       { box-shadow: 0 0 0 5px rgba(56,189,248,0); }
        }
        .nw-globe-wrap {
          width: 120px; height: 120px; font-size: 120px;
          display: block; border-radius: 50%; overflow: hidden;
          white-space: nowrap; box-sizing: border-box;
          border: 2px solid currentColor;
        }
        .nw-globe-wrap svg {
          width: 4em; height: 1em; margin-top: -0.05em;
          display: inline; fill: currentColor;
        }
        .nw-globe-wrap svg.scrolling { animation: nw-world-scroll 4s linear infinite; }
        .nw-dot-ring {
          position: absolute; border-radius: 50%;
          background: rgba(56,189,248,0.5);
          animation: nw-dot-ping 1.8s ease-out infinite;
          width: 14px; height: 14px;
          pointer-events: none;
        }
        .nw-dot-core {
          position: absolute; border-radius: 50%;
          background: #38bdf8; border: 2px solid #fff;
          width: 9px; height: 9px;
          box-shadow: 0 0 6px 2px rgba(56,189,248,0.7);
          animation: nw-dot-pulse 1.8s ease-in-out infinite;
          cursor: pointer;
          transform: translate(-50%, -50%);
        }
      `}</style>

      <span className="nw-globe-wrap text-foreground/70">
        <svg
          className={coords ? undefined : "scrolling"}
          style={coords ? { marginLeft: `${svgMarginEm}em` } : undefined}
        >
          <use href="#nw-icon-repeated-world" />
        </svg>
      </span>

      {coords && (
        <>
          <span className="nw-dot-ring" style={{ left: 60, top: dotY, transform: "translate(-50%,-50%)" }} />
          <button
            className="nw-dot-core"
            style={{ left: 60, top: dotY }}
            title={coords[2]}
            onClick={() => setLabelVisible(v => !v)}
          />
          {labelVisible && (
            <div
              className="absolute z-20 left-1/2 -translate-x-1/2 pointer-events-none"
              style={{ top: Math.min(dotY + 10, 86) }}
            >
              <div className="bg-black/80 text-white text-[10px] font-semibold px-2 py-0.5 rounded-full whitespace-nowrap backdrop-blur-sm shadow-lg">
                {code} · {coords[2]}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
