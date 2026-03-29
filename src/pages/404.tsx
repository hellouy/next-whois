import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence, useAnimationControls } from "framer-motion";
import { useRouter } from "next/router";
import Link from "next/link";
import {
  RiGhostSmileLine,
  RiArrowLeftLine,
  RiSearchLine,
  RiSignalWifiErrorLine,
  RiGlobalLine,
  RiLightbulbFlashLine,
} from "@remixicon/react";
import { toSearchURI } from "@/lib/utils";
import { useTranslation } from "@/lib/i18n";

const FUN_FACTS = [
  "The first 404 error was served at CERN in 1992 — from Room 404.",
  "NXDOMAIN stands for Non-Existent Domain — the DNS equivalent of a ghost town.",
  "There are over 350 million registered domain names worldwide.",
  "The oldest active domain, symbolics.com, was registered on March 15, 1985.",
  ".com has been the most popular TLD since 1985 — and still holds the crown.",
  "A DNS lookup typically completes in under 50ms. This 404 took even less.",
  "ICANN manages 1,500+ top-level domains. Yours just isn't one of them.",
  "The root DNS has 13 logical servers, distributed across 1,500+ physical locations.",
  "TTL: Time To Live — how long a DNS record is cached. This page: 0 seconds.",
  "Over 100,000 new domains are registered every single day.",
];

function RadarAnimation() {
  return (
    <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          className="absolute rounded-full border border-muted-foreground/20"
          style={{ width: i * 38, height: i * 38 }}
          animate={{ scale: [1, 1.18, 1], opacity: [0.5, 0.08, 0.5] }}
          transition={{
            duration: 2.8,
            repeat: Infinity,
            delay: i * 0.55,
            ease: "easeInOut",
          }}
        />
      ))}
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 flex items-center justify-center"
      >
        <div
          className="absolute top-1/2 left-1/2 w-[50%] h-px origin-left"
          style={{
            background:
              "linear-gradient(to right, transparent, hsl(var(--primary)/0.7))",
            transform: "translateY(-50%)",
          }}
        />
      </motion.div>
      <motion.div
        animate={{ scale: [1, 1.12, 1], opacity: [0.6, 1, 0.6] }}
        transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
      >
        <RiGhostSmileLine className="w-9 h-9 text-muted-foreground/50" />
      </motion.div>
    </div>
  );
}

function GlitchNumber() {
  const controls = useAnimationControls();

  useEffect(() => {
    let mounted = true;
    async function glitchLoop() {
      while (mounted) {
        await new Promise((r) => setTimeout(r, 3500 + Math.random() * 2500));
        if (!mounted) break;
        for (let i = 0; i < 3; i++) {
          await controls.start({
            x: [0, -3, 3, -2, 2, 0],
            skewX: [0, -2, 2, -1, 1, 0],
            opacity: [1, 0.7, 1, 0.8, 1],
            transition: { duration: 0.18, ease: "easeInOut" },
          });
          await new Promise((r) => setTimeout(r, 60));
        }
      }
    }
    glitchLoop();
    return () => {
      mounted = false;
    };
  }, [controls]);

  return (
    <div className="relative select-none leading-none">
      <motion.div
        animate={controls}
        className="text-[5.5rem] sm:text-[7rem] font-black tracking-tighter text-muted-foreground/[0.12] leading-none"
        style={{ fontVariantNumeric: "tabular-nums" }}
      >
        404
      </motion.div>
      <motion.div
        animate={controls}
        className="absolute inset-0 text-[5.5rem] sm:text-[7rem] font-black tracking-tighter leading-none"
        style={{
          WebkitTextStroke: "1px hsl(var(--primary)/0.15)",
          color: "transparent",
          fontVariantNumeric: "tabular-nums",
          mixBlendMode: "screen",
        }}
      >
        404
      </motion.div>
    </div>
  );
}

function TerminalLine({
  text,
  highlight,
  dim,
  accent,
  index,
}: {
  text: string;
  highlight?: boolean;
  dim?: boolean;
  accent?: boolean;
  index: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25, delay: 0.05 + index * 0.04 }}
      className={[
        "font-mono text-[11px] sm:text-xs leading-relaxed whitespace-pre",
        highlight
          ? "text-red-400 font-semibold"
          : accent
            ? "text-violet-400 font-medium"
            : dim
              ? "text-muted-foreground/35"
              : "text-muted-foreground/65",
      ].join(" ")}
    >
      {text}
    </motion.div>
  );
}

const WHOIS_FIELDS = [
  { label: "Status", getValue: () => "NXDOMAIN", error: true },
  { label: "TTL", getValue: () => "0 sec", dim: true },
  { label: "Query Time", getValue: () => "404 ms", dim: true },
];

export default function NotFoundPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [showTerminal, setShowTerminal] = useState(false);
  const [visibleLines, setVisibleLines] = useState(0);
  const [terminalDone, setTerminalDone] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const [rawPath, setRawPath] = useState("");
  // whenDate must start as a fixed empty string so SSR and client first-render
  // produce identical HTML.  We fill it in via useEffect (client-only).
  const [whenDate, setWhenDate] = useState("");
  // randomFact likewise: start with a fixed entry so SSR matches client.
  const [randomFact, setRandomFact] = useState(FUN_FACTS[0]);

  useEffect(() => {
    setRawPath(window.location.pathname.replace(/^\//, "") || "");
    setWhenDate(new Date().toUTCString());
    setRandomFact(FUN_FACTS[Math.floor(Math.random() * FUN_FACTS.length)]);
  }, []);

  const looksLikeDomain = rawPath.includes(".");

  const terminalLines = useMemo(() => {
    const p = rawPath || "unknown";
    return [
      { text: `; <<>> DiG 9.18 <<>> ${p}`, delay: 0 },
      {
        text: `;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 404`,
        delay: 350,
        highlight: true,
      },
      { text: ";; flags: qr rd ra; QUERY: 1, ANSWER: 0", delay: 700 },
      { text: ";; QUESTION SECTION:", delay: 950 },
      { text: `;${p}.   IN  A`, delay: 1100, accent: true },
      { text: ";; ANSWER SECTION:", delay: 1400 },
      { text: ";; (empty — nothing exists here)", delay: 1600, dim: true },
      { text: ";; Query time: 404 msec", delay: 1900 },
      { text: ";; SERVER: 9.9.9.9#53 (Quad9)", delay: 2100 },
      { text: `;; WHEN: ${whenDate}`, delay: 2350 },
    ];
  }, [rawPath, whenDate]);

  useEffect(() => {
    if (looksLikeDomain && rawPath) {
      setQuery(rawPath);
      setTimeout(() => inputRef.current?.focus(), 600);
    }
  }, [looksLikeDomain, rawPath]);

  useEffect(() => {
    const t1 = setTimeout(() => setShowTerminal(true), 500);
    return () => clearTimeout(t1);
  }, []);

  useEffect(() => {
    if (!showTerminal) return;
    const timers: ReturnType<typeof setTimeout>[] = [];
    terminalLines.forEach((line, i) => {
      timers.push(
        setTimeout(
          () => setVisibleLines((v) => Math.max(v, i + 1)),
          line.delay,
        ),
      );
    });
    timers.push(
      setTimeout(
        () => setTerminalDone(true),
        (terminalLines.at(-1)?.delay ?? 2000) + 400,
      ),
    );
    return () => timers.forEach(clearTimeout);
  }, [showTerminal, terminalLines]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) router.push(toSearchURI(query.trim()));
  };

  const displayPath = rawPath.length > 40 ? rawPath.slice(0, 40) + "…" : rawPath;

  return (
    <div className="w-full min-h-[calc(100vh-4rem)] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-2xl space-y-4">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
          className="glass-panel border border-border rounded-xl overflow-hidden"
        >
          <div className="border-b border-border/60 bg-muted/30 px-5 py-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <RiGlobalLine className="w-4 h-4 text-muted-foreground shrink-0" />
              <span className="text-xs font-mono text-muted-foreground truncate">
                {displayPath || "—"}
              </span>
            </div>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/30 text-red-500 text-[11px] font-semibold shrink-0">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
              NXDOMAIN
            </span>
          </div>

          <div className="p-6 sm:p-8">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6">
              <RadarAnimation />

              <div className="flex-1 text-center sm:text-left">
                <motion.div
                  initial={{ opacity: 0, scale: 0.93 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.4, delay: 0.15 }}
                >
                  <GlitchNumber />
                  <h1 className="text-xl font-semibold text-foreground mb-1 mt-2">
                    {t("not_found.title")}
                  </h1>
                  <p className="text-sm text-muted-foreground">
                    {t("not_found.subtitle")}
                  </p>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.45 }}
                  className="mt-5 grid grid-cols-3 gap-3"
                >
                  {WHOIS_FIELDS.map((f, i) => (
                    <div key={i} className="space-y-0.5">
                      <p className="text-[10px] font-medium text-muted-foreground/55 uppercase tracking-wider">
                        {f.label}
                      </p>
                      <p
                        className={[
                          "text-xs font-semibold",
                          f.error
                            ? "text-red-500"
                            : f.dim
                              ? "text-muted-foreground/50"
                              : "text-foreground",
                        ].join(" ")}
                      >
                        {f.getValue()}
                      </p>
                    </div>
                  ))}
                </motion.div>
              </div>
            </div>

            <AnimatePresence>
              {looksLikeDomain && (
                <motion.div
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ delay: 0.3, duration: 0.3 }}
                  className="mt-5 rounded-xl border border-emerald-500/25 bg-emerald-500/6 overflow-hidden"
                >
                  <div className="px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-3">
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <RiGlobalLine className="w-4 h-4 text-emerald-500/70 shrink-0" />
                      <span className="text-[11px] text-muted-foreground font-medium">
                        {t("not_found.domain_hint")}
                      </span>
                      <code className="text-[11px] font-mono text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 px-1.5 py-0.5 rounded truncate max-w-[160px]">
                        {rawPath}
                      </code>
                    </div>
                    <Link
                      href={`/${encodeURIComponent(rawPath)}`}
                      className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold transition-colors shrink-0"
                    >
                      <RiSearchLine className="w-3.5 h-3.5" />
                      {t("not_found.search_btn")} {rawPath}
                    </Link>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <form onSubmit={handleSearch} className="mt-5">
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                  <input
                    ref={inputRef}
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder={t("not_found.search_placeholder")}
                    className="w-full h-10 pl-9 pr-3 text-sm rounded-lg border border-border bg-background focus:outline-none focus:ring-1 focus:ring-primary/50 focus:border-primary/50 transition-colors"
                  />
                </div>
                <button
                  type="submit"
                  disabled={!query.trim()}
                  className="h-10 px-4 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {t("not_found.search_btn")}
                </button>
              </div>
            </form>

            <div className="mt-4 flex items-center justify-center sm:justify-start">
              <Link
                href="/"
                className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                <RiArrowLeftLine className="w-3.5 h-3.5" />
                {t("not_found.back_home")}
              </Link>
            </div>
          </div>
        </motion.div>

        <AnimatePresence>
          {showTerminal && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
              className="glass-panel border border-border rounded-xl overflow-hidden"
            >
              <div className="border-b border-border/60 bg-muted/30 px-4 py-2.5 flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-400/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-400/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-green-400/60" />
                </div>
                <span className="text-[11px] font-mono text-muted-foreground/60 ml-1">
                  {t("not_found.log_title")}
                </span>
                <RiSignalWifiErrorLine className="w-3.5 h-3.5 text-red-400/60 ml-auto" />
              </div>
              <div className="p-4 space-y-0.5 bg-muted/10">
                {terminalLines.slice(0, visibleLines).map((line, i) => (
                  <TerminalLine
                    key={i}
                    index={i}
                    text={line.text}
                    highlight={line.highlight}
                    dim={line.dim}
                    accent={line.accent}
                  />
                ))}
                {visibleLines < terminalLines.length && (
                  <motion.span
                    animate={{ opacity: [1, 0] }}
                    transition={{ duration: 0.55, repeat: Infinity }}
                    className="inline-block w-1.5 h-3 bg-muted-foreground/40 rounded-sm ml-0.5 align-middle"
                  />
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {terminalDone && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, ease: [0.32, 0.72, 0, 1] }}
              className="glass-panel border border-border/50 rounded-xl px-4 py-3 flex items-start gap-3"
            >
              <RiLightbulbFlashLine className="w-4 h-4 text-yellow-500/70 shrink-0 mt-0.5" />
              <p className="text-[12px] text-muted-foreground/70 leading-relaxed">
                {randomFact}
              </p>
            </motion.div>
          )}
        </AnimatePresence>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 3.2 }}
          className="text-center text-[11px] text-muted-foreground/35 px-4"
        >
          {t("not_found.tip")}
        </motion.p>
      </div>
    </div>
  );
}
