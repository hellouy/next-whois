import React from "react";
import { AnimatePresence, motion } from "framer-motion";
import { cn, useSaver } from "@/lib/utils";
import { RiDownloadLine, RiFileCopyLine } from "@remixicon/react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { useTranslation } from "@/lib/i18n";

// Matches URLs, but stops before trailing punctuation that shouldn't be part of the link
const URL_REGEX = /(https?:\/\/[^\s<>"{}|\\^`[\]]+?)(?=[.,;:!?)}\]]*(?:\s|$))/g;
// WHOIS key pattern: starts with a letter, contains only letters/digits/hyphens/spaces, ends before ":"
// Must be <= 50 chars and not look like an IPv6 address (which also contains colons)
const WHOIS_KEY_REGEX = /^([A-Za-z][A-Za-z0-9 \-_]{0,48}?):\s*/;

function renderWithLinks(text: string) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  const regex = new RegExp(URL_REGEX.source, "g");
  let m: RegExpExecArray | null;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={last}>{text.slice(last, m.index)}</span>);
    parts.push(
      <a
        key={m.index}
        href={m[1]}
        target="_blank"
        rel="noopener noreferrer"
        className="text-blue-600 dark:text-blue-400 hover:underline break-all"
      >
        {m[1]}
      </a>,
    );
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(<span key={last}>{text.slice(last)}</span>);
  return parts.length > 0 ? parts : [<span key={0}>{text}</span>];
}

function WhoisHighlight({ content }: { content: string }) {
  return (
    <>
      {content.split("\n").map((line, i) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={i} className="h-3" />;

        // Comment / section header lines
        if (
          trimmed.startsWith("%") ||
          trimmed.startsWith("#") ||
          trimmed.startsWith(">>>") ||
          trimmed.startsWith("--")
        ) {
          return (
            <div key={i} className="text-zinc-400 dark:text-zinc-600 italic">
              {line}
            </div>
          );
        }

        // WHOIS key-value line (strict pattern match to avoid false positives on IPv6, URLs etc.)
        const keyMatch = line.match(WHOIS_KEY_REGEX);
        if (keyMatch) {
          const keyPart = keyMatch[0];
          const valuePart = line.slice(keyPart.length);
          return (
            <div key={i}>
              <span className="text-sky-600 dark:text-sky-400 font-medium">
                {keyMatch[1]}:
              </span>
              {" "}
              <span className="text-zinc-700 dark:text-zinc-200">
                {renderWithLinks(valuePart)}
              </span>
            </div>
          );
        }

        return (
          <div key={i} className="text-zinc-600 dark:text-zinc-300">
            {renderWithLinks(line)}
          </div>
        );
      })}
    </>
  );
}

function RdapJsonHighlight({ content }: { content: string }) {
  const tokenRegex =
    /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(\btrue\b|\bfalse\b|\bnull\b)|([{}[\]])|([,:])|([\s]+)/g;

  return (
    <>
      {content.split("\n").map((line, i) => {
        const parts: React.ReactNode[] = [];
        let lastIndex = 0;
        let match;
        const re = new RegExp(tokenRegex.source, "g");
        while ((match = re.exec(line)) !== null) {
          if (match.index > lastIndex) {
            parts.push(
              <span
                key={`t${lastIndex}`}
                className="text-zinc-600 dark:text-zinc-300"
              >
                {line.slice(lastIndex, match.index)}
              </span>,
            );
          }
          if (match[1]) {
            parts.push(
              <span
                key={`k${match.index}`}
                className="text-sky-600 dark:text-sky-400"
              >
                {match[1]}
              </span>,
              <span
                key={`c${match.index}`}
                className="text-zinc-400 dark:text-zinc-500"
              >
                :
              </span>,
            );
          } else if (match[2]) {
            const str = match[2];
            if (/^"https?:\/\//.test(str)) {
              const url = str.slice(1, -1);
              parts.push(
                <span
                  key={`s${match.index}`}
                  className="text-emerald-600 dark:text-emerald-400"
                >
                  &quot;
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-emerald-600 dark:text-emerald-400 hover:underline"
                  >
                    {url}
                  </a>
                  &quot;
                </span>,
              );
            } else {
              parts.push(
                <span
                  key={`s${match.index}`}
                  className="text-emerald-600 dark:text-emerald-400"
                >
                  {str}
                </span>,
              );
            }
          } else if (match[3]) {
            parts.push(
              <span
                key={`n${match.index}`}
                className="text-amber-600 dark:text-amber-400"
              >
                {match[3]}
              </span>,
            );
          } else if (match[4]) {
            parts.push(
              <span
                key={`b${match.index}`}
                className="text-purple-600 dark:text-purple-400"
              >
                {match[4]}
              </span>,
            );
          } else if (match[5]) {
            parts.push(
              <span
                key={`p${match.index}`}
                className="text-zinc-400 dark:text-zinc-500"
              >
                {match[5]}
              </span>,
            );
          } else if (match[6]) {
            parts.push(
              <span
                key={`d${match.index}`}
                className="text-zinc-400 dark:text-zinc-500"
              >
                {match[6]}
              </span>,
            );
          } else if (match[7]) {
            parts.push(<span key={`w${match.index}`}>{match[7]}</span>);
          }
          lastIndex = re.lastIndex;
        }
        if (lastIndex < line.length) {
          parts.push(
            <span
              key={`e${lastIndex}`}
              className="text-zinc-600 dark:text-zinc-300"
            >
              {line.slice(lastIndex)}
            </span>,
          );
        }
        return (
          <div key={i} className="whitespace-pre">
            {parts.length > 0 ? parts : " "}
          </div>
        );
      })}
    </>
  );
}

export function ResponsePanel({
  whoisContent,
  rdapContent,
  target,
  copy,
}: {
  whoisContent: string;
  rdapContent?: string;
  target: string;
  copy: (text: string) => void;
}) {
  const { t } = useTranslation();
  const save = useSaver();
  const hasWhois = !!whoisContent;
  const hasRdap = !!rdapContent;
  const [activeTab, setActiveTab] = React.useState<"whois" | "rdap">(
    hasWhois ? "whois" : "rdap",
  );

  const currentContent =
    activeTab === "whois" ? whoisContent : rdapContent || "";

  const currentFilename =
    activeTab === "whois" ? `${target}.txt` : `${target}.rdap.json`;

  return (
    <div className="bg-white dark:bg-zinc-950 text-zinc-700 dark:text-zinc-300 rounded-xl overflow-hidden border border-border flex flex-col shadow-lg h-full">
      <div className="bg-muted/50 dark:bg-black border-b border-border px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-1">
          {hasWhois && (
            <button
              onClick={() => setActiveTab("whois")}
              className={cn(
                "px-2.5 py-1 rounded text-[11px] font-mono transition-colors",
                activeTab === "whois"
                  ? "bg-background dark:bg-zinc-800 text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              Whois
            </button>
          )}
          {hasRdap && (
            <button
              onClick={() => setActiveTab("rdap")}
              className={cn(
                "px-2.5 py-1 rounded text-[11px] font-mono transition-colors",
                activeTab === "rdap"
                  ? "bg-background dark:bg-zinc-800 text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              RDAP
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => save(currentFilename, currentContent)}
            className="text-[10px] text-muted-foreground hover:text-foreground transition-colors uppercase font-medium tracking-wide flex items-center gap-1"
          >
            <RiDownloadLine className="w-3 h-3" />
            {t("save")}
          </button>
          <button
            onClick={() => copy(currentContent)}
            className="text-[10px] text-muted-foreground hover:text-foreground transition-colors uppercase font-medium tracking-wide flex items-center gap-1"
          >
            <RiFileCopyLine className="w-3 h-3" />
            {t("copy")}
          </button>
        </div>
      </div>
      <ScrollArea className="flex-1">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={activeTab}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15, ease: "easeInOut" }}
            className="p-4 font-mono text-[11px] leading-relaxed"
          >
            {activeTab === "whois" && whoisContent && (
              <WhoisHighlight content={whoisContent} />
            )}
            {activeTab === "rdap" && rdapContent && (
              <RdapJsonHighlight content={rdapContent} />
            )}
          </motion.div>
        </AnimatePresence>
        <ScrollBar orientation="horizontal" />
      </ScrollArea>
    </div>
  );
}
