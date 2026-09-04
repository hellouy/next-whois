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
import { toSearchURI, isValidDomainTld } from "@/lib/utils";
import { useTranslation } from "@/lib/i18n";

// Non-domain extensions that commonly appear in URL paths (file paths, API routes, etc.)
const NON_DOMAIN_EXTS = new Set([
  "tsx", "ts", "js", "jsx", "mjs", "cjs", "vue", "svelte",
  "json", "json5", "jsonc", "yaml", "yml", "toml", "env", "lock",
  "md", "mdx", "txt", "rst", "log", "csv", "xml",
  "html", "htm", "css", "scss", "sass", "less",
  "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "avif",
  "ttf", "woff", "woff2", "eot", "otf",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "tar", "gz",
  "sh", "bash", "py", "rb", "php", "go", "rs", "java", "kt", "swift", "c", "cpp", "h",
  "map", "d", "min",
]);

/**
 * Returns true only when `path` looks like a genuine domain/IP query:
 *  - no slash (rules out file paths)
 *  - only domain-legal characters
 *  - TLD is not a known file extension
 *  - TLD passes ICANN validation via isValidDomainTld
 */
function looksLikeDomainQuery(path: string): boolean {
  if (!path || !path.includes(".")) return false;
  // Slashes → file/URL path, not a standalone domain
  if (path.includes("/")) return false;
  // Spaces are never valid in a domain
  if (path.includes(" ")) return false;
  // Only allow characters legal in domain names / IPs / ASNs
  if (!/^[a-zA-Z0-9._:[\]-]+$/.test(path)) return false;
  const parts = path.split(".");
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1].toLowerCase();
  // TLD must be at least 2 characters
  if (tld.length < 2) return false;
  // Reject known file/code extensions
  if (NON_DOMAIN_EXTS.has(tld)) return false;
  // Delegate final check to the ICANN-aware validator
  return isValidDomainTld(path);
}

const FUN_FACTS: Record<string, string[]> = {
  zh: [
    "世界上第一个 404 错误发生在 1992 年的欧洲核子研究中心（CERN），来自 Room 404 这个房间。",
    "NXDOMAIN 全称 Non-Existent Domain，即「不存在的域名」，是 DNS 世界里的鬼城。",
    "全球注册域名数量超过 3.5 亿个，但你访问的这个并不在其中。",
    "最古老的活跃域名 symbolics.com 注册于 1985 年 3 月 15 日，至今已运行 40 年。",
    ".com 自 1985 年起就是最受欢迎的顶级域，王者地位从未动摇。",
    "一次 DNS 查询通常在 50ms 内完成，这个 404 用的时间更短 —— 因为什么都没找到。",
    "ICANN 管理着 1,500 多个顶级域名（TLD），不过你要找的这个还没被注册。",
    "DNS 根服务器逻辑上只有 13 个，但实际分布在全球 1,500 多个物理节点上。",
    "TTL（Time To Live）是 DNS 记录的缓存时间。这个 404 页面的 TTL：0 秒。",
    "全球每天有超过 10 万个新域名被注册 —— 你找的这个可能明天就会出现！",
    "域名不区分大小写，google.com 和 GOOGLE.COM 会解析到同一个地方。",
    "IPv4 地址总共约 43 亿个，而 IPv6 地址数量比地球上的沙粒还多。",
    "世界上最贵的域名交易：voice.com 以 3,000 万美元成交（2019 年）。",
    ".tk（托克劳群岛）曾经是全球注册数量最多的 ccTLD，因为它免费开放注册。",
  ],
  "zh-tw": [
    "世界上第一個 404 錯誤發生在 1992 年的歐洲核子研究中心（CERN），來自 Room 404 這個房間。",
    "NXDOMAIN 全名 Non-Existent Domain，即「不存在的網域」，是 DNS 世界裡的鬼城。",
    "全球註冊網域數量超過 3.5 億個，但你造訪的這個並不在其中。",
    "最古老的活躍網域 symbolics.com 註冊於 1985 年 3 月 15 日，至今已運作 40 年。",
    ".com 自 1985 年起就是最受歡迎的頂級域，王者地位從未動搖。",
    "一次 DNS 查詢通常在 50ms 內完成，這個 404 用的時間更短 —— 因為什麼都沒找到。",
    "ICANN 管理著 1,500 多個頂級網域（TLD），不過你要找的這個還沒被註冊。",
    "DNS 根伺服器邏輯上只有 13 個，但實際分布在全球 1,500 多個實體節點上。",
    "TTL（Time To Live）是 DNS 紀錄的快取時間。這個 404 頁面的 TTL：0 秒。",
    "全球每天有超過 10 萬個新網域被註冊 —— 你找的這個可能明天就會出現！",
    "網域不區分大小寫，google.com 和 GOOGLE.COM 會解析到同一個地方。",
    "IPv4 位址總共約 43 億個，而 IPv6 位址數量比地球上的沙粒還多。",
    "世界上最貴的網域交易：voice.com 以 3,000 萬美元成交（2019 年）。",
    ".tk（托克勞群島）曾經是全球註冊數量最多的 ccTLD，因為它免費開放註冊。",
  ],
  en: [
    "The first 404 error was served at CERN in 1992 — from Room 404.",
    "NXDOMAIN stands for Non-Existent Domain — the ghost town of the DNS world.",
    "Over 350 million domains are registered worldwide, but this one isn't among them.",
    "The oldest active domain, symbolics.com, was registered on March 15, 1985.",
    ".com has been the most popular TLD since 1985 — and still holds the crown.",
    "A DNS lookup typically completes in under 50ms. This 404 took even less.",
    "ICANN manages over 1,500 top-level domains — but yours hasn't been registered yet.",
    "There are only 13 logical DNS root servers, but 1,500+ physical nodes worldwide.",
    "TTL stands for Time To Live — the cache lifetime of a DNS record. This page: 0 sec.",
    "Over 100,000 new domains are registered every single day worldwide.",
    "Domain names are case-insensitive — google.com and GOOGLE.COM go to the same place.",
    "IPv4 has ~4.3 billion addresses. IPv6 has more addresses than grains of sand on Earth.",
    "The most expensive domain sale: voice.com sold for $30 million in 2019.",
    ".tk (Tokelau) was once the most-registered ccTLD in the world — because it was free.",
  ],
  ja: [
    "最初の 404 エラーは 1992 年、CERN の「Room 404」という部屋から生まれました。",
    "NXDOMAIN は Non-Existent Domain（存在しないドメイン）の略 — DNS 世界のゴーストタウンです。",
    "世界中に 3.5 億以上のドメインが登録されていますが、このページはその中にありません。",
    "最古のアクティブなドメイン symbolics.com は 1985 年 3 月 15 日に登録されました。",
    ".com は 1985 年から最も人気のある TLD であり、今も王座を守り続けています。",
    "DNS ルックアップは通常 50ms 以内に完了します。この 404 はさらに速かった — 何も見つからなかったので。",
    "ICANN は 1,500 以上の TLD を管理していますが、あなたの探しているものはまだ登録されていません。",
    "DNS ルートサーバーは論理的に 13 台ですが、世界中に 1,500 以上の物理ノードがあります。",
    "TTL は Time To Live — DNS レコードのキャッシュ有効期間です。このページの TTL：0 秒。",
    "世界中で毎日 10 万以上の新しいドメインが登録されています — あなたの探しているものも明日には現れるかも！",
    "ドメイン名は大文字小文字を区別しません — google.com と GOOGLE.COM は同じ場所に行きます。",
    "IPv4 は約 43 億個のアドレスがありますが、IPv6 のアドレス数は地球上の砂粒よりも多いのです。",
    "史上最高額のドメイン取引：voice.com が 3,000 万ドルで売却されました（2019 年）。",
    ".tk（トケラウ）はかつて世界で最も登録数の多い ccTLD でした — 無料で登録できたからです。",
  ],
  ko: [
    "첫 번째 404 에러는 1992년 CERN의 'Room 404'라는 방에서 발생했습니다.",
    "NXDOMAIN은 Non-Existent Domain(존재하지 않는 도메인)의 약자 — DNS 세계의 유령 도시입니다.",
    "전 세계에 3억 5천만 개 이상의 도메인이 등록되어 있지만, 이 페이지는 그중에 없습니다.",
    "가장 오래된 활성 도메인 symbolics.com은 1985년 3월 15일에 등록되었습니다.",
    ".com은 1985년부터 가장 인기 있는 TLD이며, 지금도 왕좌를 지키고 있습니다.",
    "DNS 조회는 보통 50ms 이내에 완료됩니다. 이 404는 그보다 더 빨랐습니다 — 아무것도 찾지 못했으니까요.",
    "ICANN은 1,500개 이상의 TLD를 관리하지만, 당신이 찾는 것은 아직 등록되지 않았습니다.",
    "DNS 루트 서버는 논리적으로 13개뿐이지만, 전 세계에 1,500개 이상의 물리적 노드가 있습니다.",
    "TTL은 Time To Live — DNS 레코드의 캐시 수명입니다. 이 페이지의 TTL: 0초.",
    "전 세계적으로 매일 10만 개 이상의 새 도메인이 등록됩니다 — 당신이 찾는 것도 내일 나타날지 모릅니다!",
    "도메인 이름은 대소문자를 구분하지 않습니다 — google.com과 GOOGLE.COM은 같은 곳으로 갑니다.",
    "IPv4는 약 43억 개의 주소가 있지만, IPv6 주소 수는 지구의 모래알보다 많습니다.",
    "역대 최고가 도메인 거래: voice.com이 3,000만 달러에 팔렸습니다(2019년).",
    ".tk(토켈라우)는 한때 세계에서 가장 많이 등록된 ccTLD였습니다 — 무료였거든요.",
  ],
  de: [
    "Der erste 404-Fehler stammt aus dem Jahr 1992 — aus dem Raum 404 am CERN.",
    "NXDOMAIN steht für Non-Existent Domain — die Geisterstadt der DNS-Welt.",
    "Weltweit sind über 350 Millionen Domains registriert — diese hier gehört nicht dazu.",
    "Die älteste aktive Domain, symbolics.com, wurde am 15. März 1985 registriert.",
    ".com ist seit 1985 die beliebteste TLD — und verteidigt die Krone bis heute.",
    "Eine DNS-Abfrage dauert meist unter 50 ms. Dieser 404 war noch schneller — es gab ja nichts zu finden.",
    "ICANN verwaltet über 1.500 Top-Level-Domains — Ihre ist (noch) nicht dabei.",
    "Es gibt nur 13 logische DNS-Root-Server, aber über 1.500 physische Knoten weltweit.",
    "TTL steht für Time To Live — die Cache-Lebensdauer eines DNS-Eintrags. Diese Seite: 0 Sek.",
    "Weltweit werden täglich über 100.000 neue Domains registriert — Ihre könnte morgen dabei sein!",
    "Domainnamen sind case-insensitive — google.com und GOOGLE.COM führen zum selben Ziel.",
    "IPv4 bietet ~4,3 Milliarden Adressen. IPv6 hat mehr Adressen als Sandkörner auf der Erde.",
    "Der teuerste Domain-Verkauf: voice.com wechselte 2019 für 30 Millionen Dollar den Besitzer.",
    ".tk (Tokelau) war einmal die meistregistrierte ccTLD der Welt — weil sie kostenlos war.",
  ],
  fr: [
    "La première erreur 404 est née en 1992 au CERN — dans la salle Room 404.",
    "NXDOMAIN signifie Non-Existent Domain — la ville fantôme du monde DNS.",
    "Plus de 350 millions de domaines sont enregistrés dans le monde — celui-ci n'en fait pas partie.",
    "Le plus ancien domaine actif, symbolics.com, a été enregistré le 15 mars 1985.",
    ".com est la TLD la plus populaire depuis 1985 — et elle garde toujours sa couronne.",
    "Une requête DNS s'effectue généralement en moins de 50 ms. Ce 404 a été encore plus rapide — il n'y avait rien à trouver.",
    "L'ICANN gère plus de 1 500 extensions — la vôtre n'est pas encore enregistrée.",
    "Il n'existe que 13 serveurs racine DNS logiques, mais plus de 1 500 nœuds physiques dans le monde.",
    "TTL signifie Time To Live — la durée de vie en cache d'un enregistrement DNS. Cette page : 0 sec.",
    "Plus de 100 000 nouveaux domaines sont enregistrés chaque jour — le vôtre pourrait apparaître demain !",
    "Les noms de domaine sont insensibles à la casse — google.com et GOOGLE.COM mènent au même endroit.",
    "L'IPv4 offre ~4,3 milliards d'adresses. L'IPv6 en a plus que de grains de sable sur Terre.",
    "La vente de domaine la plus chère : voice.com vendu 30 millions de dollars en 2019.",
    ".tk (Tokelau) fut un temps le ccTLD le plus enregistré au monde — parce qu'il était gratuit.",
  ],
  ru: [
    "Первая ошибка 404 случилась в 1992 году в CERN — в комнате Room 404.",
    "NXDOMAIN означает Non-Existent Domain — город-призрак мира DNS.",
    "В мире зарегистрировано более 350 миллионов доменов — но этого среди них нет.",
    "Старейший активный домен symbolics.com был зарегистрирован 15 марта 1985 года.",
    ".com — самая популярная TLD с 1985 года, и корону она так и не отдала.",
    "DNS-запрос обычно выполняется за 50 мс. Этот 404 был ещё быстрее — искать было нечего.",
    "ICANN управляет более чем 1 500 доменными зонами — но вашей среди них пока нет.",
    "Логических корневых DNS-серверов всего 13, но физических узлов по миру — более 1 500.",
    "TTL — Time To Live, время жизни DNS-записи в кэше. У этой страницы TTL: 0 секунд.",
    "Ежедневно в мире регистрируется более 100 000 новых доменов — ваш может появиться завтра!",
    "Домены нечувствительны к регистру — google.com и GOOGLE.COM ведут в одно место.",
    "В IPv4 около 4,3 миллиарда адресов. В IPv6 их больше, чем песчинок на Земле.",
    "Самая дорогая сделка с доменом: voice.com продан за 30 миллионов долларов в 2019 году.",
    ".tk (Токелау) когда-то был самой регистрируемой ccTLD в мире — потому что был бесплатным.",
  ],
};

function factsForLocale(locale: string): string[] {
  return FUN_FACTS[locale] ?? FUN_FACTS.en;
}

function RadarAnimation({
  pinged,
  signalLabel,
  onGhostClick,
}: {
  pinged: boolean;
  signalLabel?: string;
  onGhostClick?: () => void;
}) {
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
      <motion.button
        type="button"
        aria-label={signalLabel}
        onClick={onGhostClick}
        whileHover={{ scale: 1.18 }}
        whileTap={{ scale: 0.88, rotate: -10 }}
        animate={
          pinged
            ? { y: [0, -8, 0], rotate: [0, 8, -8, 0] }
            : { scale: [1, 1.12, 1], opacity: [0.6, 1, 0.6] }
        }
        transition={
          pinged
            ? { duration: 0.65, ease: "easeOut" }
            : { duration: 2.2, repeat: Infinity, ease: "easeInOut" }
        }
        className="relative z-10 cursor-pointer bg-transparent border-0 p-0"
      >
        <RiGhostSmileLine
          className={
            pinged
              ? "w-9 h-9 text-emerald-500/80"
              : "w-9 h-9 text-muted-foreground/50"
          }
        />
      </motion.button>
      {pinged && signalLabel && (
        <motion.span
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          className="absolute -bottom-1 left-1/2 -translate-x-1/2 text-[10px] font-mono text-emerald-500/80 whitespace-nowrap"
        >
          {signalLabel}
        </motion.span>
      )}
    </div>
  );
}

const SCRAMBLE_CHARS = "0123456789#%&$@!?";

function GlitchNumber({ scrambleSignal = 0 }: { scrambleSignal?: number }) {
  const controls = useAnimationControls();
  const [display, setDisplay] = useState("404");

  useEffect(() => {
    let frame = 0;
    const totalFrames = 14;
    const interval = setInterval(() => {
      frame += 1;
      if (frame >= totalFrames) {
        setDisplay("404");
        clearInterval(interval);
        return;
      }
      setDisplay(
        "404"
          .split("")
          .map((c) =>
            Math.random() > 0.3
              ? c
              : SCRAMBLE_CHARS[
                  Math.floor(Math.random() * SCRAMBLE_CHARS.length)
                ],
          )
          .join(""),
      );
    }, 55);
    return () => clearInterval(interval);
  }, [scrambleSignal]);

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
        {display}
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
        {display}
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
  const { t, locale } = useTranslation();
  const [query, setQuery] = useState("");
  const [showTerminal, setShowTerminal] = useState(false);
  const [visibleLines, setVisibleLines] = useState(0);
  const [terminalDone, setTerminalDone] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const [rawPath, setRawPath] = useState("");
  const [ghostPinged, setGhostPinged] = useState(false);
  const [scrambleSignal, setScrambleSignal] = useState(0);
  // whenDate must start as a fixed empty string so SSR and client first-render
  // produce identical HTML.  We fill it in via useEffect (client-only).
  const [whenDate, setWhenDate] = useState("");
  // randomFact likewise: start with a fixed entry so SSR matches client.
  // Use locale-appropriate fact list to avoid Chinese/English mixing.
  const [randomFact, setRandomFact] = useState(() => factsForLocale(locale)[0]);

  useEffect(() => {
    const facts = factsForLocale(locale);
    setRawPath(window.location.pathname.replace(/^\//, "") || "");
    setWhenDate(new Date().toUTCString());
    setRandomFact(facts[Math.floor(Math.random() * facts.length)]);
  }, [locale]);

  const looksLikeDomain = looksLikeDomainQuery(rawPath);

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

  const handleGhostPing = () => {
    setGhostPinged(true);
    setScrambleSignal((s) => s + 1);
    const facts = factsForLocale(locale);
    setRandomFact(facts[Math.floor(Math.random() * facts.length)]);
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
              <RadarAnimation
                pinged={ghostPinged}
                signalLabel={t("not_found.signal")}
                onGhostClick={handleGhostPing}
              />

              <div className="flex-1 text-center sm:text-left">
                <motion.div
                  initial={{ opacity: 0, scale: 0.93 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.4, delay: 0.15 }}
                >
                  <GlitchNumber scrambleSignal={scrambleSignal} />
                  <h1 className="text-xl font-semibold text-foreground mb-1 mt-2">
                    {t("not_found.title")}
                  </h1>
                  <p className="text-sm text-muted-foreground">
                    {looksLikeDomain
                      ? t("not_found.subtitle")
                      : t("not_found.subtitle_path")}
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
          {(terminalDone || ghostPinged) && (
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
