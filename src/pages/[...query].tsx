import {
  cleanDomain,
  cn,
  getWindowHref,
  isValidDomainTld,
  isSearchRoute,
  toSearchURI,
  useClipboard,
  useSaver,
} from "@/lib/utils";
import { GetServerSidePropsContext } from "next";
import { useRouter } from "next/router";
import { getOrigin } from "@/lib/seo";
import { Input } from "@/components/ui/input";
import Link from "next/link";
import Head from "next/head";
import { Button } from "@/components/ui/button";
import {
  RiCameraLine,
  RiFileCopyLine,
  RiExternalLinkLine,
  RiLinkM,
  RiShareLine,
  RiTwitterXLine,
  RiFacebookFill,
  RiRedditLine,
  RiWhatsappLine,
  RiTelegramLine,
  RiTimeLine,
  RiExchangeDollarFill,
  RiBillLine,
  RiDownloadLine,
  RiServerLine,
  RiGlobalLine,
  RiForbidLine,
  RiLockLine,
  RiPauseCircleLine,
  RiScalesLine,
  RiLoopLeftLine,
  RiDeleteBin2Line,
  RiCheckLine,
  RiShoppingCartLine,
  RiBookmarkLine,
  RiBookmarkFill,
  RiCalendar2Line,
  RiStickyNoteLine,
  RiTimerLine,
  RiCalendarEventLine,
  RiShieldCheckLine,
  RiLoader4Line,
  RiErrorWarningLine,
  RiSearchLine,
  RiCheckboxCircleLine,
  RiCheckboxBlankCircleLine,
  RiIdCardLine,
  RiBuildingLine,
  RiAwardLine,
  RiShakeHandsLine,
  RiCodeSLine,
  RiVipCrownLine,
  RiAlertLine,
  RiArrowRightSLine,
  RiFlagLine,
  RiInformationLine,
  RiMegaphoneLine,
} from "@remixicon/react";
import { getTopRegistrars, DomainPricing } from "@/lib/pricing/client";
import { useSiteSettings } from "@/lib/site-settings";
import { computeLifecycle, fmtDate, fmtDateTime, fmtCountdown } from "@/lib/lifecycle";
import React, { useEffect, useMemo } from "react";
import ReactDOM from "react-dom";
import { addHistory, detectQueryType } from "@/lib/history";
import { prefetchLookup, consumePrefetch } from "@/lib/lookup-prefetch";
import { useSession } from "next-auth/react";
import { Badge } from "@/components/ui/badge";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { WhoisAnalyzeResult, WhoisResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { getSetting as getSettingServer } from "@/lib/server/site-settings-server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import {
  getEppStatusInfo,
  getEppStatusColor,
  getEppStatusDisplayName,
  getEppStatusLink,
  getEppStatusDescription,
} from "@/lib/whois/epp_status";
import { SearchBox } from "@/components/search_box";
import {
  KeyboardShortcut,
  SearchHotkeysText,
} from "@/components/search_shortcuts";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { useTheme } from "next-themes";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { useSearchHotkeys } from "@/hooks/useSearchHotkeys";
import dynamic from "next/dynamic";

// Lazy-loaded: only needed when the user opens the feedback panel
const FeedbackDrawer = dynamic(
  () => import("@/components/feedback-drawer").then((m) => ({ default: m.FeedbackDrawer })),
  { ssr: false, loading: () => null }
);

const CARD_CONTAINER_VARIANTS = {
  hidden: { opacity: 1 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.04, delayChildren: 0.08 },
  },
};

const CARD_ITEM_VARIANTS = {
  hidden: { opacity: 0, y: 8 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, ease: [0.22, 1, 0.36, 1] },
  },
};

// ── QueryProgressBar ─────────────────────────────────────────────────────────
// Thin top-of-content progress bar: fills 0→80% while loading, then 100% + fade.
// When refreshing (RDAP done, WHOIS pending), shows a slow crawl at 90-95%.
function QueryProgressBar({ loading, refreshing }: { loading: boolean; refreshing?: boolean }) {
  const [width, setWidth] = React.useState(0);
  const [visible, setVisible] = React.useState(false);
  const timerRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const doneRef  = React.useRef(false);

  React.useEffect(() => {
    if (loading) {
      doneRef.current = false;
      setWidth(0);
      setVisible(true);
      // Fast initial burst to 40%, then ease toward 85% to signal active work
      let w = 0;
      timerRef.current = setInterval(() => {
        if (doneRef.current) return;
        w += w < 40 ? 12 : w < 65 ? 4 : w < 82 ? 1 : 0;
        if (w > 85) w = 85;
        setWidth(w);
      }, 80);
    } else if (refreshing) {
      // Partial result: stay at 90% and pulse slowly (WHOIS enrichment in-flight)
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

const REGISTRAR_ICONS: Record<string, { slug: string | null; color: string }> =
  {
    godaddy: { slug: "godaddy", color: "#1BDBDB" },
    namecheap: { slug: "namecheap", color: "#DE3723" },
    cloudflare: { slug: "cloudflare", color: "#F38020" },
    google: { slug: "google", color: "#000000" },
    googledomains: { slug: "google", color: "#000000" },
    ovh: { slug: "ovh", color: "#123F6D" },
    ovhcloud: { slug: "ovh", color: "#123F6D" },
    ionos: { slug: "ionos", color: "#003D8F" },
    "1and1": { slug: "ionos", color: "#003D8F" },
    "1&1": { slug: "ionos", color: "#003D8F" },
    uniteddomains: { slug: "ionos", color: "#003D8F" },
    gandi: { slug: "gandi", color: "#6640FE" },
    porkbun: { slug: "porkbun", color: "#EF7878" },
    hetzner: { slug: "hetzner", color: "#D50C2D" },
    hostinger: { slug: "hostinger", color: "#673DE6" },
    alibaba: { slug: "alibabacloud", color: "#FF6A00" },
    alibabacloud: { slug: "alibabacloud", color: "#FF6A00" },
    aliyun: { slug: "alibabacloud", color: "#FF6A00" },
    hichina: { slug: "alibabacloud", color: "#FF6A00" },
    wanwang: { slug: "alibabacloud", color: "#FF6A00" },
    tencent: { slug: "/registrar-icons/tencent.png", color: "#EB1923" },
    dnspod: { slug: "/registrar-icons/dnspod.png", color: "#EB1923" },
    digitalocean: { slug: "digitalocean", color: "#0080FF" },
    squarespace: { slug: "squarespace", color: "#000000" },
    wix: { slug: "wix", color: "#0C6EFC" },
    wordpress: { slug: "wordpress", color: "#21759B" },
    automattic: { slug: "wordpress", color: "#21759B" },
    netlify: { slug: "netlify", color: "#00C7B7" },
    vercel: { slug: "vercel", color: "#000000" },
    namedotcom: { slug: "/registrar-icons/namecom.png", color: "#236BFF" },
    "name.com": { slug: "/registrar-icons/namecom.png", color: "#236BFF" },
    namesilo: { slug: "namesilo", color: "#031B4E" },
    dynadot: { slug: "/registrar-icons/dynadot.png", color: "#4E2998" },
    enom: { slug: "/registrar-icons/enom.png", color: "#F09B1B" },
    tucows: { slug: "/registrar-icons/tucows.png", color: "#F09B1B" },
    networksolutions: {
      slug: "/registrar-icons/networksolutions.png",
      color: "#2E8B57",
    },
    markmonitor: { slug: "/registrar-icons/markmonitor.png", color: "#2B5797" },
    amazon: { slug: "/registrar-icons/amazon.png", color: "#FF9900" },
    aws: { slug: "/registrar-icons/amazon.png", color: "#FF9900" },
    hover: { slug: "/registrar-icons/hover.png", color: "#3B7DDD" },
    rebel: { slug: "/registrar-icons/hover.png", color: "#3B7DDD" },
    epik: { slug: "/registrar-icons/epik.png", color: "#4A90D9" },
    dreamhost: { slug: "/registrar-icons/dreamhost.png", color: "#0073EC" },
    bluehost: { slug: "/registrar-icons/bluehost.png", color: "#003580" },
    hostgator: { slug: "/registrar-icons/hostgator.png", color: "#F8A41B" },
    siteground: { slug: "/registrar-icons/siteground.png", color: "#7B3FA0" },
    fastdomain: { slug: "/registrar-icons/fastdomain.png", color: "#003580" },
    huawei: { slug: "huawei", color: "#FF0000" },
    baidu: { slug: "baidu", color: "#2932E1" },
    ename: { slug: "/registrar-icons/ename.png", color: "#2C7BE5" },
    "ename technology": {
      slug: "/registrar-icons/ename.png",
      color: "#2C7BE5",
    },
    xinnet: { slug: "/registrar-icons/xinnet.png", color: "#E60012" },
    "identity digital": {
      slug: "/registrar-icons/identitydigital.png",
      color: "#1A1A2E",
    },
    donuts: { slug: "/registrar-icons/identitydigital.png", color: "#1A1A2E" },
    "registry operator": {
      slug: "/registrar-icons/identitydigital.png",
      color: "#1A1A2E",
    },
    "360": { slug: "/registrar-icons/360.png", color: "#2FC332" },
    qihoo: { slug: "/registrar-icons/360.png", color: "#2FC332" },
    westcn: { slug: "/registrar-icons/westcn.png", color: "#2B7DE9" },
    "west.cn": { slug: "/registrar-icons/westcn.png", color: "#2B7DE9" },
    vultr: { slug: "/registrar-icons/vultr.png", color: "#007BFC" },
    scaleway: { slug: "/registrar-icons/scaleway.png", color: "#4F0599" },
    csc: { slug: "/registrar-icons/csc.png", color: "#00529B" },
    cscglobal: { slug: "/registrar-icons/csc.png", color: "#00529B" },
    webcom: { slug: null, color: "#1166BB" },
    "web.com": { slug: null, color: "#1166BB" },
    registercom: { slug: "/registrar-icons/registercom.png", color: "#00A651" },
    "register.com": {
      slug: "/registrar-icons/registercom.png",
      color: "#00A651",
    },
    domaincom: { slug: "/registrar-icons/domaincom.png", color: "#2B74B4" },
    "domain.com": { slug: "/registrar-icons/domaincom.png", color: "#2B74B4" },
    gname: { slug: "/registrar-icons/gname.png", color: "#1E90FF" },
    shopify: { slug: "/registrar-icons/shopify.png", color: "#7AB55C" },
    oracle: { slug: "oracle", color: "#F80000" },
    gmo: { slug: "/registrar-icons/gmo.png", color: "#FF6600" },
    onamae: { slug: "/registrar-icons/gmo.png", color: "#FF6600" },
    gabia: { slug: "/registrar-icons/gabia.png", color: "#EE2737" },
    regru: { slug: "/registrar-icons/regru.png", color: "#FF6B00" },
    "reg.ru": { slug: "/registrar-icons/regru.png", color: "#FF6B00" },
    rucenter: { slug: "/registrar-icons/rucenter.png", color: "#005BAC" },
    "ru-center": { slug: "/registrar-icons/rucenter.png", color: "#005BAC" },
    strato: { slug: "/registrar-icons/strato.png", color: "#2DB928" },
    spaceship: { slug: "/registrar-icons/spaceship.png", color: "#6366F1" },
    centralnic: { slug: "/registrar-icons/centralnic.png", color: "#1D6AE5" },
    keysystems: { slug: "/registrar-icons/centralnic.png", color: "#1D6AE5" },
    rrpproxy: { slug: "/registrar-icons/centralnic.png", color: "#1D6AE5" },
    bigrock: { slug: "/registrar-icons/bigrock.png", color: "#FF6C2C" },
    resellerclub: {
      slug: "/registrar-icons/resellerclub.png",
      color: "#F99D1C",
    },
    publicdomainregistry: { slug: null, color: "#0066FF" },
    pdr: { slug: null, color: "#0066FF" },
    internetbs: { slug: null, color: "#2196F3" },
    "internet.bs": { slug: null, color: "#2196F3" },
  };

const NS_BRANDS: {
  brand: string;
  domains: string[];
  slug: string | null;
  color: string;
}[] = [
  {
    brand: "GoDaddy",
    domains: ["domaincontrol.com"],
    slug: "godaddy",
    color: "#1BDBDB",
  },
  {
    brand: "Cloudflare",
    domains: [
      "cloudflare.com",
      "foundationdns.com",
      "foundationdns.net",
      "foundationdns.org",
    ],
    slug: "cloudflare",
    color: "#F38020",
  },
  {
    brand: "Namecheap",
    domains: ["registrar-servers.com", "namecheaphosting.com"],
    slug: "namecheap",
    color: "#DE3723",
  },
  {
    brand: "Porkbun",
    domains: ["porkbun.com"],
    slug: "porkbun",
    color: "#EF7878",
  },
  {
    brand: "Hetzner",
    domains: [
      "hetzner.com",
      "hetzner.de",
      "first-ns.de",
      "second-ns.de",
      "second-ns.com",
      "your-server.de",
    ],
    slug: "hetzner",
    color: "#D50C2D",
  },
  {
    brand: "OVHcloud",
    domains: ["ovh.net", "ovh.ca", "anycast.me"],
    slug: "ovh",
    color: "#123F6D",
  },
  {
    brand: "IONOS",
    domains: ["ui-dns.com", "ui-dns.org", "ui-dns.de", "ui-dns.biz"],
    slug: "ionos",
    color: "#003D8F",
  },
  { brand: "Gandi", domains: ["gandi.net"], slug: "gandi", color: "#6640FE" },
  {
    brand: "DigitalOcean",
    domains: ["digitalocean.com"],
    slug: "digitalocean",
    color: "#0080FF",
  },
  {
    brand: "Hostinger",
    domains: ["dns-parking.com", "main-hosting.eu"],
    slug: "hostinger",
    color: "#673DE6",
  },
  {
    brand: "Netlify",
    domains: ["netlify.com"],
    slug: "netlify",
    color: "#00C7B7",
  },
  {
    brand: "NS1",
    domains: ["nsone.net"],
    slug: "/registrar-icons/ns1.png",
    color: "#760DDE",
  },
  {
    brand: "Vercel",
    domains: ["vercel-dns.com"],
    slug: "vercel",
    color: "#000000",
  },
  { brand: "Wix", domains: ["wixdns.net"], slug: "wix", color: "#0C6EFC" },
  {
    brand: "Squarespace",
    domains: ["squarespace-dns.com", "squarespace.com"],
    slug: "squarespace",
    color: "#000000",
  },
  {
    brand: "WordPress",
    domains: ["wordpress.com"],
    slug: "wordpress",
    color: "#21759B",
  },
  {
    brand: "AWS Route 53",
    domains: ["awsdns"],
    slug: "/registrar-icons/amazon.png",
    color: "#232F3E",
  },
  {
    brand: "Azure DNS",
    domains: [
      "azure-dns.com",
      "azure-dns.net",
      "azure-dns.org",
      "azure-dns.info",
    ],
    slug: "/registrar-icons/azure.png",
    color: "#0078D4",
  },
  {
    brand: "Google",
    domains: ["googledomains.com", "google.com"],
    slug: "google",
    color: "#000000",
  },
  {
    brand: "Akamai",
    domains: ["linode.com", "akam.net", "akamaiedge.net"],
    slug: "akamai",
    color: "#0096D6",
  },
  {
    brand: "Hurricane Electric",
    domains: ["dns.he.net"],
    slug: "/registrar-icons/he.png",
    color: "#E40000",
  },
  {
    brand: "DNSPod",
    domains: [
      "dnspod.net",
      "qq.com",
      "dnsv2.com",
      "dnsv3.com",
      "dnsv4.com",
      "dnsv5.com",
      "iidns.com",
    ],
    slug: "/registrar-icons/dnspod.png",
    color: "#4478E6",
  },
  {
    brand: "Tencent Cloud",
    domains: ["tencentcloudcns.com"],
    slug: "/registrar-icons/tencent.png",
    color: "#EB1923",
  },
  {
    brand: "DNSimple",
    domains: ["dnsimple.com", "dnsimple-edge.net"],
    slug: "/registrar-icons/dnsimple.png",
    color: "#205EBB",
  },
  {
    brand: "ClouDNS",
    domains: ["cloudns.net"],
    slug: "/registrar-icons/cloudns.png",
    color: "#4FA3D7",
  },
  { brand: "FreeDNS", domains: ["afraid.org"], slug: null, color: "#27AE60" },
  {
    brand: "Name.com",
    domains: ["name.com"],
    slug: "/registrar-icons/namecom.png",
    color: "#236BFF",
  },
  {
    brand: "Hover",
    domains: ["hover.com"],
    slug: "/registrar-icons/hover.png",
    color: "#3B7DDD",
  },
  {
    brand: "Dynadot",
    domains: ["dynadot.com"],
    slug: "/registrar-icons/dynadot.png",
    color: "#4E2998",
  },
  {
    brand: "Enom",
    domains: ["name-services.com"],
    slug: "/registrar-icons/enom.png",
    color: "#F09B1B",
  },
  {
    brand: "Network Solutions",
    domains: ["worldnic.com"],
    slug: "/registrar-icons/networksolutions.png",
    color: "#2E8B57",
  },
  {
    brand: "NameSilo",
    domains: ["dnsowl.com", "namesilo.com"],
    slug: "namesilo",
    color: "#031B4E",
  },
  {
    brand: "Alibaba Cloud",
    domains: ["hichina.com", "alidns.com", "net.cn", "aliyun.com"],
    slug: "alibabacloud",
    color: "#FF6A00",
  },
  {
    brand: "Baidu Cloud",
    domains: ["bdydns.cn", "bdydns.com"],
    slug: "baidu",
    color: "#2932E1",
  },
  {
    brand: "Huawei Cloud",
    domains: [
      "huaweicloud-dns.com",
      "huaweicloud-dns.cn",
      "huaweicloud-dns.net",
      "hwclouds-dns.com",
      "hwclouds-dns.net",
      "huawei.com",
    ],
    slug: "huawei",
    color: "#FF0000",
  },
  {
    brand: "Tucows",
    domains: ["tucows.com"],
    slug: "/registrar-icons/tucows.png",
    color: "#F09B1B",
  },
  {
    brand: "360",
    domains: ["360safe.com"],
    slug: "/registrar-icons/360.png",
    color: "#2FC332",
  },
  {
    brand: "eName",
    domains: ["ename.net", "ename.com"],
    slug: "/registrar-icons/ename.png",
    color: "#2C7BE5",
  },
  {
    brand: "Xinnet",
    domains: ["xinnet.com", "xincache.com"],
    slug: "/registrar-icons/xinnet.png",
    color: "#E60012",
  },
  {
    brand: "West.cn",
    domains: ["myhostadmin.net", "west-dns.com", "est.cn"],
    slug: "/registrar-icons/westcn.png",
    color: "#2B7DE9",
  },
  {
    brand: "JD Cloud",
    domains: ["jdgslb.com", "jdcache.com"],
    slug: "/registrar-icons/jdcloud.png",
    color: "#C9151E",
  },
  {
    brand: "Volcengine",
    domains: ["volcengine.com", "volcdns.com"],
    slug: "/registrar-icons/volcengine.png",
    color: "#3370FF",
  },
  {
    brand: "Fastly",
    domains: ["fastly.net"],
    slug: "/registrar-icons/fastly.png",
    color: "#FF282D",
  },
  {
    brand: "UltraDNS",
    domains: ["ultradns.com", "ultradns.net", "ultradns.org"],
    slug: "/registrar-icons/ultradns.png",
    color: "#5B2D8E",
  },
  {
    brand: "Constellix",
    domains: ["constellix.com", "constellix.net"],
    slug: "/registrar-icons/constellix.png",
    color: "#4B9CD3",
  },
  {
    brand: "easyDNS",
    domains: ["easydns.com", "easydns.net", "easydns.org"],
    slug: "/registrar-icons/easydns.png",
    color: "#29A8E0",
  },
  {
    brand: "Vultr",
    domains: ["vultr.com"],
    slug: "/registrar-icons/vultr.png",
    color: "#007BFC",
  },
  {
    brand: "Scaleway",
    domains: ["scaleway.com"],
    slug: "/registrar-icons/scaleway.png",
    color: "#4F0599",
  },
  {
    brand: "TransIP",
    domains: ["transip.net", "transip.nl"],
    slug: "/registrar-icons/transip.png",
    color: "#74B63B",
  },
  {
    brand: "SiteGround",
    domains: ["siteground.net", "sgvps.net"],
    slug: "/registrar-icons/siteground.png",
    color: "#7B3FA0",
  },
  {
    brand: "Bluehost",
    domains: ["bluehost.com"],
    slug: "/registrar-icons/bluehost.png",
    color: "#003580",
  },
  {
    brand: "DreamHost",
    domains: ["dreamhost.com"],
    slug: "/registrar-icons/dreamhost.png",
    color: "#0073EC",
  },
  {
    brand: "HostGator",
    domains: ["hostgator.com"],
    slug: "/registrar-icons/hostgator.png",
    color: "#F8A41B",
  },
  {
    brand: "Epik",
    domains: ["epik.com"],
    slug: "/registrar-icons/epik.png",
    color: "#4A90D9",
  },
  {
    brand: "MarkMonitor",
    domains: ["markmonitor.com"],
    slug: "/registrar-icons/markmonitor.png",
    color: "#2B5797",
  },
  {
    brand: "Identity Digital",
    domains: ["donuts.co", "identity.digital"],
    slug: "/registrar-icons/identitydigital.png",
    color: "#1A1A2E",
  },
  {
    brand: "CSC Global",
    domains: ["cscglobal.com", "cscdns.net"],
    slug: "/registrar-icons/csc.png",
    color: "#00529B",
  },
  {
    brand: "Shopify",
    domains: ["shopify.com", "myshopify.com"],
    slug: "/registrar-icons/shopify.png",
    color: "#7AB55C",
  },
  {
    brand: "Oracle/Dyn",
    domains: ["dynect.net", "oraclecloud.net"],
    slug: "oracle",
    color: "#F80000",
  },
  {
    brand: "Imperva",
    domains: ["impervadns.net", "incapdns.net"],
    slug: "/registrar-icons/imperva.png",
    color: "#004680",
  },
  {
    brand: "Sucuri",
    domains: ["sucuridns.com", "sucuri.net"],
    slug: "/registrar-icons/sucuri.png",
    color: "#88C946",
  },
  {
    brand: "Verisign",
    domains: ["verisign-grs.com", "verisigndns.com", "nstld.com"],
    slug: "/registrar-icons/verisign.png",
    color: "#003399",
  },
  {
    brand: "GMO/Onamae",
    domains: ["onamae.com", "gmoint.com", "gmoserver.jp"],
    slug: "/registrar-icons/gmo.png",
    color: "#FF6600",
  },
  {
    brand: "Gabia",
    domains: ["gabia.net", "gabia.io"],
    slug: "/registrar-icons/gabia.png",
    color: "#EE2737",
  },
  {
    brand: "Reg.ru",
    domains: ["reg.ru"],
    slug: "/registrar-icons/regru.png",
    color: "#FF6B00",
  },
  {
    brand: "RU-CENTER",
    domains: ["nic.ru"],
    slug: "/registrar-icons/rucenter.png",
    color: "#005BAC",
  },
  {
    brand: "Strato",
    domains: ["strato.de", "stratoserver.net", "rzone.de"],
    slug: "/registrar-icons/strato.png",
    color: "#2DB928",
  },
  {
    brand: "Bunny.net",
    domains: ["bunny.net", "bunnyinfra.net"],
    slug: "/registrar-icons/bunny.png",
    color: "#F47621",
  },
  {
    brand: "DNS Made Easy",
    domains: ["dnsmadeeasy.com"],
    slug: "/registrar-icons/dnsmadeeasy.png",
    color: "#6BB839",
  },
  {
    brand: "CentralNic",
    domains: ["centralnic.net", "rrpproxy.net"],
    slug: "/registrar-icons/centralnic.png",
    color: "#1D6AE5",
  },
  {
    brand: "Gname",
    domains: ["gname-dns.com"],
    slug: "/registrar-icons/gname.png",
    color: "#1E90FF",
  },
  {
    brand: "Register.com",
    domains: ["register.com"],
    slug: "/registrar-icons/registercom.png",
    color: "#00A651",
  },
  {
    brand: "Domain.com",
    domains: ["domain.com"],
    slug: "/registrar-icons/domaincom.png",
    color: "#2B74B4",
  },
  {
    brand: "Yandex",
    domains: ["yandexcloud.net", "yandex.net"],
    slug: "/registrar-icons/yandex.png",
    color: "#5282FF",
  },
  {
    brand: "DDoS-Guard",
    domains: ["ddos-guard.net"],
    slug: "/registrar-icons/ddosguard.png",
    color: "#0A2856",
  },
  {
    brand: "Sakura Internet",
    domains: ["sakura.ne.jp", "dns.ne.jp"],
    slug: "/registrar-icons/sakura.png",
    color: "#FF6699",
  },
  {
    brand: "Rackspace",
    domains: ["rackspace.com", "stabletransit.com"],
    slug: "rackspace",
    color: "#C40022",
  },
  {
    brand: "IBM Cloud",
    domains: ["softlayer.com"],
    slug: "ibm",
    color: "#054ADA",
  },
  {
    brand: "BigRock",
    domains: ["bigrock.in"],
    slug: "/registrar-icons/bigrock.png",
    color: "#FF6C2C",
  },
  {
    brand: "ResellerClub",
    domains: ["resellerclub.com"],
    slug: "/registrar-icons/resellerclub.png",
    color: "#F99D1C",
  },
  {
    brand: "Cafe24",
    domains: ["cafe24.com"],
    slug: "/registrar-icons/cafe24.png",
    color: "#13AA52",
  },
  {
    brand: "Gcore",
    domains: ["gcore.com", "gcorelabs.net"],
    slug: "/registrar-icons/gcore.png",
    color: "#FF4C00",
  },
  {
    brand: "Wangsu",
    domains: ["wscdns.com", "wsglb0.com"],
    slug: "/registrar-icons/wangsu.png",
    color: "#004B97",
  },
  {
    brand: "ZDNS",
    domains: ["zdnscloud.com", "zdns.cn"],
    slug: "/registrar-icons/zdns.png",
    color: "#1E73BE",
  },
  {
    brand: "No-IP",
    domains: ["no-ip.com"],
    slug: "/registrar-icons/noip.png",
    color: "#2196F3",
  },
  {
    brand: "Infomaniak",
    domains: ["infomaniak.com", "infomaniak.ch"],
    slug: "/registrar-icons/infomaniak.png",
    color: "#0F7A3F",
  },
  {
    brand: "Spaceship",
    domains: ["spaceship.com"],
    slug: "/registrar-icons/spaceship.png",
    color: "#6366F1",
  },
  { brand: "22.cn", domains: ["22.cn"], slug: null, color: "#FF6600" },
  { brand: "DNS.com", domains: ["dns.com"], slug: null, color: "#0099CC" },
  {
    brand: "Cndns",
    domains: ["dns-diy.com", "cndns.com"],
    slug: null,
    color: "#FF8C00",
  },
  {
    brand: "StackPath",
    domains: ["stackpathdns.com"],
    slug: null,
    color: "#003BDE",
  },
  { brand: "Zoho", domains: ["zoho.com"], slug: "zoho", color: "#C8202B" },
];

function getNsBrand(
  ns: string,
): { brand: string; slug: string | null; color: string } | null {
  const lower = ns.toLowerCase();
  for (const info of NS_BRANDS) {
    if (info.domains.some((d) => lower.includes(d))) return info;
  }
  return null;
}

function getRegistrarIcon(
  registrar: string,
  registrarURL?: string,
): { slug: string | null; color: string } | null {
  if (!registrar || registrar === "Unknown") return null;
  const normalized = registrar.toLowerCase().replace(/[\s.,\-_()]+/g, "");
  for (const [key, info] of Object.entries(REGISTRAR_ICONS)) {
    if (normalized.includes(key)) return info;
  }
  if (registrarURL) {
    const urlLower = registrarURL.toLowerCase();
    for (const [key, info] of Object.entries(REGISTRAR_ICONS)) {
      if (urlLower.includes(key)) return info;
    }
  }
  return null;
}

function getDarkModeIconColor(color: string): string {
  const hex = color.replace("#", "");
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance < 0.4 ? "white" : hex;
}

function resolveIconUrl(slug: string, color: string, dark: boolean): string {
  if (slug.startsWith("/")) return slug;
  const c = dark ? getDarkModeIconColor(color) : color.replace("#", "");
  return `https://cdn.simpleicons.org/${slug}/${c}`;
}

function getRegistrarFallbackColor(registrar: string): string {
  let hash = 0;
  for (let i = 0; i < registrar.length; i++) {
    hash = registrar.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 65%, 50%)`;
}

/**
 * Robustly parse a WHOIS date string into a Date object.
 * Handles formats like:
 *   "1996-07-01T02:00:00Z"
 *   "1996-07-01 02:00:00 U"    ← .ba / some ccTLDs append a TZ letter
 *   "1996-07-01 02:00:00 UTC"
 *   "1996-07-01 02:00:00+08:00"
 *   "2022-11-08 12:31:01"
 */
function parseWhoisDate(dateStr: string): Date | null {
  if (!dateStr || dateStr === "Unknown") return null;
  // 1. Try as-is first (covers ISO 8601 with Z or offset)
  let d = new Date(dateStr);
  if (!isNaN(d.getTime())) return d;
  // 2. Strip trailing timezone code: single letters (U, Z) or abbreviations (UTC, EST, CET…)
  //    and numeric offsets (+08:00, -05:00) then retry
  const stripped = dateStr
    .replace(/\s+[+-]\d{2}:?\d{2}$/, "")   // remove " +08:00" / " -0500"
    .replace(/\s+[A-Z]{1,5}$/, "")          // remove " U" / " UTC" / " EST"
    .replace(/\.\d+$/, "")                  // remove fractional seconds
    .trim();
  d = new Date(stripped);
  if (!isNaN(d.getTime())) return d;
  // 3. Replace space separator with T for strict ISO parsing
  const isoLike = stripped.replace(" ", "T") + "Z";
  d = new Date(isoLike);
  if (!isNaN(d.getTime())) return d;
  return null;
}

function getRelativeTime(
  dateStr: string,
  t: (key: TranslationKey, values?: Record<string, string | number>) => string,
): string {
  if (!dateStr || dateStr === "Unknown") return "";
  try {
    const date = parseWhoisDate(dateStr);
    if (!date) return "";
    const now = new Date();
    const diffDays = Math.floor(
      (now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24),
    );
    if (diffDays < 0) {
      const abs = Math.abs(diffDays);
      if (abs < 30) return t("relative_time.in_days", { days: abs });
      if (abs < 365)
        return t("relative_time.in_months", { months: Math.floor(abs / 30) });
      return t("relative_time.in_years", { years: Math.floor(abs / 365) });
    }
    if (diffDays < 1) return t("relative_time.today");
    if (diffDays < 30) return t("relative_time.days_ago", { days: diffDays });
    if (diffDays < 365)
      return t("relative_time.months_ago", {
        months: Math.floor(diffDays / 30),
      });
    return t("relative_time.years_ago", { years: Math.floor(diffDays / 365) });
  } catch {
    return "";
  }
}

function formatDate(dateStr: string): string {
  if (!dateStr || dateStr === "Unknown") return "—";
  const d = parseWhoisDate(dateStr);
  if (!d) return dateStr.slice(0, 10) || dateStr; // best-effort: first 10 chars
  return d.toISOString().slice(0, 10); // always YYYY-MM-DD
}

/**
 * Translate DNSSEC field values and embedded technical terms.
 * For zh/zh-tw locales, known DNSSEC terms are replaced with Chinese equivalents.
 * For all other locales the original value is returned unchanged.
 */
function translateDnssecValue(value: string, locale: string): string {
  if (!locale.startsWith("zh")) return value;
  const isTraditional = locale === "zh-tw";

  // Simple whole-value mapping for common RDAP/WHOIS values
  const WHOLE: Record<string, string> = {
    unsigned: "未签名",
    signed: "已签名",
    signeddelegation: "已签名",
    yes: "已签名",
    no: "未签名",
  };
  const key = value.toLowerCase().replace(/[\s\-_]/g, "");
  if (WHOLE[key]) {
    const v = WHOLE[key];
    return isTraditional ? v.replace("签", "簽") : v;
  }

  // Substring replacement for values that contain multiple terms
  const SUBS: [RegExp, string, string][] = [
    // [pattern, simplified, traditional]
    [/\bZone Signing Key\b/gi, "区域签名密钥", "區域簽名金鑰"],
    [/\bZSK\b/g, "ZSK", "ZSK"],
    [/\bKey Signing Key\b/gi, "密钥签名密钥", "金鑰簽名金鑰"],
    [/\bKSK\b/g, "KSK", "KSK"],
    [/\bDS Record\b/gi, "委托签名记录", "委託簽名記錄"],
    [/\bRRSIG\b/g, "资源记录签名", "資源記錄簽名"],
    [/\bDNSKEY\b/g, "DNS 密钥记录", "DNS 金鑰記錄"],
    [/\bNSEC3\b/g, "下一安全记录3", "下一安全記錄3"],
    [/\bNSEC\b/g, "下一安全记录", "下一安全記錄"],
    [/\bValidating Resolver\b/gi, "验证解析器", "驗證解析器"],
    [/\bValidation\b/gi, "验证", "驗證"],
    [/\bTrust Anchor\b/gi, "信任锚", "信任錨"],
    [/\bChain of Trust\b/gi, "信任链", "信任鏈"],
    [/\bKey Rollover\b/gi, "密钥滚动", "金鑰滾動"],
    [/\bDenial of Existence\b/gi, "存在否定", "存在否定"],
    [/\bAlgorithm\b/gi, "算法", "演算法"],
    [/\bsignedDelegation\b/gi, "已签名", "已簽名"],
    [/\bsigned\b/gi, "已签名", "已簽名"],
    [/\bunsigned\b/gi, "未签名", "未簽名"],
    [/\bDNSSEC\b/g, "DNS 安全扩展", "DNS 安全延伸"],
  ];

  let result = value;
  for (const [pattern, simplified, traditional] of SUBS) {
    result = result.replace(pattern, isTraditional ? traditional : simplified);
  }
  return result;
}

function buildOgUrl(
  target: string,
  result?: WhoisAnalyzeResult | undefined,
  overrides?: { w?: number; h?: number; theme?: string },
): string {
  const params = new URLSearchParams();
  params.set("query", target);
  if (overrides?.w) params.set("w", String(overrides.w));
  if (overrides?.h) params.set("h", String(overrides.h));
  const themeVal =
    overrides?.theme ||
    (typeof window !== "undefined" &&
    document.documentElement.classList.contains("dark")
      ? "dark"
      : "light");
  if (themeVal === "dark") params.set("theme", "dark");

  // Embed compact WHOIS fields so the OG handler can skip the lookup fetch.
  if (result) {
    const r = result;
    const ok = (v: unknown): v is string =>
      typeof v === "string" && v.length > 0 && v !== "Unknown";
    if (ok(r.registrar))            params.set("reg", r.registrar.slice(0, 60));
    if (ok(r.creationDate))         params.set("cr",  r.creationDate.slice(0, 10));
    if (ok(r.expirationDate))       params.set("ex",  r.expirationDate.slice(0, 10));
    if (ok(r.updatedDate))          params.set("up",  r.updatedDate.slice(0, 10));
    if (r.remainingDays != null)    params.set("rd",  String(r.remainingDays));
    if (r.domainAge != null)        params.set("age", String(r.domainAge));
    if (Array.isArray(r.nameServers) && r.nameServers.length > 0)
      params.set("ns", r.nameServers.slice(0, 3).join(","));
    if (Array.isArray(r.status) && r.status.length > 0)
      params.set("st", r.status.slice(0, 4).map((s: { status: string }) => s.status).join(","));
    if (ok(r.registrantCountry))    params.set("co",  r.registrantCountry);
    if (ok(r.registrantOrganization))
      params.set("org", r.registrantOrganization.slice(0, 50));
    if (ok(r.dnssec))               params.set("dn",  r.dnssec.slice(0, 30));
    if (ok(r.whoisServer))          params.set("ws",  r.whoisServer.slice(0, 60));
  }

  return `/api/og?${params.toString()}`;
}

function WhoisHighlight({ content }: { content: string }) {
  const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`[\]]+)/;

  return (
    <>
      {content.split("\n").map((line, i) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={i} className="h-3" />;
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
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0 && colonIdx < 40) {
          const key = line.slice(0, colonIdx + 1);
          const value = line.slice(colonIdx + 1);
          return (
            <div key={i}>
              <span className="text-sky-600 dark:text-sky-400 font-medium">
                {key}
              </span>
              <span className="text-zinc-700 dark:text-zinc-200">
                {value.split(urlRegex).map((part, j) =>
                  urlRegex.test(part) ? (
                    <a
                      key={j}
                      href={part}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      {part}
                    </a>
                  ) : (
                    <span key={j}>{part}</span>
                  ),
                )}
              </span>
            </div>
          );
        }
        return (
          <div key={i} className="text-zinc-600 dark:text-zinc-300">
            {line.split(urlRegex).map((part, j) =>
              urlRegex.test(part) ? (
                <a
                  key={j}
                  href={part}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 dark:text-blue-400 hover:underline"
                >
                  {part}
                </a>
              ) : (
                <span key={j}>{part}</span>
              ),
            )}
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

function ResponsePanel({
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

function targetToDisplayName(target: string): string {
  try {
    const { domainToUnicode } = require("url");
    const hasAce = target
      .toLowerCase()
      .split(".")
      .some((l: string) => l.startsWith("xn--"));
    if (!hasAce) return target;
    const unicode = domainToUnicode(target.toLowerCase());
    return unicode && unicode !== target.toLowerCase() ? unicode : target;
  } catch {
    return target;
  }
}

export async function getServerSideProps(context: GetServerSidePropsContext) {
  const querySegments: string[] = (context.params?.query as string[]) ?? [];
  const origin = getOrigin(context.req);

  // ── Strip locale prefix from catch-all segments ───────────────────────────
  // URLs no longer include a locale prefix.  Old bookmarked URLs like
  // /zh/x.rw or /en/x.rw are 301-redirected to /x.rw for canonicality.
  const VALID_LOCALES = new Set(["en", "zh", "zh-tw", "de", "ru", "ja", "fr", "ko"]);
  const hasLocalePrefix =
    querySegments.length >= 2 && VALID_LOCALES.has(querySegments[0]);
  if (hasLocalePrefix) {
    const cleanPath = "/" + querySegments.slice(1).join("/");
    return { redirect: { destination: cleanPath, permanent: true } };
  }
  const effectiveSegments = querySegments;

  // ── Smart URL cleaning + canonical redirect ──────────────────────────────
  // Strip spaces first (handles URL-encoded spaces like %20 decoded to " ")
  // then run cleanDomain which strips protocols, paths, ports, auth, etc.
  const rawPath = effectiveSegments.join("/");
  const spacelessPath = rawPath.replace(/\s+/g, "");
  const target = cleanDomain(spacelessPath);
  const displayTarget = targetToDisplayName(target);

  const looksLikeQuery = (t: string) =>
    // Reject bare TLDs like ".cc" or ".com" — a leading dot means an empty
    // label before it, which is never a valid domain, IP, or ASN.
    !t.startsWith(".") &&
    (t.includes(".") ||
      /^AS\d+$/i.test(t) ||
      /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(t));

  // If cleaning changed the URL (spaces removed, protocol stripped, path trimmed…),
  // redirect to the canonical clean URL to avoid duplicate/broken results.
  if (looksLikeQuery(target) && `/${target}` !== `/${rawPath}`) {
    return { redirect: { destination: `/${target}`, permanent: false } };
  }

  // If it still doesn't look like any known query type, redirect to home
  // instead of a hard 404 — real app routes (/admin, /zh/about, etc.) are
  // handled by their own pages before they ever reach this catch-all.
  if (!looksLikeQuery(target)) {
    return { redirect: { destination: "/", permanent: false } };
  }

  // ── CN Reserved SLD early-return (before cleanDomain rewrites the query) ──
  // Some .cn functional SLDs (gov.cn, edu.cn, etc.) are mapped by the WHOIS
  // lib to their www.* equivalents so the lookup works.  We must intercept
  // BEFORE that mapping so the user sees "保留域名" instead of www.gov.cn data.
  const rawQuery = target.toLowerCase();
  const cnReservedSsr = getCnReservedSldInfo(rawQuery);
  if (cnReservedSsr) {
    const syntheticData: WhoisResult = {
      time: 0,
      status: true,
      cached: false,
      source: "whois",
      result: {
        ...initialWhoisAnalyzeResult,
        domain: rawQuery,
        status: [{ status: "registry-reserved", url: "" }],
        rawWhoisContent: `[CN Reserved] ${cnReservedSsr.descZh}`,
      },
    };
    // CN reserved SLDs are static — safe to cache at edge for 12 h
    context.res.setHeader("Cache-Control", "public, s-maxage=43200, stale-while-revalidate=86400");
    return {
      props: {
        data: JSON.parse(JSON.stringify(syntheticData)),
        target: rawQuery,
        displayTarget: targetToDisplayName(rawQuery),
        origin,
      },
    };
  }

  // Server-side TLD validation — reject clearly invalid domains before lookup
  if (!isValidDomainTld(target)) {
    return {
      props: {
        data: {
          time: 0,
          status: false,
          cached: false,
          error: "INVALID_DOMAIN_TLD",
        } as WhoisResult,
        target,
        displayTarget,
        origin,
      },
    };
  }

  // ── Parallel: require_login check + cache lookup ────────────────────────────
  // Both are independently fetchable: settings has a 30s in-process cache;
  // the WHOIS cache check is a quick Postgres read.  Firing them together
  // removes the sequential gap (~20-60ms) on every page request.
  const requireLoginPromise = getSettingServer("require_login");
  const ssrCachePromise = lookupWhoisWithCache(target, { cacheOnly: true }).catch(() => null);

  const requireLogin = await requireLoginPromise;
  if (requireLogin === "1") {
    const session = await getServerSession(context.req, context.res, authOptions);
    if (!session?.user?.email) {
      const callbackUrl = `/${target}`;
      return { redirect: { destination: `/login?callbackUrl=${encodeURIComponent(callbackUrl)}&msg=require_login`, permanent: false } };
    }
  }

  // Try to serve cached WHOIS data for SSR (gives search engines rich content).
  // cacheOnly=true means we only check Redis/L1 — if there's no cache hit we
  // return data:null immediately (no live lookup, no latency added).
  let ssrData: WhoisResult | null = null;
  try {
    const cached = await ssrCachePromise;
    if (cached?.cached === true && cached.status) {
      ssrData = cached;
    }
  } catch {
    ssrData = null;
  }

  // ── Edge / CDN caching for SSR HTML ─────────────────────────────────────
  // When require_login is OFF, allow Vercel's CDN to cache the rendered HTML
  // at the edge so repeat visitors don't hit the origin server.
  // - With WHOIS data: cache matches the data TTL (capped at 1 h) so the HTML
  //   is as fresh as the underlying WHOIS cache.
  // - Without WHOIS data (loading shell): short TTL so the shell is cached
  //   briefly; the client will fetch live data via /api/lookup regardless.
  // When require_login is ON, the response is user-specific — no edge caching.
  if (requireLogin !== "1") {
    const sMaxAge = ssrData?.cacheTtl && ssrData.cacheTtl > 0
      ? Math.min(ssrData.cacheTtl, 3600)
      : 30;
    const swr = Math.min(sMaxAge * 4, 86_400);
    context.res.setHeader(
      "Cache-Control",
      `public, s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`,
    );
  }

  return {
    props: {
      data: ssrData,
      target,
      displayTarget,
      origin,
    },
  };
}

// [lat, lng, zh name]
const GLOBE_COUNTRY_COORDS: Record<string, [number, number, string]> = {
  US: [38, -97, "美国"],   CA: [60, -95, "加拿大"],  MX: [23,-102, "墨西哥"],
  BR: [-15,-47, "巴西"],   AR: [-38,-63, "阿根廷"],  CL: [-33,-70, "智利"],
  GB: [52,  -2, "英国"],   DE: [51,  10, "德国"],     FR: [46,   2, "法国"],
  IT: [42,  12, "意大利"], ES: [40,  -3, "西班牙"],   NL: [52,   5, "荷兰"],
  SE: [59,  18, "瑞典"],   NO: [60,   8, "挪威"],     FI: [64,  26, "芬兰"],
  DK: [56,  10, "丹麦"],   CH: [47,   8, "瑞士"],     AT: [47,  14, "奥地利"],
  BE: [50,   4, "比利时"], PL: [52,  20, "波兰"],     CZ: [50,  15, "捷克"],
  RO: [46,  25, "罗马尼亚"],UA: [49,  32, "乌克兰"],  RU: [60, 100, "俄罗斯"],
  PT: [39,  -8, "葡萄牙"], GR: [39,  22, "希腊"],     HU: [47,  19, "匈牙利"],
  SK: [48,  19, "斯洛伐克"],LV: [57,  25, "拉脱维亚"],LT: [55,  24, "立陶宛"],
  EE: [59,  25, "爱沙尼亚"],IE: [53,  -8, "爱尔兰"],  IS: [65, -18, "冰岛"],
  CN: [35, 105, "中国"],   JP: [36, 138, "日本"],     KR: [37, 127, "韩国"],
  TW: [23, 121, "台湾"],   HK: [22, 114, "香港"],     SG: [ 1, 103, "新加坡"],
  IN: [20,  78, "印度"],   PK: [30,  70, "巴基斯坦"], BD: [24,  90, "孟加拉国"],
  TH: [15, 100, "泰国"],   VN: [15, 108, "越南"],     MY: [ 3, 109, "马来西亚"],
  ID: [-5, 120, "印度尼西亚"],PH:[13, 122, "菲律宾"],  AU: [-25, 133, "澳大利亚"],
  NZ: [-41, 174, "新西兰"],TR: [39,  35, "土耳其"],   SA: [24,  45, "沙特阿拉伯"],
  AE: [24,  54, "阿联酋"], IL: [31,  35, "以色列"],   IR: [32,  53, "伊朗"],
  EG: [27,  30, "埃及"],   NG: [10,   8, "尼日利亚"], ZA: [-29,  25, "南非"],
  KE: [ 1,  38, "肯尼亚"], MA: [32,  -6, "摩洛哥"],   TZ: [-6,  35, "坦桑尼亚"],
  ZW: [-20,  30, "津巴布韦"],UG: [1,  32, "乌干达"],   GH: [8,   -1, "加纳"],
  CY: [35,  33, "塞浦路斯"],MT: [36,  14, "马耳他"],  LU: [49,   6, "卢森堡"],
  HR: [45,  16, "克罗地亚"],RS: [44,  21, "塞尔维亚"],BG: [43,  25, "保加利亚"],
  MK: [41,  22, "北马其顿"],AL: [41,  20, "阿尔巴尼亚"],BA: [44, 17, "波黑"],
  ME: [42,  19, "黑山"],   SI: [46,  15, "斯洛文尼亚"],LI: [47, 10, "列支敦士登"],
  KZ: [48,  68, "哈萨克斯坦"],UZ: [41,  64, "乌兹别克斯坦"],VE:[8,-66,"委内瑞拉"],
  CO: [4,  -74, "哥伦比亚"],PE: [-10,-76, "秘鲁"],    EC: [-2,  -78, "厄瓜多尔"],
  UY: [-33, -56, "乌拉圭"],PY: [-23, -58, "巴拉圭"],  BO: [-17, -65, "玻利维亚"],
  PA: [9,  -80, "巴拿马"], CR: [10,  -84, "哥斯达黎加"],GT:[15,-90,"危地马拉"],
  CU: [22, -80, "古巴"],   DO: [19,  -70, "多米尼加"], JM: [18, -77, "牙买加"],
  PR: [18, -66, "波多黎各"],TT: [11,  -61, "特立尼达"],HT:[19,-72,"海地"],
  BY: [53,  28, "白俄罗斯"], MD: [47,  29, "摩尔多瓦"],
  GE: [42,  44, "格鲁吉亚"],AM: [40,  45, "亚美尼亚"],AZ: [40, 48, "阿塞拜疆"],
  AF: [33,  66, "阿富汗"], IQ: [33,  44, "伊拉克"],   SY: [35,  38, "叙利亚"],
  LB: [34,  36, "黎巴嫩"], JO: [31,  36, "约旦"],     KW: [29,  48, "科威特"],
  QA: [25,  51, "卡塔尔"], BH: [26,  51, "巴林"],     OM: [22,  57, "阿曼"],
  YE: [15,  48, "也门"],   LK: [7,   81, "斯里兰卡"], NP: [28,  84, "尼泊尔"],
  MM: [17,  96, "缅甸"],   KH: [12, 105, "柬埔寨"],   LA: [18, 103, "老挝"],
  MN: [46, 103, "蒙古"],   KP: [40, 127, "朝鲜"],     BN: [4,  115, "文莱"],
  MO: [22, 113, "澳门"],   TL: [-9, 126, "东帝汶"],   PG: [-6,  147, "巴布亚新几内亚"],
  FJ: [-18, 178, "斐济"],  VU: [-16, 168, "瓦努阿图"], WS: [-14,-172, "萨摩亚"],
  SC: [-5,   55, "塞舌尔"],MU: [-20,  57, "毛里求斯"], RE: [-21,  56, "留尼汪"],
  DJ: [12,   43, "吉布提"],ET: [9,    40, "埃塞俄比亚"],SO:[6,  46,"索马里"],
  SD: [13,   30, "苏丹"],  LY: [26,   17, "利比亚"],  TN: [34,    9, "突尼斯"],
  DZ: [28,    3, "阿尔及利亚"],CM: [6,12,"喀麦隆"],   AO: [-12,18, "安哥拉"],
  ZM: [-13,  30, "赞比亚"],MZ: [-18,  35, "莫桑比克"],BW: [-22,24, "博茨瓦纳"],
  NA: [-22,  18, "纳米比亚"],SN: [14, -14, "塞内加尔"],CI: [8,  -5, "科特迪瓦"],
  VI: [18,  -65, "美属维京群岛"],GU: [13, 144, "关岛"],
};

function CssGlobe({ countryCode }: { countryCode?: string }) {
  const [labelVisible, setLabelVisible] = React.useState(false);

  const code = countryCode ? countryCode.toUpperCase().trim() : null;
  const coords = code ? GLOBE_COUNTRY_COORDS[code] : null;

  // Calculate globe scroll position to center the country
  // One world = 240px wide (font-size 120px, SVG 4em = 480px → two worlds = 240px each)
  let svgMarginEm: number | undefined;
  let dotY = 60; // default center

  if (coords) {
    const [lat, lng] = coords;
    const xFirst = (lng + 180) / 360 * 240; // 0–240 px
    const marginPx = xFirst >= 60 ? -(xFirst - 60) : -(xFirst + 180);
    svgMarginEm = marginPx / 120;
    dotY = (90 - lat) / 180 * 120;
    // clamp so dot stays within 10–110px (visible inside circle)
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

      {/* Globe map */}
      <span className="nw-globe-wrap text-foreground/70">
        <svg
          className={coords ? undefined : "scrolling"}
          style={coords ? { marginLeft: `${svgMarginEm}em` } : undefined}
        >
          <use href="#nw-icon-repeated-world" />
        </svg>
      </span>

      {/* Country pulsing dot */}
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

/* ── Globally mainstream / well-known website domains ─────────────────── */
const MAINSTREAM_DOMAINS = new Set([
  // Search
  "google.com","bing.com","baidu.com","yahoo.com","yandex.com","duckduckgo.com","sogou.com","so.com","360.com",
  // Social
  "facebook.com","instagram.com","twitter.com","x.com","tiktok.com","linkedin.com","reddit.com","pinterest.com",
  "snapchat.com","weibo.com","qq.com","douyin.com","bilibili.com","zhihu.com","xiaohongshu.com","tieba.baidu.com",
  "tumblr.com","flickr.com","quora.com","discord.com","telegram.org","line.me","kakaotalk.com","vk.com",
  // Video
  "youtube.com","netflix.com","twitch.tv","hulu.com","vimeo.com","youku.com","iqiyi.com","v.qq.com","mango.tv",
  "disneyplus.com","primevideo.com","hbomax.com","crunchyroll.com","niconico.jp","dailymotion.com",
  // E-commerce
  "amazon.com","ebay.com","taobao.com","tmall.com","jd.com","aliexpress.com","shopify.com","etsy.com",
  "walmart.com","costco.com","target.com","rakuten.com","lazada.com","shopee.com","pinduoduo.com","wish.com",
  "zalando.com","flipkart.com","mercadolibre.com","mercadolibre.com.ar",
  // Tech
  "microsoft.com","apple.com","github.com","stackoverflow.com","cloudflare.com","adobe.com","oracle.com",
  "ibm.com","intel.com","nvidia.com","amd.com","openai.com","anthropic.com","huggingface.co","deepmind.com",
  "samsung.com","sony.com","lg.com","xiaomi.com","huawei.com","lenovo.com","dell.com","hp.com","asus.com",
  // Cloud/Dev
  "aws.amazon.com","digitalocean.com","heroku.com","netlify.com","vercel.com","railway.app","render.com",
  "npmjs.com","pypi.org","docker.com","kubernetes.io","linux.org","debian.org","ubuntu.com","archlinux.org",
  // Productivity/SaaS
  "dropbox.com","slack.com","zoom.us","notion.so","figma.com","canva.com","trello.com","asana.com",
  "atlassian.com","confluence.com","jira.atlassian.com","hubspot.com","salesforce.com","servicenow.com",
  "office.com","google.com","docs.google.com","drive.google.com","mail.google.com",
  // Finance
  "paypal.com","stripe.com","visa.com","mastercard.com","americanexpress.com","chase.com","wellsfargo.com",
  "bankofamerica.com","citibank.com","hsbc.com","alipay.com","wechatpay.com","patreon.com",
  // Media/News
  "bbc.com","cnn.com","nytimes.com","theguardian.com","reuters.com","bloomberg.com","ap.org",
  "xinhua.net","people.com.cn","sina.com.cn","163.com","sohu.com","ifeng.com","thepaper.cn",
  "wsj.com","ft.com","forbes.com","businessinsider.com","techcrunch.com","theverge.com","wired.com",
  // Lifestyle/Travel
  "airbnb.com","booking.com","tripadvisor.com","expedia.com","uber.com","lyft.com","doordash.com",
  "grubhub.com","yelp.com","zomato.com","swiggy.com","meituan.com","eleme.cn",
  // Music/Streaming
  "spotify.com","apple.com","pandora.com","soundcloud.com","tidal.com","deezer.com","qqmusic.qq.com",
  "netease.com","163.com",
  // Domain/Web infra
  "godaddy.com","namecheap.com","dynadot.com","name.com","porkbun.com","cloudflare.com","letsencrypt.org",
  "wordpress.com","wix.com","squarespace.com","webflow.com",
  // Knowledge
  "wikipedia.org","medium.com","substack.com","google.com",
  // Crypto
  "coinbase.com","binance.com","kraken.com","okx.com","bybit.com","metamask.io","etherscan.io",
  // Gaming
  "steam.com","steampowered.com","epicgames.com","ea.com","blizzard.com","roblox.com","minecraft.net",
  "nintendo.com","playstation.com","xbox.com",
  // Education
  "coursera.org","udemy.com","edx.org","khanacademy.org","duolingo.com","academia.edu","researchgate.net",
  "mit.edu","harvard.edu","stanford.edu","ox.ac.uk","cam.ac.uk",
  // Gov/Standards
  "iana.org","icann.org","w3.org","ietf.org","iso.org",
]);

const OFFICIAL_DOMAIN_DESC: Record<string, { name: string; zh: string; en: string }> = {
  // Search
  "google.com": { name: "Google", zh: "全球最大的搜索引擎，由 Alphabet 旗下 Google 公司运营，提供搜索、邮件、地图、云服务等全方位互联网服务。", en: "The world's largest search engine by Google (Alphabet), offering search, Gmail, Maps, and a broad suite of internet services." },
  "bing.com": { name: "Bing", zh: "微软旗下的全球搜索引擎，提供网页、图片、视频搜索及 AI 对话功能，是 Google 最大的竞争对手之一。", en: "Microsoft's global search engine offering web, image, and video search plus AI-powered chat capabilities." },
  "baidu.com": { name: "百度", zh: "中国最大的中文搜索引擎，由百度公司运营，提供搜索、地图、百科、AI 等互联网服务。", en: "China's largest Chinese-language search engine, offering search, maps, encyclopedia, and AI services." },
  "yahoo.com": { name: "Yahoo", zh: "雅虎旗下的综合门户网站，提供搜索、邮件、新闻、财经等互联网服务，曾是全球访问量最大的网站之一。", en: "Yahoo's flagship portal offering search, email, news, and finance—one of the earliest global internet giants." },
  "duckduckgo.com": { name: "DuckDuckGo", zh: "注重用户隐私的搜索引擎，不追踪个人搜索记录，在隐私保护领域享有极高口碑。", en: "A privacy-focused search engine that doesn't track personal searches, renowned for protecting user data." },
  "yandex.com": { name: "Yandex", zh: "俄罗斯最大的搜索引擎，同时提供地图、出行、云服务等业务，在俄语互联网市场占据主导地位。", en: "Russia's largest search engine and internet company, dominating the Russian-language web with maps, transport, and cloud services." },
  // Social
  "facebook.com": { name: "Facebook", zh: "全球最大的社交网络平台，由 Meta 公司运营，拥有超过 30 亿注册用户，提供社交、广告及 VR 业务。", en: "The world's largest social network operated by Meta, with over 3 billion users, offering social networking, advertising, and VR." },
  "instagram.com": { name: "Instagram", zh: "Meta 旗下的图片和短视频社交平台，全球月活用户超过 20 亿，以精美内容分享和网红经济著称。", en: "Meta's photo and short video social platform with over 2 billion monthly active users, known for visual content and influencer culture." },
  "twitter.com": { name: "Twitter / X", zh: "全球知名的微博客社交平台，现已更名为 X，由马斯克旗下 X Corp. 运营，以实时信息传播和公众讨论为核心。", en: "A globally influential microblogging platform, now rebranded as X by Elon Musk's X Corp., known for real-time information and public discourse." },
  "x.com": { name: "X (Twitter)", zh: "前身为 Twitter 的社交平台，由马斯克收购后更名为 X，致力于打造涵盖社交、支付、AI 的超级应用。", en: "Formerly Twitter, rebranded as X by Elon Musk, aiming to become a super-app covering social, payments, and AI." },
  "tiktok.com": { name: "TikTok", zh: "字节跳动旗下的全球短视频平台，拥有超过 10 亿月活用户，以算法驱动的个性化内容推荐著称。", en: "ByteDance's global short-video platform with over 1 billion monthly active users, known for algorithm-powered personalized content." },
  "linkedin.com": { name: "LinkedIn", zh: "全球最大的职业社交网络，由微软旗下运营，帮助职场人士建立人脉、寻找工作机会及分享行业见解。", en: "The world's largest professional social network, owned by Microsoft, helping professionals build connections and find career opportunities." },
  "reddit.com": { name: "Reddit", zh: "全球最大的社区讨论平台，由无数细分版块（Subreddit）组成，被称为「互联网前页」，覆盖几乎所有话题。", en: "The world's largest community discussion platform made up of countless subreddits, dubbed 'the front page of the internet.'" },
  "weibo.com": { name: "微博", zh: "中国最大的微博客社交平台，由新浪旗下微博公司运营，是中国公众讨论、明星互动和热点传播的核心舞台。", en: "China's largest microblogging platform by Weibo Corp., the central stage for public discussion, celebrity interaction, and trending topics in China." },
  "qq.com": { name: "腾讯QQ", zh: "腾讯公司旗下的综合互联网门户，提供即时通讯、邮件、游戏、新闻等服务，是中国最知名的互联网品牌之一。", en: "Tencent's comprehensive internet portal offering instant messaging, email, gaming, and news—one of China's most iconic internet brands." },
  "bilibili.com": { name: "哔哩哔哩", zh: "中国最大的弹幕视频网站，以年轻用户群体、ACG（动漫游戏）内容及独特的弹幕互动文化著称。", en: "China's largest bullet-comment video platform, renowned for its young audience, ACG (anime, comics, games) content, and unique danmaku culture." },
  "zhihu.com": { name: "知乎", zh: "中国最大的中文问答社区，汇聚各领域专家和知识分享者，提供高质量的知识讨论与内容创作平台。", en: "China's largest Chinese-language Q&A community, gathering experts across fields for high-quality knowledge sharing and discussion." },
  "discord.com": { name: "Discord", zh: "面向游戏玩家和社区用户的实时通讯平台，支持语音、视频、文字频道，已成为全球社区运营的首选工具。", en: "A real-time communication platform for gamers and communities, supporting voice, video, and text channels—a go-to tool for global community management." },
  // Video
  "youtube.com": { name: "YouTube", zh: "全球最大的视频分享与流媒体平台，隶属于 Google，每分钟上传视频超过 500 小时，月活用户逾 25 亿。", en: "The world's largest video sharing and streaming platform owned by Google, with over 500 hours of video uploaded per minute and 2.5 billion monthly active users." },
  "netflix.com": { name: "Netflix", zh: "全球领先的流媒体订阅服务，自制剧集、电影内容享誉全球，在超过 190 个国家和地区提供服务。", en: "The world's leading subscription streaming service, globally acclaimed for original series and films, available in over 190 countries." },
  "twitch.tv": { name: "Twitch", zh: "全球最大的游戏直播平台，由亚马逊旗下运营，也支持音乐、创意和日常生活类内容的直播。", en: "The world's largest game streaming platform owned by Amazon, also supporting music, creative, and IRL (in real life) streams." },
  "iqiyi.com": { name: "爱奇艺", zh: "百度旗下的中国领先在线视频平台，以海量影视剧、综艺和原创内容著称，被誉为「中国版 Netflix」。", en: "Baidu's leading Chinese online video platform, known for its vast library of drama, variety shows, and original content—often called 'the Netflix of China.'" },
  "youku.com": { name: "优酷", zh: "阿里巴巴旗下的中国知名视频平台，提供影视剧、综艺、体育等视频内容，与爱奇艺、腾讯视频并称中国三大视频网站。", en: "Alibaba's well-known Chinese video platform offering drama, variety, and sports content—one of China's 'big three' video sites alongside iQIYI and Tencent Video." },
  // E-commerce
  "amazon.com": { name: "Amazon", zh: "全球最大的电商平台，由贝佐斯创立，业务涵盖零售、云计算（AWS）、流媒体及 AI，年营收超 5000 亿美元。", en: "The world's largest e-commerce platform founded by Jeff Bezos, spanning retail, cloud computing (AWS), streaming, and AI with annual revenue exceeding $500 billion." },
  "ebay.com": { name: "eBay", zh: "全球知名的网络拍卖及购物平台，连接数亿买家与卖家，以二手商品交易和个人卖家生态著称。", en: "A globally renowned online auction and shopping platform connecting hundreds of millions of buyers and sellers, known for second-hand goods and individual sellers." },
  "taobao.com": { name: "淘宝", zh: "阿里巴巴旗下中国最大的C2C电商平台，汇聚数亿商品，是中国网购的代名词，拥有超过8亿活跃买家。", en: "Alibaba's largest C2C e-commerce platform in China, synonymous with online shopping in China with over 800 million active buyers." },
  "tmall.com": { name: "天猫", zh: "阿里巴巴旗下的B2C电商平台，专注于品牌商家入驻，为消费者提供正品保障的购物体验，是中国品牌电商的核心渠道。", en: "Alibaba's B2C e-commerce platform for brand merchants, providing consumers with a guaranteed-authentic shopping experience—China's leading brand retail channel." },
  "jd.com": { name: "京东", zh: "中国第二大综合电商平台，以自营商品和高效物流著称，同时提供金融、科技、健康等多元化服务。", en: "China's second-largest comprehensive e-commerce platform, known for its self-operated products and efficient logistics, alongside finance, tech, and health services." },
  "shopify.com": { name: "Shopify", zh: "全球领先的独立站电商平台，帮助商家快速搭建在线商店，支持超过 175 个国家的卖家运营业务。", en: "A leading global e-commerce platform that helps merchants quickly set up online stores, supporting sellers in over 175 countries." },
  // Tech
  "microsoft.com": { name: "Microsoft", zh: "全球最大的软件公司之一，提供 Windows 操作系统、Office 办公套件、Azure 云服务及 Xbox 游戏平台等产品。", en: "One of the world's largest software companies, offering Windows OS, Office suite, Azure cloud services, and the Xbox gaming platform." },
  "apple.com": { name: "Apple", zh: "全球市值最高的科技公司，以 iPhone、Mac、iPad、Apple Watch 等硬件产品及 iOS/macOS 生态系统闻名全球。", en: "The world's highest-valued tech company, globally renowned for iPhone, Mac, iPad, Apple Watch, and the iOS/macOS ecosystem." },
  "github.com": { name: "GitHub", zh: "全球最大的代码托管平台，由微软旗下运营，是开源软件和开发者协作的核心基础设施，拥有超过 1 亿注册开发者。", en: "The world's largest code hosting platform owned by Microsoft, core infrastructure for open-source software and developer collaboration with over 100 million registered developers." },
  "stackoverflow.com": { name: "Stack Overflow", zh: "全球最大的程序员问答社区，帮助开发者解决编程难题，是开发者日常工作中最依赖的技术问答平台之一。", en: "The world's largest developer Q&A community, helping programmers solve coding challenges and one of the most relied-upon technical resources for developers." },
  "cloudflare.com": { name: "Cloudflare", zh: "全球领先的网络安全与内容分发网络（CDN）服务商，为数百万网站提供 DDoS 防护、DNS 解析和性能优化服务。", en: "A global leader in cybersecurity and CDN services, providing DDoS protection, DNS resolution, and performance optimization for millions of websites." },
  "openai.com": { name: "OpenAI", zh: "全球领先的人工智能研究公司，ChatGPT、GPT-4 和 DALL·E 的开发者，引领了新一轮全球 AI 技术革命。", en: "The world's leading AI research company and developer of ChatGPT, GPT-4, and DALL·E, spearheading the latest global AI revolution." },
  "nvidia.com": { name: "NVIDIA", zh: "全球领先的图形处理器（GPU）制造商，其 GPU 芯片是人工智能训练和游戏图形渲染的核心硬件，市值跻身全球前三。", en: "The world's leading GPU manufacturer whose chips are essential for AI training and gaming graphics rendering, with a market cap among the global top three." },
  "samsung.com": { name: "Samsung", zh: "全球最大的智能手机和半导体制造商，韩国三星集团旗下，产品涵盖手机、芯片、家电及显示屏等多个领域。", en: "The world's largest smartphone and semiconductor manufacturer under South Korea's Samsung Group, spanning phones, chips, home appliances, and displays." },
  "huawei.com": { name: "华为", zh: "中国最大的科技企业之一，全球领先的通信设备和智能手机制造商，同时布局云计算、AI 及消费者终端业务。", en: "One of China's largest tech companies and a global leader in telecommunications equipment and smartphones, with a growing presence in cloud, AI, and consumer devices." },
  "xiaomi.com": { name: "小米", zh: "中国知名科技公司，以性价比极高的智能手机起家，现已扩展至智能家居、IoT 设备、电动汽车等多个领域。", en: "A leading Chinese tech company that started with high-value smartphones and has expanded into smart home, IoT devices, and electric vehicles." },
  // Cloud/Dev
  "digitalocean.com": { name: "DigitalOcean", zh: "面向开发者的云计算平台，以简洁易用的 VPS（Droplets）和 Kubernetes 服务著称，深受初创公司和独立开发者青睐。", en: "A developer-friendly cloud computing platform known for easy-to-use VPS (Droplets) and Kubernetes services, favored by startups and indie developers." },
  "vercel.com": { name: "Vercel", zh: "面向前端开发者的云部署平台，Next.js 框架的开发者，支持一键部署 Serverless 应用，以极致的开发者体验著称。", en: "A cloud deployment platform for frontend developers and the creator of Next.js, enabling one-click serverless app deployment with a world-class developer experience." },
  "docker.com": { name: "Docker", zh: "全球最流行的容器化平台，使开发者能够将应用及其依赖打包进可移植的容器中，是现代 DevOps 的核心工具。", en: "The world's most popular containerization platform, enabling developers to package apps and dependencies into portable containers—a cornerstone of modern DevOps." },
  "npmjs.com": { name: "npm", zh: "Node.js 生态系统的官方包管理平台，托管超过 200 万个 JavaScript 软件包，是全球最大的软件注册表。", en: "The official package management platform for the Node.js ecosystem, hosting over 2 million JavaScript packages—the world's largest software registry." },
  // Productivity/SaaS
  "notion.so": { name: "Notion", zh: "集笔记、数据库、项目管理于一体的一站式效率工具，以极强的灵活性和精美界面赢得全球数千万用户的青睐。", en: "An all-in-one productivity tool combining notes, databases, and project management, loved by tens of millions globally for its flexibility and beautiful interface." },
  "figma.com": { name: "Figma", zh: "全球最流行的基于浏览器的 UI/UX 设计协作工具，支持实时多人协作，已成为产品设计团队的行业标准。", en: "The world's most popular browser-based UI/UX design and collaboration tool, supporting real-time multiplayer editing—the industry standard for product design teams." },
  "slack.com": { name: "Slack", zh: "企业级团队即时通讯平台，以频道化的对话方式重塑职场沟通方式，现已并入 Salesforce 旗下。", en: "An enterprise team messaging platform that reimagined workplace communication through channels, now part of Salesforce." },
  "zoom.us": { name: "Zoom", zh: "全球领先的视频会议和在线协作平台，在新冠疫情期间迅速普及，成为远程办公和在线教育的代名词。", en: "The world's leading video conferencing and online collaboration platform, which surged to ubiquity during COVID-19 and became synonymous with remote work and online education." },
  "canva.com": { name: "Canva", zh: "面向普通用户的在线设计平台，提供海量模板和拖拽式设计工具，让没有专业设计背景的用户也能轻松制作精美图文内容。", en: "An online design platform for everyone, offering vast templates and drag-and-drop tools so anyone—without design experience—can create stunning visuals." },
  "dropbox.com": { name: "Dropbox", zh: "云存储与文件同步服务的先驱，帮助个人和团队在多设备间无缝同步、共享文件，是云存储领域的开创者之一。", en: "A pioneer in cloud storage and file syncing, helping individuals and teams seamlessly sync and share files across devices." },
  "salesforce.com": { name: "Salesforce", zh: "全球领先的客户关系管理（CRM）软件公司，以云端 SaaS 模式提供销售、服务、营销等全方位企业解决方案。", en: "The world's leading CRM software company, delivering cloud-based sales, service, and marketing solutions for enterprises of all sizes." },
  // Finance
  "paypal.com": { name: "PayPal", zh: "全球最知名的在线支付平台之一，支持跨境收付款、电商结算及个人转账，在全球超过 200 个市场提供服务。", en: "One of the world's most recognized online payment platforms, supporting cross-border payments, e-commerce checkout, and personal transfers in over 200 markets." },
  "stripe.com": { name: "Stripe", zh: "面向开发者的在线支付基础设施，以 API 优先的方式为全球数百万商家提供支付、订阅、欺诈检测等金融服务。", en: "A developer-first payment infrastructure company offering payments, subscriptions, and fraud detection via API for millions of businesses worldwide." },
  "alipay.com": { name: "支付宝", zh: "蚂蚁集团旗下的中国最大移动支付平台，拥有超过 10 亿用户，同时提供理财、信贷、保险等综合金融服务。", en: "Ant Group's largest mobile payment platform in China with over 1 billion users, also offering wealth management, lending, and insurance services." },
  // Media/News
  "bbc.com": { name: "BBC", zh: "英国广播公司的官方网站，全球最具影响力的公共媒体机构之一，提供英文及多语种的新闻、纪录片和娱乐内容。", en: "The official site of the British Broadcasting Corporation, one of the world's most influential public media organizations, offering news, documentaries, and entertainment in English and many languages." },
  "cnn.com": { name: "CNN", zh: "美国有线电视新闻网，全球领先的英文新闻媒体，以 24 小时滚动新闻直播和突发新闻报道著称。", en: "Cable News Network, a global leader in English-language news known for 24/7 rolling news coverage and breaking news reporting." },
  "nytimes.com": { name: "纽约时报", zh: "美国最具影响力的报纸之一，以深度调查报道和评论著称，数字版订阅用户超过 1000 万，是全球顶级新闻机构。", en: "One of the most influential American newspapers, renowned for in-depth investigative reporting and commentary, with over 10 million digital subscribers." },
  "bloomberg.com": { name: "Bloomberg", zh: "全球领先的金融数据与新闻媒体，为专业投资者和商界人士提供实时市场数据、金融分析和商业报道。", en: "A global leader in financial data and news media, providing real-time market data, financial analysis, and business reporting for professional investors and business leaders." },
  "reuters.com": { name: "路透社", zh: "全球最大的国际新闻通讯社之一，以客观公正的新闻报道著称，向全球数千家媒体机构提供实时新闻资讯。", en: "One of the world's largest international news agencies, renowned for objective reporting and providing real-time news to thousands of media organizations worldwide." },
  "xinhua.net": { name: "新华网", zh: "新华社旗下的官方门户网站，是中国最权威的国家级通讯社，负责发布重要政治、经济和国际新闻。", en: "The official portal of Xinhua News Agency, China's most authoritative state-level news agency, responsible for publishing major political, economic, and international news." },
  // Travel/Lifestyle
  "airbnb.com": { name: "Airbnb", zh: "全球最大的短租住宿共享平台，连接全球数百万房东与旅行者，提供从民宿到豪华别墅的多样化住宿选择。", en: "The world's largest short-term accommodation sharing platform, connecting millions of hosts and travelers worldwide with lodging options from homestays to luxury villas." },
  "booking.com": { name: "Booking.com", zh: "全球最大的在线旅行和住宿预订平台，覆盖超过 200 个国家和地区的数百万家酒店、公寓及其他住宿类型。", en: "The world's largest online travel and accommodation booking platform, covering millions of hotels, apartments, and other accommodations in over 200 countries." },
  "uber.com": { name: "Uber", zh: "全球最大的网约车平台，业务已扩展至外卖（Uber Eats）和货运领域，在全球超过 70 个国家的数百座城市运营。", en: "The world's largest ride-hailing platform, now also spanning food delivery (Uber Eats) and freight, operating in hundreds of cities across over 70 countries." },
  // Music
  "spotify.com": { name: "Spotify", zh: "全球最大的音乐流媒体平台，拥有超过 6 亿用户和 1 亿首曲目，以个性化推荐和播客功能引领数字音乐行业。", en: "The world's largest music streaming platform with over 600 million users and 100 million tracks, leading the digital music industry with personalized recommendations and podcasts." },
  // Domain/Web infra
  "godaddy.com": { name: "GoDaddy", zh: "全球最大的域名注册商之一，同时提供虚拟主机、建站工具和网络安全服务，管理超过 8000 万个域名。", en: "One of the world's largest domain registrars, also offering web hosting, website builders, and cybersecurity services, managing over 80 million domain names." },
  "namecheap.com": { name: "Namecheap", zh: "全球知名的域名注册商，以低价和优质客服著称，同时提供主机、SSL 证书和隐私保护等配套服务。", en: "A globally known domain registrar renowned for competitive pricing and quality support, also offering hosting, SSL certificates, and privacy protection." },
  "letsencrypt.org": { name: "Let's Encrypt", zh: "由 ISRG 运营的免费、自动化、开放的 SSL/TLS 证书颁发机构，为全球数亿网站提供 HTTPS 加密证书。", en: "A free, automated, and open Certificate Authority operated by ISRG, issuing HTTPS encryption certificates for hundreds of millions of websites worldwide." },
  // Knowledge
  "wikipedia.org": { name: "Wikipedia", zh: "全球最大的开放式百科全书，由维基媒体基金会运营，支持 300 多种语言，拥有超过 6000 万篇文章，任何人均可编辑。", en: "The world's largest open-content encyclopedia operated by the Wikimedia Foundation, supporting over 300 languages and 60 million articles editable by anyone." },
  "medium.com": { name: "Medium", zh: "全球知名的开放式写作与阅读平台，汇聚各领域作者发布深度文章，深受科技、创业和人文领域的读者喜爱。", en: "A globally known open publishing platform aggregating in-depth articles from writers across fields, popular among readers in tech, startups, and humanities." },
  // Crypto
  "coinbase.com": { name: "Coinbase", zh: "美国最大的合规加密货币交易所，在纳斯达克上市，提供比特币等主流数字资产的买卖、存储和钱包服务。", en: "The largest compliant cryptocurrency exchange in the US, listed on NASDAQ, offering buy, sell, store, and wallet services for Bitcoin and other major digital assets." },
  "binance.com": { name: "币安", zh: "全球交易量最大的加密货币交易所，提供现货、合约、理财等多种数字资产交易服务，支持数百种加密货币对。", en: "The world's largest cryptocurrency exchange by trading volume, offering spot, futures, and savings products across hundreds of digital asset pairs." },
  // Gaming
  "steampowered.com": { name: "Steam", zh: "全球最大的 PC 游戏数字发行平台，由 Valve 公司运营，拥有超过 5 万款游戏和 1.3 亿注册用户。", en: "The world's largest PC game digital distribution platform operated by Valve, with over 50,000 games and 130 million registered users." },
  "epicgames.com": { name: "Epic Games", zh: "《堡垒之夜》和虚幻引擎的开发商，同时运营 Epic Games Store 游戏平台，以免费赠送游戏的策略广为人知。", en: "Developer of Fortnite and Unreal Engine, also operating the Epic Games Store digital platform, known for its game giveaway strategy." },
  "roblox.com": { name: "Roblox", zh: "全球最大的用户生成游戏平台，深受青少年欢迎，玩家既可游玩他人创建的游戏，也可创建并发布自己的游戏世界。", en: "The world's largest user-generated gaming platform popular among younger audiences, where players can both play and create their own game worlds." },
  "nintendo.com": { name: "Nintendo", zh: "日本知名游戏公司，马里奥、塞尔达、宝可梦等世界级 IP 的创造者，也是 Switch 游戏主机的制造商。", en: "Japan's iconic gaming company, creator of world-class IPs including Mario, Zelda, and Pokémon, and manufacturer of the Nintendo Switch console." },
  "playstation.com": { name: "PlayStation", zh: "索尼旗下的全球知名游戏品牌，PlayStation 主机系列自 1994 年起引领家用游戏主机市场，拥有大量独占 3A 大作。", en: "Sony's globally iconic gaming brand. The PlayStation console series has led the home gaming console market since 1994, with a vast library of exclusive AAA titles." },
  // Education
  "coursera.org": { name: "Coursera", zh: "全球领先的在线教育平台，与斯坦福、谷歌、耶鲁等顶尖院校和企业合作，提供专业证书、学位和职业技能课程。", en: "A global leader in online education, partnering with top universities and companies like Stanford, Google, and Yale to offer professional certificates, degrees, and career skill courses." },
  "khanacademy.org": { name: "可汗学院", zh: "非营利性在线教育机构，提供数学、科学、编程等领域的免费课程，致力于为全球任何人提供免费、优质的教育资源。", en: "A non-profit online education platform offering free courses in math, science, and programming, committed to providing free, world-class education for anyone, anywhere." },
  "duolingo.com": { name: "Duolingo", zh: "全球最流行的语言学习应用，以游戏化学习方式和可爱的猫头鹰吉祥物著称，支持超过 40 种语言的学习。", en: "The world's most popular language learning app, known for its gamified learning approach and beloved owl mascot, supporting over 40 languages." },
  // Gov/Standards
  "iana.org": { name: "IANA", zh: "互联网号码分配局，负责全球 IP 地址、域名根区和互联网协议参数的协调与分配，是互联网基础架构的核心管理机构。", en: "The Internet Assigned Numbers Authority, responsible for coordinating global IP addresses, the domain name root zone, and Internet protocol parameters—a core internet governance body." },
  "icann.org": { name: "ICANN", zh: "互联网名称与数字地址分配机构，负责管理全球域名系统（DNS）政策、新顶级域（gTLD）批准及互联网地址资源分配。", en: "The Internet Corporation for Assigned Names and Numbers, governing global DNS policy, new gTLD approvals, and internet address resource allocation." },
  "w3.org": { name: "W3C", zh: "万维网联盟，HTML、CSS、SVG 等 Web 核心标准的制定机构，致力于引导万维网向开放、可访问、可互操作的方向发展。", en: "The World Wide Web Consortium, the body that sets core web standards including HTML, CSS, and SVG, guiding the web toward openness, accessibility, and interoperability." },
};

type RegistrationStatusType =
  | "registered"
  | "available"
  | "reserved"
  | "prohibited"
  | "hold"
  | "dispute"
  | "redemption"
  | "pending-delete";

const STATUS_LABELS: Record<RegistrationStatusType, { zh: string; en: string }> = {
  registered: { zh: "已注册", en: "Registered" },
  available: { zh: "未注册", en: "Available" },
  reserved: { zh: "保留域名", en: "Reserved" },
  prohibited: { zh: "禁止注册", en: "Prohibited" },
  hold: { zh: "暂停", en: "On Hold" },
  dispute: { zh: "争议中", en: "In Dispute" },
  redemption: { zh: "赎回期", en: "Redemption" },
  "pending-delete": { zh: "待删除", en: "Pending Delete" },
};

function getDomainRegistrationStatus(
  result: WhoisAnalyzeResult,
  locale = "en",
): {
  type: RegistrationStatusType;
  label: string;
  color: string;
  dotColor: string;
  isPremiumReserved: boolean;
} {
  const isZh = locale.startsWith("zh");

  // EPP lock statuses that contain "prohibited" in their name but are NOT
  // about registration prohibition — they protect already-registered domains.
  const EPP_PROHIBITED_LOCK_STATUSES = new Set([
    "clientdeleteprohibited",
    "clienttransferprohibited",
    "clientrenewprohibited",
    "clientupdateprohibited",
    "serverdeleteprohibited",
    "servertransferprohibited",
    "serverrenewprohibited",
    "serverupdateprohibited",
    // hyphenated / space variants used by some ccTLDs
    "client-delete-prohibited",
    "client-transfer-prohibited",
    "client-renew-prohibited",
    "client-update-prohibited",
    "server-delete-prohibited",
    "server-transfer-prohibited",
    "server-renew-prohibited",
    "server-update-prohibited",
  ]);

  const allStatusCodes = result.status.map((s) => s.status.toLowerCase().trim());
  const allStatusText = allStatusCodes.join(" ");

  // Build a separate text excluding EPP lock statuses for the prohibit check
  // so that "clientTransferProhibited" / "client transfer prohibited" /
  // "client-transfer-prohibited" do not trigger "禁止注册".
  // We check THREE forms of each code: the raw first-word, the full hyphenated
  // string (some ccTLDs emit "client-delete-prohibited"), and the concatenated
  // no-separator form (TWNIC WHOIS emits "client delete prohibited" with spaces).
  const prohibitCheckText = allStatusCodes
    .filter((s) => {
      const firstWord = s.split(/\s+/)[0];            // "client" from "client delete prohibited"
      const noSep = s.replace(/[\s_\-]/g, "");        // "clientdeleteprohibited"
      return (
        !EPP_PROHIBITED_LOCK_STATUSES.has(firstWord) &&
        !EPP_PROHIBITED_LOCK_STATUSES.has(noSep)
      );
    })
    .join(" ");

  // ── Raw content scan (safety net for RDAP and exotic ccTLD WHOIS formats) ───
  // Some registries embed state as free text in WHOIS/RDAP rather than EPP
  // codes. Scan the raw content with specific phrases to capture these signals.
  const rawContent = [
    typeof result.rawWhoisContent === "string" ? result.rawWhoisContent : "",
    result.rawRdapContent
      ? typeof result.rawRdapContent === "string"
        ? result.rawRdapContent
        : JSON.stringify(result.rawRdapContent)
      : "",
  ]
    .join("\n")
    .toLowerCase();

  // ── RESERVED — mirrors common_parser.ts syntheticReserved exactly ───────────
  const rawHasReserved =
    // English free-text phrases
    rawContent.includes("reserved name") ||
    rawContent.includes("this name is reserved") ||
    rawContent.includes("is a reserved name") ||
    rawContent.includes("domain is reserved") ||
    rawContent.includes("this domain is reserved") ||
    rawContent.includes("domain name is reserved") ||
    rawContent.includes("reserved by the registry") ||
    rawContent.includes("registry reserved") ||
    rawContent.includes("reserved-name") ||
    rawContent.includes("reserved domain") ||
    rawContent.includes("in the reserved list") ||
    rawContent.includes("on the reserved list") ||
    rawContent.includes("is in the reserved list") ||
    rawContent.includes("is on the reserved list") ||
    rawContent.includes("has been reserved") ||
    rawContent.includes("name is reserved") ||
    rawContent.includes("is reserved for") ||
    rawContent.includes("is reserved by") ||
    rawContent.includes("reserved for registry") ||
    rawContent.includes("reserved for the registry") ||
    rawContent.includes("registry has reserved") ||
    rawContent.includes("registry hold") ||
    rawContent.includes("held by the registry") ||
    rawContent.includes("domain is held") ||
    rawContent.includes("being held by") ||
    rawContent.includes("reserved for future use") ||
    rawContent.includes("reserved for official use") ||
    rawContent.includes("reserved for this registry") ||
    rawContent.includes("reserved at the registry") ||
    rawContent.includes("sunrise reserved") ||
    rawContent.includes("reserved for sunrise") ||
    rawContent.includes("reserved for landrush") ||
    rawContent.includes("landrush reserved") ||
    // Withheld — Donuts, Radix, ICM, Minds + Machines new gTLDs
    rawContent.includes("withheld") ||
    rawContent.includes("withheld by registry") ||
    rawContent.includes("withheld for registry") ||
    rawContent.includes("registry withheld") ||
    rawContent.includes("name withheld") ||
    rawContent.includes("domain withheld") ||
    /\bstatus\s*:\s*withheld\b/.test(rawContent) ||
    // IANA / ICANN delegations — "not delegated" / "not assigned"
    rawContent.includes("not delegated") ||
    rawContent.includes("not-delegated") ||
    rawContent.includes("not assigned") ||
    rawContent.includes("iana reserved") ||
    rawContent.includes("iana hold") ||
    rawContent.includes("blocked by iana") ||
    rawContent.includes("has not been delegated") ||
    rawContent.includes("this tld has not") ||
    /\bstatus\s*:\s*not.delegated\b/.test(rawContent) ||
    // Available only by specific request (some ccTLDs, e.g. .uk)
    rawContent.includes("available-by-request") ||
    rawContent.includes("available by request") ||
    rawContent.includes("registration by request only") ||
    rawContent.includes("available to specific registrants") ||
    rawContent.includes("restricted to qualified") ||
    // "Allocated" (RIPE/RIR context, some country ccTLDs)
    /\bstatus\s*:\s*allocated\b/.test(rawContent) ||
    // Blocked by registry (for reserved/sensitive strings — not abuse block)
    /\bstatus\s*:\s*blocked\b/.test(rawContent) ||
    rawContent.includes("blocked for registration") ||
    rawContent.includes("registry block") ||
    // RDAP "remarks" text: "This domain has not been delegated"
    rawContent.includes("not been delegated") ||
    // Structured field patterns (EURID .eu, IIS .se/.nu, Donuts, CentralNic, CIRA, etc.)
    /\bstatus\s*:\s*reserved\b/.test(rawContent) ||
    /\bstate\s*:\s*reserved\b/.test(rawContent) ||
    /\bdomainstatus\s*:\s*reserved\b/.test(rawContent) ||
    // German (DENIC .de): "% Status: reserviert"
    rawContent.includes("reserviert") ||
    /\bstatus\s*:\s*reserviert\b/.test(rawContent) ||
    // Czech/Slovak (CZ.NIC .cz .sk): "rezervovan: ano"
    rawContent.includes("rezervovan") ||
    // French ccTLD (AFNIC .fr .re .pm .tf .wf .yt)
    rawContent.includes("réservé") ||
    rawContent.includes("domaine réservé") ||
    rawContent.includes("domaine reserve") ||
    /\bstatus\s*:\s*r[eé]serv[eé]\b/.test(rawContent) ||
    // Spanish ccTLD (.es, .ar, .mx, .co, .cl, .pe, .uy, etc.)
    rawContent.includes("reservado") ||
    rawContent.includes("dominio reservado") ||
    /\bestado\s*:\s*reservado\b/.test(rawContent) ||
    // Portuguese (.pt / .br)
    rawContent.includes("domínio reservado") ||
    // Italian (NIC.it .it): RISERVATO
    /\bstatus\s*:\s*riservato\b/.test(rawContent) ||
    rawContent.includes("dominio riservato") ||
    // Swedish (IIS .se .nu): "state: reserverad"
    /\bstate\s*:\s*reserverad\b/.test(rawContent) ||
    /\bstatus\s*:\s*reserverad\b/.test(rawContent) ||
    rawContent.includes("domännamnet är reserverat") ||
    // Norwegian (Norid .no)
    /\bstatus\s*:\s*reservert\b/.test(rawContent) ||
    rawContent.includes("domenet er reservert") ||
    // Danish (DK Hostmaster .dk)
    /\bstatus\s*:\s*reserveret\b/.test(rawContent) ||
    rawContent.includes("domænet er reserveret") ||
    // Polish (DNS Polska / NASK .pl)
    /\bstatus\s*:\s*zarezerwowany\b/.test(rawContent) ||
    rawContent.includes("domena zarezerwowana") ||
    // Dutch (SIDN .nl)
    /\bstatus\s*:\s*gereserveerd\b/.test(rawContent) ||
    rawContent.includes("domein is gereserveerd") ||
    // Finnish (Traficom .fi): "varattu"
    /\bstatus\s*:\s*varattu\b/.test(rawContent) ||
    rawContent.includes("verkkotunnus varattu") ||
    rawContent.includes("on varattu") ||
    // Hungarian (.hu): "fenntartott"
    /\bstatus\s*:\s*fenntartott\b/.test(rawContent) ||
    rawContent.includes("fenntartott tartomány") ||
    // Romanian (RoTLD .ro): "rezervat"
    /\bstatus\s*:\s*rezervat\b/.test(rawContent) ||
    rawContent.includes("domeniu rezervat") ||
    // Turkish (NIC.TR .tr): "rezerve"
    /\bstatus\s*:\s*rezerve\b/.test(rawContent) ||
    rawContent.includes("alan adı rezerve") ||
    // Greek (ICS.FORTH .gr)
    rawContent.includes("δεσμευμένο") ||
    rawContent.includes("δεσμεύτηκε") ||
    // Bulgarian (.bg)
    rawContent.includes("резервиран") ||
    // Serbian / Bosnian / Croatian (.rs / .ba / .hr)
    rawContent.includes("rezervisano") ||
    rawContent.includes("rezervirano") ||
    // Latvian (NIC.lv .lv)
    rawContent.includes("rezervēts") ||
    // Lithuanian (DOMREG .lt)
    rawContent.includes("rezervuotas") ||
    // Estonian (EIS .ee)
    rawContent.includes("reserveeritud") ||
    // Slovak (.sk)
    rawContent.includes("rezervovaný") ||
    // Russian (.ru / .рф) — non-Latin, safe direct includes
    rawContent.includes("зарезервирован") ||
    rawContent.includes("зарезервировано") ||
    rawContent.includes("зарезервирована") ||
    rawContent.includes("домен зарезервирован") ||
    rawContent.includes("заблокирован") ||
    // Ukrainian (.ua)
    rawContent.includes("зарезервовано") ||
    rawContent.includes("домен зарезервовано") ||
    // Japanese (.jp — JPRS): bilingual WHOIS
    rawContent.includes("予約済み") ||
    rawContent.includes("利用停止") ||
    rawContent.includes("登録停止") ||
    // Korean (.kr — KRNIC)
    rawContent.includes("예약됨") ||
    rawContent.includes("예약된") ||
    rawContent.includes("예약된 도메인") ||
    // Arabic ccTLDs (.sa / .ae / .eg / .iq / .ly)
    rawContent.includes("محجوز") ||
    rawContent.includes("النطاق محجوز") ||
    rawContent.includes("مخصص") ||
    // Hebrew (.il — ISOC-IL)
    rawContent.includes("שמור") ||
    rawContent.includes("הדומיין שמור") ||
    // Traditional Chinese (.tw / .hk)
    rawContent.includes("保留網域") ||
    rawContent.includes("已保留") ||
    // Simplified Chinese (CNNIC, TELE-INFO, ZDNS)
    rawContent.includes("保留域名") ||
    rawContent.includes("已被保留") ||
    rawContent.includes("注册局保留") ||
    rawContent.includes("保留中") ||
    rawContent.includes("该域名已保留") ||
    rawContent.includes("域名已锁定") ||
    // Standalone "reserved" on its own line (TWNIC / NZRS)
    /(?:^|\n)\s*reserved\s*(?:\n|$)/.test(rawContent);

  // ── PREMIUM RESERVED — mirrors common_parser.ts syntheticPremiumReserved ────
  const rawHasPremiumReserved =
    rawContent.includes("premium domain") ||
    rawContent.includes("premium name") ||
    rawContent.includes("premium price") ||
    rawContent.includes("premium pricing") ||
    rawContent.includes("premium listing") ||
    rawContent.includes("registry premium") ||
    rawContent.includes("available at a premium") ||
    rawContent.includes("this is a premium") ||
    rawContent.includes("premium registration") ||
    rawContent.includes("early access program") ||
    rawContent.includes("early access pricing") ||
    rawContent.includes("early access period") ||
    rawContent.includes("available for purchase") ||
    rawContent.includes("available for sale") ||
    rawContent.includes("this name is for sale") ||
    rawContent.includes("domain is for sale") ||
    rawContent.includes("make an offer") ||
    rawContent.includes("aftermarket") ||
    rawContent.includes("reserve price") ||
    rawContent.includes("starting bid") ||
    rawContent.includes("minimum bid") ||
    rawContent.includes("please contact the registry") ||
    rawContent.includes("contact the registry to") ||
    rawContent.includes("contact the registry for") ||
    rawContent.includes("contact your registrar to") ||
    rawContent.includes("contact your registrar for") ||
    rawContent.includes("enquire about this domain") ||
    rawContent.includes("inquire about this domain") ||
    rawContent.includes("may be available for purchase") ||
    rawContent.includes("can be acquired") ||
    rawContent.includes("reach out to the registry");

  // ── PROHIBITED — mirrors common_parser.ts syntheticProhibited ────────────
  const rawHasProhibited =
    rawContent.includes("registration is prohibited") ||
    rawContent.includes("registration prohibited") ||
    rawContent.includes("cannot be registered") ||
    rawContent.includes("registration not possible") ||
    rawContent.includes("registration not available") ||
    rawContent.includes("not available for registration") ||
    rawContent.includes("not eligible for registration") ||
    rawContent.includes("not open for registration") ||
    rawContent.includes("not open for general registration") ||
    rawContent.includes("not open to general registrations") ||
    rawContent.includes("not currently open for registration") ||
    rawContent.includes("not available for public registration") ||
    rawContent.includes("not permitted to register") ||
    rawContent.includes("registration is not permitted") ||
    rawContent.includes("registrations are not permitted") ||
    rawContent.includes("registrations not permitted") ||
    rawContent.includes("not accepting registrations") ||
    rawContent.includes("registrations not accepted") ||
    rawContent.includes("no registrations are accepted") ||
    rawContent.includes("does not accept registrations") ||
    rawContent.includes("cannot be publicly registered") ||
    rawContent.includes("prohibited string") ||
    rawContent.includes("prohibited by policy") ||
    rawContent.includes("policy prohibited") ||
    rawContent.includes("not available for public use") ||
    rawContent.includes("registrar banned") ||
    rawContent.includes("registry banned") ||
    rawContent.includes("blacklisted") ||
    // Additional English patterns
    rawContent.includes("registration is blocked") ||
    rawContent.includes("domain is blocked") ||
    rawContent.includes("name is blocked") ||
    rawContent.includes("blackholed") ||
    rawContent.includes("registration disallowed") ||
    rawContent.includes("registration is disallowed") ||
    rawContent.includes("registrations are disallowed") ||
    rawContent.includes("registration has been blocked") ||
    rawContent.includes("domain name cannot be registered") ||
    rawContent.includes("name cannot be registered") ||
    rawContent.includes("does not allow registrations") ||
    rawContent.includes("registry does not allow") ||
    rawContent.includes("ineligible for registration") ||
    rawContent.includes("registration ineligible") ||
    rawContent.includes("this string is prohibited") ||
    rawContent.includes("this label is prohibited") ||
    rawContent.includes("this domain cannot be registered") ||
    rawContent.includes("cannot register this domain") ||
    rawContent.includes("registration of this name is not") ||
    rawContent.includes("not available at this time") ||
    rawContent.includes("agency forbidden") ||
    rawContent.includes("forbidden by") ||
    /\bstatus\s*:\s*prohibited\b/.test(rawContent) ||
    /\bstatus\s*:\s*forbidden\b/.test(rawContent) ||
    /\bstatus\s*:\s*blocked\-prohibited\b/.test(rawContent) ||
    // Simplified / Traditional Chinese
    rawContent.includes("禁止注册") ||
    rawContent.includes("不开放注册") ||
    rawContent.includes("不可注册") ||
    rawContent.includes("禁止使用") ||
    rawContent.includes("禁止域名") ||
    rawContent.includes("限制注册") ||
    rawContent.includes("禁止") && rawContent.includes("注册") ||
    // Russian / Ukrainian
    rawContent.includes("запрещена регистрация") ||
    rawContent.includes("регистрация запрещена") ||
    rawContent.includes("реєстрація заборонена") ||
    rawContent.includes("реєстрація не дозволена") ||
    rawContent.includes("регистрация недоступна") ||
    // German (.de / .at / .ch)
    rawContent.includes("registrierung nicht möglich") ||
    rawContent.includes("nicht registrierbar") ||
    rawContent.includes("gesperrte zeichenfolge") ||
    /\bstatus\s*:\s*verboten\b/.test(rawContent) ||
    // French
    rawContent.includes("enregistrement interdit") ||
    rawContent.includes("non disponible à l'enregistrement") ||
    // Spanish
    rawContent.includes("registro prohibido") ||
    rawContent.includes("no se puede registrar") ||
    rawContent.includes("no disponible para registro") ||
    // Italian
    /\bstatus\s*:\s*vietato\b/.test(rawContent) ||
    rawContent.includes("registrazione vietata") ||
    rawContent.includes("non registrabile") ||
    // Portuguese
    rawContent.includes("registro não permitido") ||
    rawContent.includes("domínio proibido") ||
    // Dutch
    rawContent.includes("registratie niet mogelijk") ||
    rawContent.includes("niet registreerbaar") ||
    // Polish
    rawContent.includes("rejestracja zabroniona") ||
    rawContent.includes("niedostępne do rejestracji") ||
    // Japanese
    rawContent.includes("登録不可") ||
    rawContent.includes("登録制限") ||
    rawContent.includes("利用不可") ||
    rawContent.includes("申請不可") ||
    // Korean
    rawContent.includes("등록불가") ||
    rawContent.includes("등록 금지") ||
    rawContent.includes("등록 불가능") ||
    // Arabic
    rawContent.includes("محظور") ||
    rawContent.includes("التسجيل محظور") ||
    rawContent.includes("غير متاح للتسجيل") ||
    // Hebrew
    rawContent.includes("אסור לרישום") ||
    rawContent.includes("חסום לרישום") ||
    // Turkish
    rawContent.includes("kayıt yasak") ||
    rawContent.includes("tescil edilemez") ||
    /\bblocked\s+by\s+(?:registry|registrar)\b/.test(rawContent) ||
    /\bregistration\s+blocked\b/.test(rawContent);

  // ── SUSPENDED / HOLD ─────────────────────────────────────────────────────
  const rawHasSuspended =
    rawContent.includes("suspended by registry") ||
    rawContent.includes("suspended by registrar") ||
    rawContent.includes("registry-suspended") ||
    rawContent.includes("domain is suspended") ||
    rawContent.includes("domain suspended") ||
    rawContent.includes("domain has been suspended") ||
    rawContent.includes("account suspended") ||
    rawContent.includes("abuse suspension") ||
    rawContent.includes("abuse hold") ||
    rawContent.includes("fraud hold") ||
    rawContent.includes("compliance hold") ||
    rawContent.includes("billing suspension") ||
    rawContent.includes("billing hold") ||
    rawContent.includes("payment hold") ||
    rawContent.includes("domain is on hold") ||
    rawContent.includes("domain on hold") ||
    rawContent.includes("placed on hold") ||
    rawContent.includes("put on hold") ||
    rawContent.includes("account on hold") ||
    rawContent.includes("account hold") ||
    rawContent.includes("registrar hold") ||
    rawContent.includes("agency hold") ||
    rawContent.includes("legal hold") ||
    rawContent.includes("judicial hold") ||
    rawContent.includes("government hold") ||
    rawContent.includes("seized by") ||
    rawContent.includes("domain seized") ||
    rawContent.includes("domain has been seized") ||
    rawContent.includes("confiscated by") ||
    rawContent.includes("domain confiscated") ||
    rawContent.includes("law enforcement hold") ||
    rawContent.includes("enforcement hold") ||
    rawContent.includes("frozen by") ||
    rawContent.includes("domain frozen") ||
    rawContent.includes("domain has been frozen") ||
    rawContent.includes("domain is frozen") ||
    rawContent.includes("suspended for") ||
    rawContent.includes("suspended due to") ||
    rawContent.includes("temporarily suspended") ||
    rawContent.includes("domain is temporarily") ||
    rawContent.includes("temporarily unavailable") ||
    rawContent.includes("domain is inactive") ||
    /\bstatus\s*:\s*(?:hold|on-hold|onhold|inactive)\b/.test(rawContent) ||
    // German (.de / .at / .ch)
    rawContent.includes("gesperrt") ||
    rawContent.includes("sperrung") ||
    rawContent.includes("domain gesperrt") ||
    rawContent.includes("beschlagnahmt") ||
    rawContent.includes("eingefroren") ||
    // Spanish (.es / .ar / .mx / ...)
    rawContent.includes("suspendido") ||
    rawContent.includes("dominio suspendido") ||
    rawContent.includes("en espera") ||
    rawContent.includes("confiscado") ||
    rawContent.includes("embargado") ||
    // French (.fr / .be / .ch / ...)
    rawContent.includes("suspendu") ||
    rawContent.includes("domaine suspendu") ||
    rawContent.includes("bloqué") ||
    rawContent.includes("saisi") ||
    rawContent.includes("gelé") ||
    // Portuguese (.pt / .br)
    rawContent.includes("suspenso") ||
    rawContent.includes("domínio suspenso") ||
    rawContent.includes("congelado") ||
    rawContent.includes("apreendido") ||
    // Italian (NIC.it .it)
    /\bstatus\s*:\s*sospeso\b/.test(rawContent) ||
    rawContent.includes("dominio sospeso") ||
    rawContent.includes("bloccato") ||
    rawContent.includes("sequestrato") ||
    // Dutch (.nl)
    rawContent.includes("opgeschort") ||
    rawContent.includes("domein opgeschort") ||
    rawContent.includes("bevroren") ||
    rawContent.includes("in beslag") ||
    // Polish (.pl)
    rawContent.includes("zawieszony") ||
    rawContent.includes("domena zawieszona") ||
    rawContent.includes("zablokowany") ||
    // Finnish (.fi)
    rawContent.includes("keskeytetty") ||
    rawContent.includes("jäädytetty") ||
    // Swedish (.se)
    rawContent.includes("spärrad") ||
    rawContent.includes("inaktiv") ||
    // Norwegian (.no)
    rawContent.includes("suspendert") ||
    // Danish (.dk)
    rawContent.includes("suspenderet") ||
    rawContent.includes("deaktiveret") ||
    // Romanian (.ro)
    rawContent.includes("suspendat") ||
    // Hungarian (.hu)
    rawContent.includes("felfüggesztett") ||
    // Turkish (.tr)
    rawContent.includes("askıya alındı") ||
    rawContent.includes("donduruldu") ||
    // Greek (.gr)
    rawContent.includes("ανεσταλμένο") ||
    rawContent.includes("αδρανές") ||
    // Russian (.ru / .рф)
    rawContent.includes("приостановлен") ||
    rawContent.includes("приостановлено") ||
    rawContent.includes("домен заблокирован") ||
    rawContent.includes("изъят") ||
    rawContent.includes("заморожен") ||
    // Ukrainian (.ua)
    rawContent.includes("призупинено") ||
    rawContent.includes("заморожено") ||
    // Japanese (.jp)
    rawContent.includes("停止中") ||
    rawContent.includes("利用停止") ||
    rawContent.includes("凍結") ||
    rawContent.includes("差し押さえ") ||
    // Korean (.kr)
    rawContent.includes("정지됨") ||
    rawContent.includes("사용 정지") ||
    rawContent.includes("동결") ||
    // Arabic
    rawContent.includes("موقوف") ||
    rawContent.includes("معلق") ||
    rawContent.includes("مجمد") ||
    rawContent.includes("مضبوط") ||
    // Hebrew
    rawContent.includes("מושעה") ||
    rawContent.includes("קפוא") ||
    // Chinese (Simplified)
    rawContent.includes("已暂停") ||
    rawContent.includes("域名暂停") ||
    rawContent.includes("已停用") ||
    rawContent.includes("暂停使用") ||
    rawContent.includes("已冻结") ||
    rawContent.includes("冻结域名") ||
    rawContent.includes("被扣押") ||
    rawContent.includes("被没收") ||
    /(?:^|\n)\s*suspended\s*(?:\n|$)/.test(rawContent);

  // ── DISPUTE ─────────────────────────────────────────────────────────────────
  const rawHasDispute =
    // UDRP (Uniform Domain-Name Dispute-Resolution Policy) — most common
    rawContent.includes("udrp") ||
    rawContent.includes("uniform domain-name dispute") ||
    rawContent.includes("udrp proceeding") ||
    rawContent.includes("udrp complaint") ||
    rawContent.includes("udrp-lock") ||
    rawContent.includes("udrp lock") ||
    rawContent.includes("locked-udrp") ||
    rawContent.includes("locked for udrp") ||
    rawContent.includes("locked during udrp") ||
    rawContent.includes("pending udrp") ||
    rawContent.includes("udrp transfer") ||
    rawContent.includes("udrp decision") ||
    // General dispute
    rawContent.includes("domain dispute") ||
    rawContent.includes("name dispute") ||
    rawContent.includes("in dispute") ||
    rawContent.includes("under dispute") ||
    rawContent.includes("dispute in progress") ||
    rawContent.includes("dispute pending") ||
    rawContent.includes("subject to dispute") ||
    rawContent.includes("currently disputed") ||
    rawContent.includes("domain conflict") ||
    // DRP / ADR variants (EU/ICANN alternative dispute resolution)
    rawContent.includes("adr proceeding") ||
    rawContent.includes("alternative dispute") ||
    rawContent.includes("domain resolution") ||
    rawContent.includes("drp proceeding") ||
    rawContent.includes("icann drp") ||
    // Trademark / legal dispute
    rawContent.includes("trademark dispute") ||
    rawContent.includes("trademark conflict") ||
    rawContent.includes("trademark complaint") ||
    rawContent.includes("trademark objection") ||
    rawContent.includes("legal dispute") ||
    rawContent.includes("legal proceedings") ||
    rawContent.includes("legal action") ||
    rawContent.includes("court order") ||
    rawContent.includes("court ordered") ||
    rawContent.includes("court proceeding") ||
    rawContent.includes("arbitration") ||
    rawContent.includes("pending arbitration") ||
    rawContent.includes("in arbitration") ||
    rawContent.includes("dispute resolution") ||
    rawContent.includes("locked for dispute") ||
    rawContent.includes("lock for dispute") ||
    rawContent.includes("locked pending") ||
    /\bstatus\s*:\s*(?:dispute|disputed|in-dispute)\b/.test(rawContent) ||
    // German (.de / .at)
    rawContent.includes("streitfall") ||
    rawContent.includes("rechtstreit") ||
    rawContent.includes("widerspruch") ||
    rawContent.includes("markenstreit") ||
    rawContent.includes("schiedsverfahren") ||
    // French (.fr)
    rawContent.includes("litige") ||
    rawContent.includes("en litige") ||
    rawContent.includes("différend") ||
    rawContent.includes("contentieux") ||
    rawContent.includes("arbitrage") ||
    // Spanish
    rawContent.includes("disputa") ||
    rawContent.includes("en disputa") ||
    rawContent.includes("conflicto de dominio") ||
    rawContent.includes("procedimiento arbitral") ||
    // Italian
    rawContent.includes("contesa") ||
    rawContent.includes("in contesa") ||
    rawContent.includes("disputa di dominio") ||
    rawContent.includes("procedimento arbitrale") ||
    // Portuguese
    rawContent.includes("disputa de domínio") ||
    rawContent.includes("arbitragem") ||
    // Dutch
    rawContent.includes("geschil") ||
    rawContent.includes("in geschil") ||
    rawContent.includes("arbitrage") ||
    // Polish
    rawContent.includes("spór domenowy") ||
    rawContent.includes("postępowanie arbitrażowe") ||
    // Russian
    rawContent.includes("спор") ||
    rawContent.includes("арбитраж") ||
    rawContent.includes("судебное") ||
    // Ukrainian
    rawContent.includes("спір") ||
    rawContent.includes("арбітраж") ||
    // Japanese
    rawContent.includes("係争中") ||
    rawContent.includes("異議申立") ||
    rawContent.includes("紛争") ||
    rawContent.includes("仲裁") ||
    // Korean
    rawContent.includes("분쟁 중") ||
    rawContent.includes("분쟁") ||
    rawContent.includes("중재") ||
    // Chinese (Simplified)
    rawContent.includes("争议中") ||
    rawContent.includes("域名争议") ||
    rawContent.includes("商标争议") ||
    rawContent.includes("仲裁中") ||
    rawContent.includes("法律纠纷") ||
    // Arabic
    rawContent.includes("نزاع") ||
    rawContent.includes("تحكيم") ||
    rawContent.includes("في نزاع") ||
    // Hebrew
    rawContent.includes("סכסוך") ||
    rawContent.includes("בוררות") ||
    // Turkish
    rawContent.includes("uyuşmazlık") ||
    rawContent.includes("ihtilaf") ||
    rawContent.includes("tahkim");

  // ── GUARD: A domain with registrar + creation + expiration date is definitively
  // registered. Reserved/prohibited domains have no registrar or dates.
  // Without this guard, WHOIS boilerplate text (e.g. RegistrarSafe privacy
  // notice containing "withheld") triggers false reserved/prohibited positives.
  const isDefinitelyRegistered =
    result.registrar && result.registrar !== "Unknown" &&
    result.creationDate && result.creationDate !== "Unknown" &&
    result.expirationDate && result.expirationDate !== "Unknown";

  const isProhibited =
    !isDefinitelyRegistered &&
    (prohibitCheckText.includes("prohibited") ||
    prohibitCheckText.includes("registrationprohibited") ||
    prohibitCheckText.includes("cannot be registered") ||
    prohibitCheckText.includes("not available for registration") ||
    prohibitCheckText.includes("not-available") ||
    prohibitCheckText.includes("ineligible") ||
    prohibitCheckText.includes("forbidden") ||
    prohibitCheckText.includes("registry-prohibited") ||
    prohibitCheckText.includes("registrybanned") ||
    rawHasProhibited);

  function makeStatus(
    type: RegistrationStatusType,
    color: string,
    dotColor: string,
    isPremiumReserved = false,
  ) {
    return { type, label: isZh ? STATUS_LABELS[type].zh : STATUS_LABELS[type].en, color, dotColor, isPremiumReserved };
  }

  if (isProhibited)
    return makeStatus("prohibited", "text-red-600 border-red-400/50 bg-red-50 dark:bg-red-950/20", "bg-red-500");

  // "reserved" should not be triggered by "registry-hold" (that is a hold, not a reserve)
  // Also guarded: an actively registered domain (has registrar + dates) cannot be reserved.
  const isReserved =
    !isDefinitelyRegistered &&
    (prohibitCheckText.includes("reserved") ||
    allStatusText.includes("reserved-delegated") ||
    allStatusText.includes("registryreserved") ||
    allStatusText.includes("registry-reserved") ||
    allStatusText.includes("registry-premium") ||
    rawHasReserved);

  // A "premium reserved" domain is held by the registry for sale — different
  // from an "official use" reserved domain.  Both display as "reserved" but
  // carry different descriptions in the info card.
  const isPremiumReserved =
    allStatusText.includes("registry-premium") ||
    rawHasPremiumReserved;

  if (isReserved)
    return makeStatus("reserved", "text-amber-600 border-amber-400/50 bg-amber-50 dark:bg-amber-950/20", "bg-amber-500", isPremiumReserved);

  const isRedemption =
    allStatusText.includes("redemptionperiod") ||
    allStatusText.includes("redemption period") ||
    allStatusText.includes("redemption-period");

  if (isRedemption)
    return makeStatus("redemption", "text-purple-600 border-purple-400/50 bg-purple-50 dark:bg-purple-950/20", "bg-purple-500");

  const isPendingDelete =
    allStatusText.includes("pendingdelete") ||
    allStatusText.includes("pending delete") ||
    allStatusText.includes("pending-delete");

  if (isPendingDelete)
    return makeStatus("pending-delete", "text-slate-600 border-slate-400/50 bg-slate-50 dark:bg-slate-950/20", "bg-slate-500");

  // ── DISPUTE — check before hold (more specific; UDRP domains often have serverHold too)
  const isDispute =
    allStatusText.includes("dispute") ||
    allStatusText.includes("udrp") ||
    allStatusText.includes("locked-udrp") ||
    allStatusText.includes("adr") ||
    rawHasDispute;

  if (isDispute)
    return makeStatus("dispute", "text-rose-600 border-rose-400/50 bg-rose-50 dark:bg-rose-950/20", "bg-rose-500");

  // ── HOLD / SUSPENDED — Match EPP codes ("serverhold") and hyphenated / spaced variants
  const hasServerHold =
    allStatusText.includes("serverhold") ||
    allStatusText.includes("server-hold") ||
    allStatusText.includes("server hold") ||
    allStatusText.includes("registry-hold") ||
    allStatusText.includes("registryhold");

  const hasClientHold =
    allStatusText.includes("clienthold") ||
    allStatusText.includes("client-hold") ||
    allStatusText.includes("client hold");

  const hasOk =
    allStatusText.includes(" ok ") ||
    allStatusText === "ok" ||
    allStatusText.includes("active");

  const hasSuspended =
    allStatusText.includes("suspended") ||
    allStatusText.includes("hold") ||
    allStatusText.includes("frozen") ||
    allStatusText.includes("inactive") ||
    rawHasSuspended;

  const isHold = (hasServerHold || hasClientHold || hasSuspended) && !hasOk;

  if (isHold)
    return makeStatus("hold", "text-orange-600 border-orange-400/50 bg-orange-50 dark:bg-orange-950/20", "bg-orange-500");

  return {
    type: "registered" as RegistrationStatusType,
    label: isZh ? STATUS_LABELS.registered.zh : STATUS_LABELS.registered.en,
    color: "text-emerald-600 border-emerald-400/50 bg-emerald-50 dark:bg-emerald-950/20",
    dotColor: "bg-emerald-500",
    isPremiumReserved: false,
  };
}

const STATUS_INFO: Record<
  RegistrationStatusType,
  {
    icon: React.ReactNode;
    titleZh: string;
    titleEn: string;
    descZh: string;
    descEn: string;
    border: string;
    bg: string;
    iconBg: string;
    iconText: string;
    titleText: string;
    descText: string;
  }
> = {
  prohibited: {
    icon: <RiForbidLine className="w-5 h-5" />,
    titleZh: "禁止注册域名",
    titleEn: "Prohibited Domain",
    descZh: "该域名被注册局标记为禁止注册字符串，无法通过任何常规渠道注册。通常为政策性保护词汇或敏感字符串。",
    descEn: "This domain is marked as a prohibited string by the registry and cannot be registered through any conventional channel.",
    border: "border-red-300/60 dark:border-red-800/50",
    bg: "bg-gradient-to-r from-red-50/80 to-red-50/30 dark:from-red-950/30 dark:to-transparent",
    iconBg: "bg-red-100 dark:bg-red-900/40",
    iconText: "text-red-600 dark:text-red-400",
    titleText: "text-red-800 dark:text-red-300",
    descText: "text-red-700/80 dark:text-red-400/70",
  },
  reserved: {
    icon: <RiLockLine className="w-5 h-5" />,
    titleZh: "保留域名",
    titleEn: "Reserved Domain",
    descZh: "该域名为注册局保留域名，由官方机构专用或预留，暂不向公众开放注册。",
    descEn: "This domain is reserved by the registry for official use and is not available for public registration.",
    border: "border-amber-300/60 dark:border-amber-800/50",
    bg: "bg-gradient-to-r from-amber-50/80 to-amber-50/30 dark:from-amber-950/30 dark:to-transparent",
    iconBg: "bg-amber-100 dark:bg-amber-900/40",
    iconText: "text-amber-600 dark:text-amber-400",
    titleText: "text-amber-800 dark:text-amber-300",
    descText: "text-amber-700/80 dark:text-amber-400/70",
  },
  hold: {
    icon: <RiPauseCircleLine className="w-5 h-5" />,
    titleZh: "域名暂停",
    titleEn: "Domain On Hold",
    descZh: "该域名当前处于暂停状态（Server Hold / Client Hold），可能由于违规行为、未付款或争议被暂时锁定，无法正常解析。",
    descEn: "This domain is currently on hold (Server Hold / Client Hold) and cannot resolve normally. This is usually due to a policy violation, non-payment, or dispute.",
    border: "border-orange-300/60 dark:border-orange-800/50",
    bg: "bg-gradient-to-r from-orange-50/80 to-orange-50/30 dark:from-orange-950/30 dark:to-transparent",
    iconBg: "bg-orange-100 dark:bg-orange-900/40",
    iconText: "text-orange-600 dark:text-orange-400",
    titleText: "text-orange-800 dark:text-orange-300",
    descText: "text-orange-700/80 dark:text-orange-400/70",
  },
  dispute: {
    icon: <RiScalesLine className="w-5 h-5" />,
    titleZh: "域名争议",
    titleEn: "Domain Dispute",
    descZh: "该域名正处于 UDRP 争议程序或其他争议处理中，当前处于锁定状态，等待仲裁结果。",
    descEn: "This domain is currently undergoing a UDRP dispute or other legal proceedings and is locked pending arbitration.",
    border: "border-rose-300/60 dark:border-rose-800/50",
    bg: "bg-gradient-to-r from-rose-50/80 to-rose-50/30 dark:from-rose-950/30 dark:to-transparent",
    iconBg: "bg-rose-100 dark:bg-rose-900/40",
    iconText: "text-rose-600 dark:text-rose-400",
    titleText: "text-rose-800 dark:text-rose-300",
    descText: "text-rose-700/80 dark:text-rose-400/70",
  },
  redemption: {
    icon: <RiLoopLeftLine className="w-5 h-5" />,
    titleZh: "赎回期",
    titleEn: "Redemption Period",
    descZh: "该域名已过期并进入赎回期，原注册人可在此期间支付额外费用赎回，赎回期结束后将被公开删除。",
    descEn: "This domain has expired and entered the redemption period. The original registrant can reclaim it for an extra fee before it is deleted.",
    border: "border-purple-300/60 dark:border-purple-800/50",
    bg: "bg-gradient-to-r from-purple-50/80 to-purple-50/30 dark:from-purple-950/30 dark:to-transparent",
    iconBg: "bg-purple-100 dark:bg-purple-900/40",
    iconText: "text-purple-600 dark:text-purple-400",
    titleText: "text-purple-800 dark:text-purple-300",
    descText: "text-purple-700/80 dark:text-purple-400/70",
  },
  "pending-delete": {
    icon: <RiDeleteBin2Line className="w-5 h-5" />,
    titleZh: "待删除",
    titleEn: "Pending Delete",
    descZh: "该域名即将从注册系统中删除，删除后将重新开放注册。删除通常在 5 天内完成。",
    descEn: "This domain is about to be deleted from the registry and will soon become available for registration again.",
    border: "border-slate-300/60 dark:border-slate-700/50",
    bg: "bg-gradient-to-r from-slate-50/80 to-slate-50/30 dark:from-slate-950/30 dark:to-transparent",
    iconBg: "bg-slate-100 dark:bg-slate-800/60",
    iconText: "text-slate-600 dark:text-slate-400",
    titleText: "text-slate-700 dark:text-slate-300",
    descText: "text-slate-600/80 dark:text-slate-400/70",
  },
  available: {
    icon: <RiCheckLine className="w-5 h-5" />,
    titleZh: "域名可注册",
    titleEn: "Domain Available",
    descZh: "该域名当前未被注册，您可以立即前往域名注册商注册此域名。",
    descEn: "This domain is currently unregistered and available for purchase.",
    border: "border-emerald-300/60 dark:border-emerald-800/50",
    bg: "bg-gradient-to-r from-emerald-50/80 to-emerald-50/30 dark:from-emerald-950/30 dark:to-transparent",
    iconBg: "bg-emerald-100 dark:bg-emerald-900/40",
    iconText: "text-emerald-600 dark:text-emerald-400",
    titleText: "text-emerald-800 dark:text-emerald-300",
    descText: "text-emerald-700/80 dark:text-emerald-400/70",
  },
  registered: {
    icon: null,
    titleZh: "",
    titleEn: "",
    descZh: "",
    descEn: "",
    border: "",
    bg: "",
    iconBg: "",
    iconText: "",
    titleText: "",
    descText: "",
  },
};

function DomainStatusInfoCard({
  type,
  locale,
  customDesc,
}: {
  type: RegistrationStatusType;
  locale: string;
  customDesc?: { zh: string; en: string };
}) {
  if (type === "registered") return null;
  const info = STATUS_INFO[type];
  const isZh = locale.startsWith("zh");
  const desc = customDesc
    ? (isZh ? customDesc.zh : customDesc.en)
    : (isZh ? info.descZh : info.descEn);
  return (
    <div
      className={cn(
        "rounded-xl border p-4 mt-5",
        "flex items-start gap-3.5",
        info.border,
        info.bg,
      )}
    >
      <div
        className={cn(
          "w-9 h-9 rounded-xl flex items-center justify-center shrink-0",
          info.iconBg,
          info.iconText,
        )}
      >
        {info.icon}
      </div>
      <div className="min-w-0">
        <p className={cn("text-sm font-semibold leading-tight", info.titleText)}>
          {isZh ? info.titleZh : info.titleEn}
        </p>
        <p className={cn("text-xs mt-1 leading-relaxed", info.descText)}>
          {desc}
        </p>
      </div>
    </div>
  );
}


const ALL_REMINDER_THRESHOLDS = [60, 30, 10, 5, 1];
const DEFAULT_REMINDER_THRESHOLDS = [60, 30, 1];

function DomainReminderDialog({
  domain,
  expirationDate,
  remainingDays,
  open,
  onOpenChange,
  isZh,
  userEmail,
  registerPriceFmt,
  renewPriceFmt,
  isPremium,
  eppStatuses,
  regStatusType,
}: {
  domain: string;
  expirationDate: string | null | undefined;
  remainingDays: number | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  isZh: boolean;
  userEmail?: string;
  registerPriceFmt?: string;
  renewPriceFmt?: string;
  isPremium?: boolean;
  eppStatuses?: string[];
  regStatusType?: RegistrationStatusType;
}) {
  const hasExpiry = !!(expirationDate && expirationDate !== "Unknown");
  const [email, setEmail] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);
  const [selectedThresholds, setSelectedThresholds] = React.useState<number[]>(DEFAULT_REMINDER_THRESHOLDS);

  const [lcFeedbackOpen, setLcFeedbackOpen] = React.useState(false);
  const [lcForm, setLcForm] = React.useState({ grace: "0", redemption: "0", pendingDelete: "0", sourceUrl: "", notes: "", email: "" });
  const [lcSubmitting, setLcSubmitting] = React.useState(false);
  const [lcDone, setLcDone] = React.useState(false);

  function toggleThreshold(d: number) {
    setSelectedThresholds(prev =>
      prev.includes(d) ? prev.filter(x => x !== d) : [...prev, d]
    );
  }

  React.useEffect(() => {
    if (open) { setEmail(userEmail || ""); setDone(false); setSelectedThresholds(DEFAULT_REMINDER_THRESHOLDS); }
  }, [open, userEmail]);

  const isRestricted = regStatusType === "prohibited" || regStatusType === "reserved";

  async function handleSubmit() {
    if (!email || !email.includes("@")) {
      toast.error(isZh ? "请输入有效邮箱" : "Please enter a valid email");
      return;
    }
    if (!isRestricted && selectedThresholds.length === 0) {
      toast.error(isZh ? "请至少选择一个到期前提醒时间" : "Please select at least one pre-expiry reminder");
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/remind/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain, email, expirationDate, phaseAlerts,
          thresholds: isRestricted ? [] : selectedThresholds,
          regStatusType,
        }),
      });
      if (res.ok) {
        setDone(true);
      } else {
        toast.error(isZh ? "提交失败，请重试" : "Submission failed");
      }
    } catch {
      toast.error(isZh ? "网络错误" : "Network error");
    } finally {
      setSubmitting(false);
    }
  }

  const lc = React.useMemo(
    () => computeLifecycle(domain, expirationDate ?? null, eppStatuses),
    [domain, expirationDate, eppStatuses]
  );
  const tldUpper = domain.split(".").pop()?.toUpperCase() ?? "";
  const hasPricing = !!(registerPriceFmt || renewPriceFmt);

  // Lifecycle feedback – placed after `lc` to avoid TDZ
  React.useEffect(() => {
    if (lcFeedbackOpen && lc) {
      setLcForm({
        grace: String(lc.cfg.grace),
        redemption: String(lc.cfg.redemption),
        pendingDelete: String(lc.cfg.pendingDelete),
        sourceUrl: "",
        notes: "",
        email: userEmail || "",
      });
      setLcDone(false);
    }
  }, [lcFeedbackOpen, lc, userEmail]);

  async function handleLcFeedbackSubmit() {
    const sg = parseInt(lcForm.grace, 10);
    const sr = parseInt(lcForm.redemption, 10);
    const sp = parseInt(lcForm.pendingDelete, 10);
    if (isNaN(sg) || isNaN(sr) || isNaN(sp) || sg < 0 || sr < 0 || sp < 0) {
      toast.error(isZh ? "天数必须为非负整数" : "Days must be a non-negative integer");
      return;
    }
    if (lcForm.email && !lcForm.email.includes("@")) {
      toast.error(isZh ? "请输入有效邮箱" : "Please enter a valid email");
      return;
    }
    setLcSubmitting(true);
    try {
      const tld = domain.split(".").pop()?.toLowerCase() ?? "";
      const res = await fetch("/api/user/tld-lifecycle-feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tld,
          current_grace: lc?.cfg.grace ?? null,
          current_redemption: lc?.cfg.redemption ?? null,
          current_pending_delete: lc?.cfg.pendingDelete ?? null,
          suggested_grace: sg,
          suggested_redemption: sr,
          suggested_pending_delete: sp,
          source_url: lcForm.sourceUrl || null,
          notes: lcForm.notes || null,
          submitter_email: lcForm.email || null,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "提交失败");
      }
      setLcDone(true);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : (isZh ? "提交失败" : "Submission failed"));
    } finally {
      setLcSubmitting(false);
    }
  }

  const PHASE_UI = {
    active:        { label: isZh ? "正常有效" : "Active",        colorClass: "text-emerald-600 dark:text-emerald-400", bgClass: "bg-emerald-50/70 dark:bg-emerald-950/25", borderClass: "border-emerald-200/60 dark:border-emerald-800/40", dotClass: "bg-emerald-500" },
    grace:         { label: isZh ? "宽限期"   : "Grace Period",  colorClass: "text-amber-600 dark:text-amber-400",    bgClass: "bg-amber-50/70 dark:bg-amber-950/25",    borderClass: "border-amber-200/60 dark:border-amber-800/40",    dotClass: "bg-amber-500" },
    redemption:    { label: isZh ? "赎回期"   : "Redemption",    colorClass: "text-orange-600 dark:text-orange-400",  bgClass: "bg-orange-50/70 dark:bg-orange-950/25",  borderClass: "border-orange-200/60 dark:border-orange-800/40",  dotClass: "bg-orange-500" },
    pendingDelete: { label: isZh ? "待删除"   : "Pending Delete", colorClass: "text-red-600 dark:text-red-400",        bgClass: "bg-red-50/70 dark:bg-red-950/25",        borderClass: "border-red-200/60 dark:border-red-800/40",        dotClass: "bg-red-500" },
    dropped:       { label: isZh ? "已释放"   : "Available",     colorClass: "text-emerald-600 dark:text-emerald-400",        bgClass: "bg-emerald-50/70 dark:bg-emerald-950/25",        borderClass: "border-emerald-200/60 dark:border-emerald-800/40",        dotClass: "bg-emerald-400" },
  };

  const PHASE_ADVICE: Record<string, { zh: string; en: string }> = {
    active:        { zh: "域名状态正常，我们将在到期前自动发送提醒邮件。", en: "Domain is active. We'll alert you before expiry." },
    grace:         { zh: "域名已过期，仍处于宽限期内，可按正常价格续费，请尽快操作！", en: "Expired but renewable at normal price during grace — act now!" },
    redemption:    { zh: "已进入赎回期，续费费用大幅增加，请立即联系注册商赎回。", en: "In redemption. Recovery fees are much higher — contact your registrar." },
    pendingDelete: { zh: "即将被注册局删除，通常无法再续期，请提前做好准备。", en: "Pending deletion. Usually cannot be renewed anymore." },
    dropped:       { zh: "域名已被删除，即将或已可重新注册。", en: "Domain has been deleted and may be available for re-registration." },
  };

  const urgencyNum =
    remainingDays === null ? "text-muted-foreground" :
    remainingDays <= 0  ? "text-red-500 dark:text-red-400" :
    remainingDays <= 30 ? "text-orange-500 dark:text-orange-400" :
    remainingDays <= 90 ? "text-amber-500 dark:text-amber-400" :
    "text-emerald-500 dark:text-emerald-400";

  const phaseUI = lc ? PHASE_UI[lc.phase] : null;

  type PhaseAlerts = { grace: boolean; redemption: boolean; pendingDelete: boolean; dropSoon: boolean; dropped: boolean };
  const [phaseAlerts, setPhaseAlerts] = React.useState<PhaseAlerts>({
    grace: true, redemption: true, pendingDelete: true, dropSoon: true, dropped: true,
  });
  function togglePhase(key: keyof PhaseAlerts) {
    setPhaseAlerts((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  type PhaseChip = {
    key: keyof PhaseAlerts;
    label: string;
    icon: React.ReactNode;
    activeCls: string;
    inactiveCls: string;
    always?: boolean;
  };
  const phaseChips: PhaseChip[] = lc ? [
    lc.cfg.grace > 0         && { key: "grace"       as const, label: isZh ? "进入宽限期"   : "Grace Period",    icon: <RiTimeLine className="w-2.5 h-2.5" />,            activeCls: "bg-amber-500/18 border-amber-400/60 text-amber-700 dark:text-amber-300",   inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    lc.cfg.redemption > 0    && { key: "redemption"  as const, label: isZh ? "进入赎回期"   : "Redemption",      icon: <RiExchangeDollarFill className="w-2.5 h-2.5" />,  activeCls: "bg-orange-500/18 border-orange-400/60 text-orange-700 dark:text-orange-300", inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    lc.cfg.pendingDelete > 0 && { key: "pendingDelete" as const, label: isZh ? "进入待删除期" : "Pending Delete",  icon: <RiDeleteBin2Line className="w-2.5 h-2.5" />,     activeCls: "bg-red-500/18 border-red-400/60 text-red-700 dark:text-red-300",          inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    (lc.cfg.pendingDelete > 0 || lc.cfg.redemption > 0 || lc.cfg.grace > 0) && { key: "dropSoon" as const, always: true, label: isZh ? "即将可注册" : "Drop Soon",       icon: <RiAlertLine className="w-2.5 h-2.5" />,           activeCls: "bg-foreground/10 border-foreground/25 text-foreground",                   inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    (lc.cfg.pendingDelete > 0 || lc.cfg.redemption > 0 || lc.cfg.grace > 0) && { key: "dropped"  as const, always: true, label: isZh ? "域名可注册"  : "Available",      icon: <RiShoppingCartLine className="w-2.5 h-2.5" />,    activeCls: "bg-emerald-500/18 border-emerald-400/60 text-emerald-700 dark:text-emerald-300", inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
  ].filter(Boolean) as PhaseChip[] : [];

  return (<>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[420px] p-0 overflow-hidden gap-0">

        {/* ── Header ── */}
        <div className="px-5 pt-5 pb-4 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-muted border border-border/60 flex items-center justify-center shrink-0">
              <RiTimerLine className="w-[18px] h-[18px] text-foreground/70" />
            </div>
            <h2 className="text-sm font-bold text-foreground leading-none">
              {isZh ? "域名监控订阅" : "Domain Monitoring"}
            </h2>
          </div>
        </div>

        {/* ── Body ── */}
        <div className="px-5 pb-5 overflow-y-auto max-h-[72dvh]">

          {/* ── Domain name card — centered, above pricing ── */}
          <div className="flex flex-col items-center justify-center pt-4 pb-1 gap-1">
            <div className="px-4 py-2.5 rounded-xl border border-border/60 bg-muted/30 text-center min-w-0 max-w-full">
              <p className="text-[15px] font-mono font-bold text-foreground truncate tracking-tight">{domain}</p>
              {lc?.cfg.registry && (
                <p className="text-[10px] text-muted-foreground/55 mt-0.5 truncate">{lc.cfg.registry}</p>
              )}
            </div>
          </div>

          <AnimatePresence mode="wait" initial={false}>

            {/* ── Success ── */}
            {done ? (
              <motion.div
                key="done"
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.96 }}
                transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
                className="py-7 text-center space-y-4"
              >
                <div className="relative w-16 h-16 mx-auto">
                  <div className="absolute inset-0 rounded-full bg-emerald-500/15 animate-ping" style={{ animationDuration: "1.6s" }} />
                  <div className="relative w-16 h-16 bg-emerald-500/10 border-2 border-emerald-400/30 rounded-full flex items-center justify-center">
                    <RiCheckLine className="w-7 h-7 text-emerald-500" />
                  </div>
                </div>
                <div>
                  <p className="font-bold text-[15px] text-foreground">{isZh ? "订阅成功！" : "Subscribed!"}</p>
                  <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                    {isZh ? "将向" : "We'll notify"}{" "}
                    <strong className="text-foreground font-mono text-[11px]">{email}</strong>{" "}
                    {isZh ? "发送以下提醒" : "with the alerts below"}
                  </p>
                </div>
                <div className="text-left rounded-xl border border-border/60 bg-muted/15 p-3 space-y-2.5">
                  <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                    {isZh ? "已订阅的提醒类型" : "Subscribed alerts"}
                  </p>
                  {isRestricted ? (
                    <div className="flex items-center gap-1.5">
                      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-foreground/8 border border-foreground/20 text-foreground/80 text-[10px] font-semibold">
                        <RiCheckboxCircleLine className="w-2.5 h-2.5" />
                        {isZh ? "域名状态变化通知" : "Status change alert"}
                      </span>
                    </div>
                  ) : (
                    <>
                      <div>
                        <p className="text-[10px] text-foreground/60 font-semibold mb-1.5">{isZh ? "到期前提醒" : "Pre-expiry"}</p>
                        <div className="flex flex-wrap gap-1">
                          {[...selectedThresholds].sort((a, b) => b - a).map((d) => (
                            <span key={d} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-foreground/8 border border-foreground/20 text-foreground/80 text-[10px] font-semibold">
                              <RiTimerLine className="w-2.5 h-2.5" />{isZh ? `提前${d}天` : `${d}d`}
                            </span>
                          ))}
                        </div>
                      </div>
                      {phaseChips.filter((c) => phaseAlerts[c.key]).length > 0 && (
                        <div>
                          <p className="text-[10px] text-foreground/60 font-semibold mb-1.5">{isZh ? "阶段提醒" : "Phase alerts"}</p>
                          <div className="flex flex-wrap gap-1">
                            {phaseChips.filter((c) => phaseAlerts[c.key]).map((chip) => (
                              <span key={chip.key} className={cn("inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md border text-[10px] font-semibold", chip.activeCls)}>
                                <RiCheckboxCircleLine className="w-2.5 h-2.5" />{chip.label}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
                <p className="text-[10px] text-muted-foreground/55">{isZh ? "确认邮件已发送，请查收" : "Check your inbox for confirmation"}</p>
                <button
                  type="button"
                  onClick={() => setDone(false)}
                  className="text-xs text-muted-foreground/70 hover:text-foreground transition-colors underline-offset-2 hover:underline"
                >
                  {isZh ? "← 返回修改信息" : "← Edit subscription"}
                </button>
              </motion.div>

            ) : (
              /* ── Form ── */
              <motion.div
                key="form"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="space-y-3 pt-2"
              >
                {/* ── Prohibited / Reserved warning banner ─────────────── */}
                {(regStatusType === "prohibited" || regStatusType === "reserved") && (
                  <div className={cn(
                    "flex items-start gap-2.5 rounded-xl border px-3.5 py-3",
                    regStatusType === "prohibited"
                      ? "bg-red-50/60 dark:bg-red-950/20 border-red-300/50 dark:border-red-700/40"
                      : "bg-amber-50/60 dark:bg-amber-950/20 border-amber-300/50 dark:border-amber-700/40"
                  )}>
                    <RiInformationLine className={cn(
                      "w-4 h-4 mt-0.5 shrink-0",
                      regStatusType === "prohibited" ? "text-red-500" : "text-amber-500"
                    )} />
                    <div className="min-w-0">
                      <p className={cn(
                        "text-xs font-bold leading-snug",
                        regStatusType === "prohibited" ? "text-red-600 dark:text-red-400" : "text-amber-600 dark:text-amber-400"
                      )}>
                        {regStatusType === "prohibited"
                          ? (isZh ? "该域名被禁止注册" : "Registration Prohibited")
                          : (isZh ? "该域名为保留域名" : "Reserved Domain")}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {regStatusType === "prohibited"
                          ? (isZh
                              ? "该域名被注册局标记为禁止注册字符串，通常无法通过常规渠道注册。仍可订阅，当域名状态变化时会发送通知。"
                              : "This domain is marked as prohibited by the registry and cannot be registered through normal channels. You can still subscribe to receive status change notifications.")
                          : (isZh
                              ? "该域名目前为保留状态，不对公众开放注册。仍可订阅，如状态发生变化或域名开放注册时会收到通知。"
                              : "This domain is currently reserved and not available for public registration. You can still subscribe to receive notifications if the status changes.")}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Hold warning banner ───────────────────────────────── */}
                {regStatusType === "hold" && (
                  <div className="flex items-start gap-2.5 rounded-xl border px-3.5 py-3 bg-orange-50/60 dark:bg-orange-950/20 border-orange-300/50 dark:border-orange-700/40">
                    <RiInformationLine className="w-4 h-4 mt-0.5 shrink-0 text-orange-500" />
                    <div className="min-w-0">
                      <p className="text-xs font-bold leading-snug text-orange-600 dark:text-orange-400">
                        {isZh ? "该域名当前处于暂停状态" : "Domain On Hold"}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {isZh
                          ? "该域名已被注册局或注册商暂停（如违规、欠款或政府扣押），目前无法正常解析。仍可订阅到期提醒，以便跟踪续费或状态变化。"
                          : "This domain has been suspended by the registry or registrar (e.g. policy violation, non-payment, or seizure) and cannot currently resolve. You can still subscribe for expiry and status alerts."}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Dispute warning banner ────────────────────────────── */}
                {regStatusType === "dispute" && (
                  <div className="flex items-start gap-2.5 rounded-xl border px-3.5 py-3 bg-rose-50/60 dark:bg-rose-950/20 border-rose-300/50 dark:border-rose-700/40">
                    <RiInformationLine className="w-4 h-4 mt-0.5 shrink-0 text-rose-500" />
                    <div className="min-w-0">
                      <p className="text-xs font-bold leading-snug text-rose-600 dark:text-rose-400">
                        {isZh ? "该域名正处于争议程序中" : "Domain In Dispute"}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {isZh
                          ? "该域名正处于 UDRP 或其他争议解决程序中，当前被锁定，等待仲裁结果。仍可订阅到期提醒，以便及时获知域名状态变化。"
                          : "This domain is currently locked in a UDRP or other dispute resolution proceeding. You can still subscribe for expiry and status alerts to stay informed of any outcome."}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Pricing + premium row ────────────────────────────── */}
                {hasPricing && (
                  <div className="grid grid-cols-3 gap-1.5 rounded-xl border border-border/50 bg-muted/15 overflow-hidden">
                    {/* Register price */}
                    <div className="flex flex-col items-center justify-center px-2 py-2.5 gap-0.5">
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "注册" : "Register"}
                      </p>
                      <p className={cn("text-[13px] font-black tabular-nums leading-none", isPremium ? "text-amber-500" : "text-foreground")}>
                        {registerPriceFmt ?? "—"}
                      </p>
                    </div>
                    {/* Renew price */}
                    <div className="flex flex-col items-center justify-center px-2 py-2.5 gap-0.5 border-x border-border/40">
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "续费" : "Renew"}
                      </p>
                      <p className={cn("text-[13px] font-black tabular-nums leading-none", isPremium ? "text-amber-500" : "text-foreground")}>
                        {renewPriceFmt ?? "—"}
                      </p>
                    </div>
                    {/* Premium badge */}
                    <div className={cn(
                      "flex flex-col items-center justify-center px-2 py-2.5 gap-0.5",
                      isPremium ? "bg-amber-500/8 dark:bg-amber-500/12" : ""
                    )}>
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "溢价" : "Premium"}
                      </p>
                      <p className={cn(
                        "text-[12px] font-black leading-none",
                        isPremium
                          ? "text-amber-500"
                          : "text-emerald-600 dark:text-emerald-400"
                      )}>
                        {isPremium
                          ? (isZh ? "是" : "Yes")
                          : (isZh ? "否" : "No")}
                      </p>
                    </div>
                  </div>
                )}

                {/* Lifecycle card — phase dot + expiry countdown + drop date multi-tz */}
                {hasExpiry && lc && phaseUI ? (
                  <div className={cn("rounded-xl border overflow-hidden", phaseUI.borderClass)}>
                    {/* Expiry + countdown row */}
                    <div className={cn("flex items-center justify-between px-3.5 py-3", phaseUI.bgClass)}>
                      <div className="min-w-0">
                        <p className="text-[9px] text-muted-foreground/70 uppercase tracking-wider font-bold mb-1">
                          {isZh ? "到期日期" : "Expiry date"}
                        </p>
                        <p className="text-[13px] font-mono font-bold text-foreground leading-none">{fmtDate(lc.expiry)}</p>
                        <p className="text-[10px] font-mono text-muted-foreground/60 mt-0.5 tabular-nums">
                          {`${String(lc.expiry.getUTCHours()).padStart(2,"0")}:${String(lc.expiry.getUTCMinutes()).padStart(2,"0")}:${String(lc.expiry.getUTCSeconds()).padStart(2,"0")} UTC`}
                        </p>
                      </div>
                      <div className="text-right shrink-0 pl-2">
                        {remainingDays !== null && remainingDays >= 0 && remainingDays <= 7 ? (
                          <>
                            <p className={cn("text-[20px] font-black tabular-nums leading-none", urgencyNum)}>
                              {fmtCountdown(lc.expiry, isZh)}
                            </p>
                            <p className="text-[10px] text-muted-foreground mt-0.5">{isZh ? "后到期" : "remaining"}</p>
                          </>
                        ) : (
                          <>
                            <p className={cn("text-[30px] font-black tabular-nums leading-none", urgencyNum)}>
                              {remainingDays !== null ? Math.max(0, remainingDays) : "—"}
                            </p>
                            <p className="text-[10px] text-muted-foreground mt-0.5">{isZh ? "天后到期" : "days left"}</p>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Current phase — animated dot + label + advice */}
                    <div className="px-3.5 py-3 bg-background/60 border-t border-border/25">
                      <div className="flex items-center gap-2">
                        <span className="relative flex h-2 w-2 shrink-0">
                          {lc.phase !== "active" && (
                            <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-60", phaseUI.dotClass)} />
                          )}
                          <span className={cn("relative inline-flex rounded-full h-2 w-2", phaseUI.dotClass)} />
                        </span>
                        <span className={cn("text-[11px] font-bold tracking-wide", phaseUI.colorClass)}>
                          {phaseUI.label}
                        </span>
                        {lc.phaseSource === "epp" && (
                          <span className="ml-auto inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-400/20 text-[9px] font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wide">
                            <RiShieldCheckLine className="w-2 h-2" />EPP
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-muted-foreground leading-relaxed mt-1.5">
                        {isZh ? PHASE_ADVICE[lc.phase]?.zh : PHASE_ADVICE[lc.phase]?.en}
                      </p>
                    </div>

                    {/* Drop/available date with multi-timezone breakdown */}
                    {(lc.cfg.pendingDelete > 0 || lc.cfg.grace > 0 || lc.cfg.redemption > 0) && (() => {
                      const dropIsPast = new Date() > lc.dropDate;
                      const daysToDropDate = Math.ceil((lc.dropDate.getTime() - Date.now()) / 86_400_000);

                      // Build timezone rows — always UTC, + locale-specific cities
                      type TzRow = { label: string; tz: string };
                      const tzRows: TzRow[] = [{ label: "UTC", tz: "UTC" }];
                      if (isZh) {
                        tzRows.push({ label: isZh ? "北京时间" : "Beijing", tz: "Asia/Shanghai" });
                      } else {
                        tzRows.push({ label: "New York", tz: "America/New_York" });
                        tzRows.push({ label: "London",   tz: "Europe/London"   });
                      }
                      // Always add browser local timezone if it differs from the above
                      try {
                        const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                        if (!tzRows.some(r => r.tz === localTz)) {
                          tzRows.push({ label: isZh ? "本地时间" : "Local", tz: localTz });
                        }
                      } catch { /* ignore */ }

                      const fmtInTz = (d: Date, tz: string) => {
                        try {
                          return new Intl.DateTimeFormat(isZh ? "zh-CN" : "en-US", {
                            timeZone: tz,
                            year: "numeric", month: "2-digit", day: "2-digit",
                            hour: "2-digit", minute: "2-digit", second: "2-digit",
                            hour12: false,
                          }).format(d).replace(/\//g, "/");
                        } catch { return "—"; }
                      };

                      return (
                        <div className={cn(
                          "border-t px-3.5 py-3",
                          dropIsPast ? "border-emerald-300/40 bg-emerald-50/40 dark:bg-emerald-950/15" : "border-border/25 bg-muted/20"
                        )}>
                          {/* Header row */}
                          <div className="flex items-center gap-2 mb-2.5">
                            <RiShoppingCartLine className={cn("w-3.5 h-3.5 shrink-0", dropIsPast ? "text-emerald-500" : "text-foreground/50")} />
                            <span className={cn("text-[11px] font-bold", dropIsPast ? "text-emerald-600 dark:text-emerald-400" : "text-foreground/70")}>
                              {isZh ? "预计可注册" : "Est. available"}
                            </span>
                            {dropIsPast ? (
                              <span className="ml-auto inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-400/30 uppercase tracking-wide">
                                {isZh ? "现在可注册" : "NOW"}
                              </span>
                            ) : (
                              <span className={cn("ml-auto text-[11px] font-black tabular-nums", urgencyNum === "text-muted-foreground" ? "text-foreground/80" : urgencyNum)}>
                                {Math.max(0, daysToDropDate)}{isZh ? "天后" : "d"}
                              </span>
                            )}
                          </div>
                          {/* Timezone rows */}
                          <div className="space-y-1.5">
                            {tzRows.map(({ label, tz }) => (
                              <div key={tz} className="flex items-center justify-between gap-2">
                                <span className="text-[10px] text-muted-foreground/70 font-medium shrink-0 w-[64px]">{label}</span>
                                <span className="text-[10px] font-mono font-semibold tabular-nums text-foreground/80 text-right">
                                  {fmtInTz(lc.dropDate, tz)}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Feedback row */}
                    <div className="px-3.5 py-2 border-t border-border/20 bg-background/40 flex items-center justify-between">
                      <p className="text-[10px] text-muted-foreground/50">
                        {isZh ? "时间不准确？" : "Timing incorrect?"}
                      </p>
                      <button
                        type="button"
                        onClick={() => setLcFeedbackOpen(true)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border border-border/40 bg-muted/20 text-muted-foreground hover:bg-amber-50 dark:hover:bg-amber-950/30 hover:border-amber-400/40 hover:text-amber-600 dark:hover:text-amber-400 transition-colors cursor-pointer"
                      >
                        <RiFlagLine className="w-2.5 h-2.5" />
                        {isZh ? "反馈纠错" : "Report"}
                      </button>
                    </div>
                  </div>
                ) : !hasExpiry ? (
                  <div className="px-3.5 py-3 rounded-xl border border-border/50 bg-muted/15 flex items-center gap-2.5">
                    <span className="relative flex h-2 w-2 shrink-0">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-40 bg-foreground/40" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-foreground/50" />
                    </span>
                    <p className="text-[11px] text-muted-foreground">
                      {isZh ? "暂无到期日期，仍可订阅提醒" : "No expiry info yet, but you can still subscribe"}
                    </p>
                  </div>
                ) : null}

                {/* Reminder plan */}
                {isRestricted ? (
                  /* Restricted (prohibited / reserved) — status-change only */
                  <div className="rounded-xl border border-border/60 bg-muted/15 p-3.5 space-y-2.5">
                    <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                      {isZh ? "提醒计划" : "Reminder plan"}
                    </p>
                    <div className="flex items-center gap-2.5 rounded-lg border border-border/50 bg-muted/30 px-3 py-2.5">
                      <RiCheckboxCircleLine className="w-4 h-4 text-foreground/60 shrink-0" />
                      <div>
                        <p className="text-[11px] font-bold text-foreground/80">
                          {isZh ? "域名状态变化通知" : "Status change alert"}
                        </p>
                        <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
                          {isZh
                            ? "当该域名注册状态发生变化（如解禁、开放注册）时，系统将自动发送邮件通知。"
                            : "You'll be notified by email if this domain's status changes (e.g. restriction lifted, becomes available)."}
                        </p>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground/65 border-t border-border/40 pt-2 leading-relaxed">
                      {isZh ? "可随时取消订阅" : "Unsubscribe anytime"}
                    </p>
                  </div>
                ) : (
                  /* Normal domain — pre-expiry + phase chips */
                  <div className="rounded-xl border border-border/60 bg-muted/15 p-3.5 space-y-3">
                    <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                      {isZh ? "提醒计划" : "Reminder plan"}
                    </p>
                    {/* Pre-expiry day alerts — interactive */}
                    <div>
                      <p className="text-[10px] text-foreground/70 mb-2 flex items-center gap-1.5 font-semibold">
                        <RiTimerLine className="w-3 h-3 text-foreground/50" />
                        {isZh ? "到期前提醒" : "Pre-expiry alerts"}
                        <span className="ml-auto text-[9px] text-muted-foreground/60 font-normal normal-case">
                          {isZh ? "点击选择" : "tap to toggle"}
                        </span>
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {ALL_REMINDER_THRESHOLDS.map((d) => {
                          const on = selectedThresholds.includes(d);
                          return (
                            <button
                              key={d}
                              type="button"
                              onClick={() => toggleThreshold(d)}
                              className={cn(
                                "inline-flex items-center gap-0.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold transition-all cursor-pointer select-none",
                                on
                                  ? "bg-foreground/10 border-foreground/30 text-foreground"
                                  : "bg-muted/30 border-border/50 text-muted-foreground/55"
                              )}
                            >
                              {on
                                ? <RiCheckboxCircleLine className="w-2.5 h-2.5 shrink-0" />
                                : <RiCheckboxBlankCircleLine className="w-2.5 h-2.5 shrink-0" />}
                              {isZh ? `提前 ${d} 天` : `${d}d`}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    {/* Phase event alerts */}
                    {phaseChips.length > 0 ? (
                      <div>
                        <p className="text-[10px] text-foreground/70 mb-2 flex items-center gap-1.5 font-semibold">
                          <RiCalendarEventLine className="w-3 h-3 text-violet-500" />
                          {isZh ? `阶段提醒（.${tldUpper}）` : `Phase alerts (.${tldUpper})`}
                          <span className="ml-auto text-[9px] text-muted-foreground/60 font-normal normal-case">
                            {isZh ? "点击选择" : "tap to toggle"}
                          </span>
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {phaseChips.map((chip) => {
                            const on = phaseAlerts[chip.key];
                            return (
                              <button
                                key={chip.key}
                                type="button"
                                onClick={() => togglePhase(chip.key)}
                                className={cn(
                                  "inline-flex items-center gap-0.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold transition-all cursor-pointer select-none",
                                  on ? chip.activeCls : chip.inactiveCls
                                )}
                              >
                                {on
                                  ? <RiCheckboxCircleLine className="w-2.5 h-2.5 shrink-0" />
                                  : <RiCheckboxBlankCircleLine className="w-2.5 h-2.5 shrink-0" />}
                                {chip.label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ) : lc ? (
                      <p className="text-[10px] text-muted-foreground/55 italic">
                        {isZh
                          ? `.${tldUpper} 注册局不设宽限期，仅发送到期前提醒`
                          : `.${tldUpper} has no grace/redemption — pre-expiry alerts only`}
                      </p>
                    ) : null}
                    <p className="text-[10px] text-muted-foreground/65 border-t border-border/40 pt-2.5 leading-relaxed">
                      {isZh
                        ? "域名释放后自动停止 · 续费时提醒保留直至到期 · 可随时取消"
                        : "Auto-stops on drop · Reminders continue after renewal until new expiry · Unsubscribe anytime"}
                    </p>
                  </div>
                )}

                {/* Email input */}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1.5">
                    {isZh ? "接收邮箱" : "Email address"} <span className="text-red-500">*</span>
                  </p>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                    placeholder="your@email.com"
                    className="w-full text-sm rounded-xl border border-border bg-background px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-ring/30 transition-shadow font-mono"
                  />
                  {userEmail && email === userEmail && (
                    <p className="text-[10px] text-muted-foreground/60 mt-1 flex items-center gap-1">
                      <RiShieldCheckLine className="w-3 h-3 text-emerald-500" />
                      {isZh ? "已自动填入您的账户邮箱" : "Pre-filled from your account"}
                    </p>
                  )}
                </div>

                {/* Submit */}
                <Button
                  onClick={handleSubmit}
                  disabled={submitting}
                  className="w-full gap-2 h-10 bg-primary hover:bg-primary/90 active:bg-primary/80 text-primary-foreground border-0 rounded-xl font-semibold text-sm transition-all"
                >
                  {submitting
                    ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{isZh ? "订阅中…" : "Subscribing…"}</>
                    : <><RiCalendarEventLine className="w-4 h-4" />{isZh ? "订阅域名监控" : "Subscribe"}</>
                  }
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </DialogContent>
    </Dialog>

    {/* TLD Lifecycle Correction feedback dialog */}
    <Dialog open={lcFeedbackOpen} onOpenChange={setLcFeedbackOpen}>
      <DialogContent className="max-w-sm rounded-2xl gap-0 p-0 overflow-hidden">
        <DialogHeader className="px-5 pt-5 pb-3 border-b border-border/40">
          <DialogTitle className="text-base flex items-center gap-2">
            <RiFlagLine className="w-4 h-4 text-amber-500" />
            {isZh ? `纠正 .${tldUpper} 生命周期数据` : `Correct .${tldUpper} Lifecycle Data`}
          </DialogTitle>
          <p className="text-xs text-muted-foreground mt-1">
            {isZh
              ? "若实际注册局政策与显示数据不符，请填写正确天数并提交，管理员审核后将更新数据。"
              : "If the registry policy differs from what's shown, enter the correct days and submit. Admin will review and update."}
          </p>
        </DialogHeader>

        {lcDone ? (
          <div className="px-5 py-8 text-center space-y-2">
            <p className="text-2xl">✅</p>
            <p className="text-sm font-semibold">
              {isZh ? "感谢您的反馈！" : "Thanks for your feedback!"}
            </p>
            <p className="text-xs text-muted-foreground">
              {isZh ? "管理员审核后将更新数据，届时页面会自动反映最新信息。" : "Admin will review and update the data accordingly."}
            </p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => setLcFeedbackOpen(false)}>
              {isZh ? "关闭" : "Close"}
            </Button>
          </div>
        ) : (
          <div className="px-5 py-4 space-y-4">
            <p className="text-[10px] text-muted-foreground/60 uppercase tracking-widest font-bold">
              {isZh ? "建议天数（填 0 表示无该阶段）" : "Suggested Days (0 = phase does not exist)"}
            </p>

            <div className="grid grid-cols-3 gap-3">
              {([
                { key: "grace",        label: isZh ? "宽限期" : "Grace",      placeholder: "30" },
                { key: "redemption",   label: isZh ? "赎回期" : "Redemption", placeholder: "30" },
                { key: "pendingDelete",label: isZh ? "待删除" : "Pending Del", placeholder: "5"  },
              ] as const).map(f => (
                <div key={f.key} className="space-y-1">
                  <label className="text-[10px] font-semibold text-muted-foreground/80">{f.label}</label>
                  <Input
                    type="number"
                    min="0"
                    max="365"
                    value={lcForm[f.key]}
                    onChange={e => setLcForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                    placeholder={f.placeholder}
                    className="h-9 text-sm font-mono text-center"
                  />
                  {lc && (
                    <p className="text-[9px] text-muted-foreground/50 text-center font-mono">
                      {isZh ? "当前" : "now"}: {f.key === "grace" ? lc.cfg.grace : f.key === "redemption" ? lc.cfg.redemption : lc.cfg.pendingDelete}d
                    </p>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "来源链接（可选）" : "Source URL (optional)"}
              </label>
              <Input
                type="url"
                value={lcForm.sourceUrl}
                onChange={e => setLcForm(prev => ({ ...prev, sourceUrl: e.target.value }))}
                placeholder="https://registry.example/policy"
                className="h-9 text-xs font-mono"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "备注（可选）" : "Notes (optional)"}
              </label>
              <Input
                type="text"
                value={lcForm.notes}
                onChange={e => setLcForm(prev => ({ ...prev, notes: e.target.value }))}
                placeholder={isZh ? "如：官网政策更新日期 2025-01-01" : "e.g. Registry policy updated 2025-01-01"}
                className="h-9 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "联系邮箱（可选，用于告知审核结果）" : "Contact email (optional)"}
              </label>
              <Input
                type="email"
                value={lcForm.email}
                onChange={e => setLcForm(prev => ({ ...prev, email: e.target.value }))}
                placeholder="your@email.com"
                className="h-9 text-xs font-mono"
              />
            </div>
          </div>
        )}

        {!lcDone && (
          <div className="flex flex-row gap-2 px-5 pb-5 pt-0">
            <Button variant="outline" size="sm" onClick={() => setLcFeedbackOpen(false)} className="flex-1">
              {isZh ? "取消" : "Cancel"}
            </Button>
            <Button
              size="sm"
              onClick={handleLcFeedbackSubmit}
              disabled={lcSubmitting}
              className="flex-1 bg-amber-500 hover:bg-amber-600 text-white"
            >
              {lcSubmitting
                ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" />{isZh ? "提交中…" : "Submitting…"}</>
                : <><RiFlagLine className="w-3.5 h-3.5 mr-1" />{isZh ? "提交纠错" : "Submit Correction"}</>}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  </>);
}

function RegistrarIcon({ faviconDomain, name }: { faviconDomain: string | null; name: string }) {
  const [imgFailed, setImgFailed] = React.useState(false);
  return (
    <div className="shrink-0 w-9 h-9 rounded-xl flex items-center justify-center overflow-hidden bg-muted/40 border border-border/30">
      {faviconDomain && !imgFailed ? (
        <img
          src={`/api/favicon?domain=${encodeURIComponent(faviconDomain)}`}
          alt={name}
          className="w-6 h-6 object-contain"
          onError={() => setImgFailed(true)}
        />
      ) : (
        <span className="text-xs font-bold text-muted-foreground select-none">
          {name.charAt(0).toUpperCase()}
        </span>
      )}
    </div>
  );
}

function DomainFavicon({
  domain,
  size = 20,
  className = "",
  fallback,
}: {
  domain: string;
  size?: number;
  className?: string;
  fallback: React.ReactNode;
}) {
  const [failed, setFailed] = React.useState(false);
  if (!domain || failed) return <>{fallback}</>;
  return (
    <img
      src={`/api/favicon?domain=${encodeURIComponent(domain)}`}
      alt=""
      width={size}
      height={size}
      className={`object-contain rounded-sm ${className}`}
      onError={() => setFailed(true)}
    />
  );
}

function AvailableDomainCard({ domain, locale, isPremiumByWhois = false }: { domain: string; locale: string; isPremiumByWhois?: boolean }) {
  const [rawPrices, setRawPrices] = React.useState<DomainPricing[]>([]);
  const [registrars, setRegistrars] = React.useState<DomainPricing[]>([]);
  const [renewRegistrars, setRenewRegistrars] = React.useState<DomainPricing[]>([]);
  const [loadingPrices, setLoadingPrices] = React.useState(true);
  const [anyApiPremium, setAnyApiPremium] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const CARD_FALLBACK_RATES: Record<string, number> = {
    AUD: 1.65, CAD: 1.49, CHF: 0.94, CNY: 7.82, DKK: 7.46,
    GBP: 0.85, HKD: 8.50, JPY: 162, KRW: 1520, NOK: 11.7,
    NZD: 1.80, SEK: 11.3, SGD: 1.46, TWD: 34.8, USD: 1.09,
  };
  const [eurRates, setEurRates] = React.useState<Record<string, number>>(CARD_FALLBACK_RATES);
  const isZh = locale.startsWith("zh");

  React.useEffect(() => {
    const tld = domain.substring(domain.lastIndexOf(".") + 1).toLowerCase();
    const ctrl = new AbortController();
    fetch(`/api/pricing?tld=${encodeURIComponent(tld)}&type=new`, { signal: ctrl.signal })
      .then((r) => r.json())
      .then((data) => {
        if (data.anyPremium) setAnyApiPremium(true);
        const prices: DomainPricing[] = (data.price || [])
          .filter((r: any) => typeof r.new === "number")
          .map((r: any) => ({
            ...r,
            isPremium: r.isPremium ?? (
              (r.currencytype && r.currencytype.toLowerCase().includes("premium")) ||
              (typeof r.new === "number" && (() => {
                const cur = (r.currency || "").toLowerCase();
                const t: Record<string, number> = { usd: 60, eur: 55, cad: 80, gbp: 50, aud: 90, cny: 420, hkd: 470, sgd: 80, jpy: 9000 };
                return t[cur] !== undefined && r.new > t[cur];
              })())
            ),
            externalLink: `https://www.nazhumi.com/domain/${tld}/new`,
          }));
        setRawPrices(prices);
      })
      .catch(() => {})
      .finally(() => setLoadingPrices(false));
    return () => ctrl.abort();
  }, [domain]);

  React.useEffect(() => {
    fetch("https://api.frankfurter.dev/v1/latest")
      .then((r) => r.json())
      .then((data) => { if (data?.rates) setEurRates(data.rates); })
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    if (rawPrices.length === 0) return;
    const toEur = (amount: number, currency: string) => {
      const cur = currency.toUpperCase();
      if (cur === "EUR") return amount;
      return amount / (eurRates[cur] ?? 1);
    };
    // Registration price sort
    const sortedNew = [...rawPrices]
      .sort((a, b) => {
        if (anyApiPremium) {
          if (a.isPremium !== b.isPremium) return a.isPremium ? -1 : 1;
        } else {
          if (a.isPremium !== b.isPremium) return a.isPremium ? 1 : -1;
        }
        return toEur(a.new as number, a.currency) - toEur(b.new as number, b.currency);
      })
      .slice(0, 5);
    setRegistrars(sortedNew);
    // Renewal price sort — from the same data (NazhumiRegistrar has renew field)
    const sortedRenew = [...rawPrices]
      .filter((r) => typeof r.renew === "number" && r.renew !== -1)
      .sort((a, b) => {
        if (a.isPremium !== b.isPremium) return a.isPremium ? 1 : -1;
        return toEur(a.renew as number, a.currency) - toEur(b.renew as number, b.currency);
      })
      .slice(0, 5);
    setRenewRegistrars(sortedRenew);
  }, [rawPrices, eurRates, anyApiPremium]);

  function formatPrice(amount: number, currency: string): string {
    const cur = (currency ?? "").toUpperCase();
    if (isZh) {
      if (cur === "CNY") return `¥${amount.toFixed(2)}`;
      const cnyRate = eurRates["CNY"] ?? 7.82;
      const eurAmount = cur === "EUR" ? amount : amount / (eurRates[cur] ?? 1);
      return `¥${(eurAmount * cnyRate).toFixed(2)}`;
    }
    const SYMBOLS: Record<string, string> = {
      USD: "$", EUR: "€", CNY: "¥", GBP: "£",
      CAD: "CA$", AUD: "A$", HKD: "HK$", SGD: "S$",
      NZD: "NZ$", TWD: "NT$", KRW: "₩", JPY: "¥",
    };
    const sym = SYMBOLS[cur] ?? (cur + "\u00a0");
    const decimals = ["JPY", "KRW"].includes(cur) ? 0 : 2;
    return `${sym}${amount.toFixed(decimals)}`;
  }

  function handleCopy() {
    navigator.clipboard.writeText(domain).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }

  const tldForDisplay = domain.substring(domain.lastIndexOf(".")).toLowerCase();
  const sldForDisplay = domain.substring(0, domain.lastIndexOf("."));
  const isPremium = anyApiPremium || isPremiumByWhois || registrars.some((r) => r.isPremium);
  const premiumRegistrars = registrars.filter((r) => r.isPremium);
  const bestRegistrar = (isPremium && premiumRegistrars.length > 0)
    ? premiumRegistrars[0]
    : (registrars.find((r) => !r.isPremium) ?? registrars[0] ?? null);

  // Shared registrar row renderer for both new and renew tables
  function RegistrarRow({ r, idx, priceField, colorFirst }: { r: DomainPricing; idx: number; priceField: "new" | "renew"; colorFirst: boolean }) {
    const faviconDomain = (() => { try { return new URL(r.registrarweb).hostname; } catch { return null; } })();
    const rowIsPremium = r.isPremium;
    const isFirst = idx === 0;
    const price = r[priceField];
    return (
      <a
        href={r.registrarweb}
        target="_blank"
        rel="noopener noreferrer"
        className={cn(
          "flex items-center gap-3 px-4 sm:px-5 py-2.5 transition-colors duration-150 group hover:bg-muted/40",
          isFirst && colorFirst && "bg-muted/20",
        )}
      >
        <RegistrarIcon faviconDomain={faviconDomain} name={r.registrarname} />
        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="shrink-0 text-[11px] font-bold text-muted-foreground/25 w-4 text-right tabular-nums">{idx + 1}</span>
          <p className={cn("text-sm truncate", isFirst ? "font-semibold text-foreground" : "font-medium text-foreground/70")}>
            {r.registrarname}
          </p>
          {isFirst && !rowIsPremium && !isPremium && colorFirst && (
            <span className="shrink-0 text-[9px] font-bold text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border border-emerald-400/30 dark:border-emerald-500/30 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "最低价" : "BEST"}
            </span>
          )}
          {rowIsPremium && (
            <span className="shrink-0 text-[9px] font-bold text-amber-600 dark:text-amber-400 bg-amber-500/8 border border-amber-400/25 dark:border-amber-500/25 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "溢价" : "PREMIUM"}
            </span>
          )}
          {!rowIsPremium && anyApiPremium && (
            <span className="shrink-0 text-[9px] font-bold text-muted-foreground/50 bg-muted/50 border border-border/50 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "参考价" : "STD"}
            </span>
          )}
        </div>
        <div className="shrink-0 text-right flex items-center gap-1.5">
          <div className="flex items-baseline gap-0.5">
            <span className={cn(
              "font-bold tabular-nums",
              rowIsPremium
                ? (isFirst ? "text-base text-amber-600 dark:text-amber-400" : "text-sm text-amber-500/60 dark:text-amber-500/50")
                : (isFirst && colorFirst ? "text-base text-emerald-600 dark:text-emerald-400" : "text-sm text-foreground/60"),
            )}>
              {typeof price === "number" ? formatPrice(price, r.currency) : "N/A"}
            </span>
            <span className="text-xs text-muted-foreground/40">/{isZh ? "年" : "yr"}</span>
          </div>
          <svg className="w-3.5 h-3.5 text-muted-foreground/25 group-hover:text-muted-foreground/50 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      </a>
    );
  }

  return (
    <div className="glass-panel rounded-xl overflow-hidden border border-border/60">
      {/* Accent bar */}
      <div className={cn("h-1 w-full", isPremium ? "bg-gradient-to-r from-amber-400 to-amber-500" : "bg-gradient-to-r from-emerald-400 to-emerald-500")} />

      {/* ── Hero ── */}
      <div className="px-5 pt-8 pb-6 text-center">
        {/* Big icon */}
        <div className="flex justify-center mb-4">
          <div className={cn(
            "w-16 h-16 rounded-full flex items-center justify-center border-2",
            isPremium
              ? "bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-700/50"
              : "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-700/50"
          )}>
            {isPremium
              ? <RiVipCrownLine className="w-7 h-7 text-amber-500 dark:text-amber-400" />
              : <RiCheckLine className="w-8 h-8 text-emerald-500 dark:text-emerald-400" />}
          </div>
        </div>

        {/* Badge */}
        <div className="flex justify-center mb-3">
          <span className={cn(
            "inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border",
            isPremium
              ? "text-amber-700 dark:text-amber-300 bg-amber-500/10 border-amber-400/30 dark:border-amber-500/30"
              : "text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border-emerald-400/30 dark:border-emerald-500/30"
          )}>
            <span className={cn("w-1.5 h-1.5 rounded-full", isPremium ? "bg-amber-500" : "bg-emerald-500")} />
            {isPremium ? (isZh ? "溢价域名" : "Premium Domain") : (isZh ? "可注册" : "Available")}
          </span>
        </div>

        {/* Domain name */}
        <div className="mb-2.5 leading-tight">
          <span className="text-3xl sm:text-4xl font-bold tracking-tight text-foreground break-all">{sldForDisplay}</span>
          <span className={cn(
            "text-3xl sm:text-4xl font-bold tracking-tight",
            isPremium ? "text-amber-500 dark:text-amber-400" : "text-emerald-500 dark:text-emerald-400"
          )}>{tldForDisplay}</span>
        </div>

        {/* Description */}
        <p className="text-sm text-muted-foreground leading-relaxed mb-5 max-w-xs mx-auto">
          {isPremium
            ? (anyApiPremium && premiumRegistrars.length > 0
                ? (isZh
                    ? `溢价域名，注册费约 ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/年起，实际以注册商报价为准。`
                    : `Premium domain — starting from ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/yr. Confirm price with registrar.`)
                : (isZh
                    ? "溢价域名，注册价格高于普通域名，请以注册商实时报价为准。"
                    : "Premium domain — registration costs above standard rates. Confirm with registrar."))
            : (isZh
                ? "恭喜！该域名目前可注册，抓紧时间抢注吧！"
                : "Great news! This domain is available. Grab it before someone else does.")}
        </p>

        {/* Action buttons */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-2.5">
          {loadingPrices ? (
            <div className="h-9 w-44 rounded-lg bg-muted/40 animate-pulse mx-auto" />
          ) : bestRegistrar ? (
            <a
              href={bestRegistrar.registrarweb}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "inline-flex items-center justify-center gap-2 font-semibold text-sm px-5 py-2.5 rounded-lg border transition-all duration-150 active:scale-[0.98]",
                isPremium
                  ? "border-amber-400/40 dark:border-amber-500/35 text-amber-700 dark:text-amber-300 bg-amber-500/10 dark:bg-amber-500/12 hover:bg-amber-500/18 dark:hover:bg-amber-500/20"
                  : "border-emerald-400/40 dark:border-emerald-500/35 text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 dark:bg-emerald-500/12 hover:bg-emerald-500/18 dark:hover:bg-emerald-500/20"
              )}
            >
              <RiShoppingCartLine className="w-4 h-4 shrink-0" />
              <span>
                {isZh
                  ? `${isPremium ? "查看价格" : "立即注册"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/首年起`
                  : `${isPremium ? "Check Price" : "Register Now"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/yr`}
              </span>
            </a>
          ) : null}
          <button
            onClick={handleCopy}
            className="inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.98]"
          >
            {copied
              ? <RiCheckLine className="w-4 h-4 shrink-0 text-emerald-500" />
              : <RiFileCopyLine className="w-4 h-4 shrink-0" />}
            {isZh ? (copied ? "已复制" : "复制域名") : (copied ? "Copied!" : "Copy Domain")}
          </button>
          <Link href="/">
            <button className="w-full sm:w-auto inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.98]">
              <RiSearchLine className="w-4 h-4 shrink-0" />
              {isZh ? "新查询" : "New Search"}
            </button>
          </Link>
        </div>
      </div>

      {/* ── Registration tips ── */}
      <div className="border-t border-border/50 px-5 py-4">
        <p className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground/60 mb-3 flex items-center gap-1.5">
          <RiInformationLine className="w-3.5 h-3.5" />
          {isZh ? "注册建议" : "Tips"}
        </p>
        <ul className="space-y-2">
          {[
            isZh ? "建议尽快通过正规注册商完成注册" : "Register through an accredited registrar promptly",
            isZh ? "注册前请确认域名用途符合相关法规" : "Confirm your intended use complies with relevant regulations",
            isZh ? "建议同时注册常见后缀以保护品牌" : "Consider registering common TLD variants to protect your brand",
          ].map((tip, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground leading-snug">
              <span className={cn("mt-1 w-1.5 h-1.5 rounded-full shrink-0", isPremium ? "bg-amber-400" : "bg-emerald-400")} />
              {tip}
            </li>
          ))}
        </ul>
      </div>

      {/* ── Price section ── */}
      <div className="border-t border-border/50">
        {/* Premium notice */}
        {isPremium && !loadingPrices && (
          <div className="mx-4 sm:mx-5 mt-4 flex items-start gap-2 rounded-lg border border-border/60 bg-muted/30 px-3 py-2.5">
            <RiInformationLine className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-[11px] text-muted-foreground leading-snug">
              {anyApiPremium && premiumRegistrars.length > 0
                ? (isZh
                    ? "溢价注册商报价（标注「溢价」）为域名真实价格，其余为参考标准价，实际价格以注册商报价为准。"
                    : "Entries marked \"Premium\" reflect the actual premium fee. Others show standard TLD reference prices — always confirm with the registrar.")
                : (isZh
                    ? "以下为该 TLD 标准/参考价，实际溢价金额可能显著更高，以注册商报价为准。"
                    : "Prices shown are standard/reference rates. Actual premium cost may be significantly higher — confirm with the registrar.")}
            </p>
          </div>
        )}

        {/* Registration prices */}
        <div className="px-4 sm:px-5 pt-4 pb-1 flex items-center justify-between">
          <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 font-bold uppercase tracking-wider">
            <RiShoppingCartLine className="w-3 h-3" />
            {isZh ? "注册价格" : "Registration"}
          </p>
          {registrars.length > 0 && (
            <span className="text-[10px] text-muted-foreground/40">{isZh ? "以官网为准" : "Reference only"}</span>
          )}
        </div>

        {loadingPrices ? (
          <div className="px-4 sm:px-5 pb-4 pt-2 space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-3 py-1.5">
                <div className="w-8 h-8 rounded-lg bg-muted/50 animate-pulse shrink-0" />
                <div className="flex-1 h-3.5 rounded bg-muted/40 animate-pulse" />
                <div className="w-16 h-4 rounded bg-muted/40 animate-pulse shrink-0" />
              </div>
            ))}
          </div>
        ) : registrars.length > 0 ? (
          <div className="pb-1">
            {registrars.map((r, idx) => (
              <RegistrarRow key={r.registrar} r={r} idx={idx} priceField="new" colorFirst={true} />
            ))}
          </div>
        ) : (
          <div className="px-4 sm:px-5 pb-4 pt-1">
            <p className="text-[10px] text-muted-foreground/40 mb-3 text-center">
              {isZh ? "暂无聚合价格数据，可直接前往以下注册商查询" : "No aggregated price data — search directly on these registrars"}
            </p>
            <div className="grid grid-cols-2 gap-2">
              {[
                { name: "Namecheap", color: "#de3723", logo: "namecheap.com", url: `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(domain)}` },
                { name: "GoDaddy",   color: "#1bdbdb", logo: "godaddy.com",   url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(domain)}` },
                { name: "Porkbun",   color: "#f76b8a", logo: "porkbun.com",   url: `https://porkbun.com/checkout/search?q=${encodeURIComponent(domain)}` },
                { name: "Dynadot",   color: "#4e2998", logo: "dynadot.com",   url: `https://www.dynadot.com/domain/search.html?domain=${encodeURIComponent(domain)}` },
                { name: "Cloudflare",color: "#f48120", logo: "cloudflare.com",url: `https://www.cloudflare.com/products/registrar/` },
                { name: "Name.com",  color: "#0066cc", logo: "name.com",      url: `https://www.name.com/domain/search?search=${encodeURIComponent(domain)}` },
              ].map(reg => (
                <a
                  key={reg.name}
                  href={reg.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-2.5 py-2 rounded-lg border border-border/50 hover:border-primary/30 hover:bg-muted/40 transition-all group"
                >
                  <DomainFavicon
                    domain={reg.logo}
                    size={16}
                    className="w-4 h-4 rounded-sm shrink-0"
                    fallback={<RiGlobalLine className="w-4 h-4 text-muted-foreground/50 shrink-0" />}
                  />
                  <span className="text-xs font-medium text-foreground/80 group-hover:text-foreground transition-colors truncate flex-1">{reg.name}</span>
                  <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/30 group-hover:text-muted-foreground/60 shrink-0 transition-colors" />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Renewal prices */}
        {!loadingPrices && renewRegistrars.length > 0 && (
          <>
            <div className="border-t border-border/40 px-4 sm:px-5 pt-4 pb-1 flex items-center justify-between">
              <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 font-bold uppercase tracking-wider">
                <RiLoopLeftLine className="w-3 h-3" />
                {isZh ? "续费价格" : "Renewal"}
              </p>
            </div>
            <div className="pb-1">
              {renewRegistrars.map((r, idx) => (
                <RegistrarRow key={`renew-${r.registrar}`} r={r} idx={idx} priceField="renew" colorFirst={false} />
              ))}
            </div>
          </>
        )}

        {/* Footer note */}
        {!loadingPrices && registrars.length > 0 && (
          <p className="text-[10px] text-muted-foreground/30 px-4 sm:px-5 pt-2.5 pb-3">
            {isZh ? "数据来源：nazhumi.com & miqingju.com · 价格仅供参考" : "Source: nazhumi.com & miqingju.com · Reference only"}
          </p>
        )}
      </div>
    </div>
  );
}


const _EMPTY_WHOIS_RESULT: WhoisResult = {
  status: false,
  time: 0,
  cached: false,
  result: { ...initialWhoisAnalyzeResult },
};

/** Extract the cleaned query target from Next.js router.query (client-side). */
function targetFromRouterQuery(query: NodeJS.Dict<string | string[]>): string {
  const segments = (query.query as string[] | undefined) ?? [];
  return cleanDomain(segments.join("/").replace(/\s+/g, ""));
}

/** Text ad banner — multi-item with 4s fade cycling, only shown after results load. */
function ResultTextAd({ loading = false, inline = false }: { loading?: boolean; inline?: boolean }) {
  const settings = useSiteSettings();
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  const rawText = settings.result_ad_text || "";
  const items = React.useMemo(
    () => rawText.split("|").map(s => s.trim()).filter(Boolean),
    [rawText],
  );

  React.useEffect(() => {
    if (items.length <= 1) return;
    setActiveIdx(0);
    const timer = setInterval(() => {
      setFading(true);
      setTimeout(() => {
        setActiveIdx(i => (i + 1) % items.length);
        setFading(false);
      }, 350);
    }, 5000);
    return () => clearInterval(timer);
  }, [items.length, rawText]);

  if (settings.result_ad_enabled !== "1") return null;
  if (items.length === 0) return null;
  if (loading) return null;

  const label = settings.result_ad_label || "广告";
  const url   = settings.result_ad_url;
  const text  = items[activeIdx];

  const inner = (
    <div className="flex items-center gap-2 py-1 cursor-default">
      <RiMegaphoneLine
        className="w-3.5 h-3.5 shrink-0 text-primary/70"
        style={{ animation: "ad-icon 2.4s ease-in-out infinite" }}
      />
      <span
        className="text-xs text-foreground/65 flex-1 leading-snug"
        style={{ opacity: fading ? 0 : 1, transition: "opacity 0.35s ease" }}
      >
        <span className="font-semibold text-primary/80 mr-1">{label}：</span>
        {text}
      </span>
      {url && <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/40 shrink-0" />}
      <style>{`
        @keyframes ad-icon {
          0%, 100% { transform: rotate(-8deg) scale(1);   opacity: 0.7; }
          25%       { transform: rotate(8deg) scale(1.1);  opacity: 1;   }
          50%       { transform: rotate(-6deg) scale(1);   opacity: 0.7; }
          75%       { transform: rotate(6deg) scale(1.05); opacity: 1;   }
        }
      `}</style>
    </div>
  );

  const wrapper = url ? (
    <Link href={url} target="_blank" rel="noopener noreferrer sponsored" className="block hover:opacity-80 transition-opacity">
      {inner}
    </Link>
  ) : inner;

  if (inline) {
    return <div className="sm:hidden mt-3">{wrapper}</div>;
  }
  return <div className="hidden sm:block mt-4">{wrapper}</div>;
}

export default function LookupPage({
  data: initialData,
  target: propTarget,
  displayTarget: propDisplayTarget,
  origin,
}: {
  data: WhoisResult | null;
  target: string;
  displayTarget: string;
  origin: string;
}) {
  const { t, locale } = useTranslation();
  const router = useRouter();
  const settings = useSiteSettings();
  const hideRawWhois = settings.hide_raw_whois === "1";
  const enableSearchLinks = settings.enable_search_links !== "";

  // ── Shallow-routing target sync ──────────────────────────────────────────
  // `target` starts as the SSR-provided prop.  When the user searches again
  // from the same page (handleSearch uses shallow routing to skip SSR), only
  // router.query changes — props are NOT updated.  We track target in state
  // and re-derive it from router.query so useEffect([target]) re-fires and
  // fetches new data without a full page reload.
  const [target, setTarget] = React.useState(propTarget);
  const [displayTarget, setDisplayTarget] = React.useState(propDisplayTarget);

  useEffect(() => {
    const newTarget = targetFromRouterQuery(router.query);
    if (newTarget && newTarget !== target) {
      setTarget(newTarget);
      setDisplayTarget(newTarget); // domainToUnicode not available client-side
    }
  // router.query.query is the catch-all segment array; re-run when it changes
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.query.query]);

  // When SSR returns cached data (initialData != null), start with it so the
  // server-rendered HTML has real content (better SEO / Googlebot indexing).
  // The client-side useEffect always fires a fresh /api/lookup to get up-to-date
  // data, so the SSR snapshot is just a warm-start hint.
  const [loading, setLoading] = React.useState(initialData == null);
  // refreshing=true means partial RDAP data is shown; WHOIS enrichment still in-flight.
  // A subtle indicator is shown while refreshing, but the main content is visible.
  const [refreshing, setRefreshing] = React.useState(false);
  const [data, setData] = React.useState<WhoisResult>(initialData ?? _EMPTY_WHOIS_RESULT);
  // Incrementing this forces a fresh fetch for the same target (re-query button).
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [expandStatus, setExpandStatus] = React.useState(false);
  const [feedbackOpen, setFeedbackOpen] = React.useState(false);
  const suppressNextLoad = React.useRef(false);
  // Track if the first client-side fetch has completed to avoid flicker:
  // On first load, if SSR already provided data, do a silent background refresh
  // (keep showing SSR data while fresh data loads) instead of flashing a skeleton.
  const firstLoadDone = React.useRef(false);
  const scrollAreaRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleStart = (url: string) => {
      if (suppressNextLoad.current) {
        suppressNextLoad.current = false;
        return;
      }
      if (isSearchRoute(url)) { setLoading(true); setRefreshing(false); }
    };
    // routeChangeComplete is intentionally NOT handled here: the
    // client-side fetch useEffect sets loading=false once data arrives.
    const handleError = () => setLoading(false);
    router.events.on("routeChangeStart", handleStart);
    router.events.on("routeChangeError", handleError);
    return () => {
      router.events.off("routeChangeStart", handleStart);
      router.events.off("routeChangeError", handleError);
    };
  }, [router]);

  // Client-side WHOIS fetch — runs when target changes (shallow nav) or
  // refreshKey increments (re-query button forces a fresh lookup).
  useEffect(() => {
    // Flicker prevention: on the very first client-side render, if SSR already
    // provided data (initialData != null), skip resetting to empty and just
    // silently update the data in the background — no skeleton flash.
    const isFirstLoad = !firstLoadDone.current;
    firstLoadDone.current = true;
    const silentRefresh = isFirstLoad && initialData != null && refreshKey === 0;

    if (!silentRefresh) {
      setLoading(true);
      // Scroll back to top when navigating to a new domain
      if (scrollAreaRef.current) {
        const vp = scrollAreaRef.current.querySelector("[data-radix-scroll-area-viewport]");
        if (vp) vp.scrollTop = 0;
      }
      // Do NOT reset data to _EMPTY_WHOIS_RESULT here.
      // Keeping the previous result visible prevents the layout from
      // collapsing then re-expanding (the "jump") while the new lookup loads.
      // On the very first load data is already _EMPTY_WHOIS_RESULT (initial
      // useState), so the skeleton still shows correctly when there is nothing
      // to display yet.
    }

    let cancelled = false;
    // Use a pre-started fetch if handleSearch already fired one (hides SSR +
    // hydration latency ~400-700 ms inside the reported lookup time).
    // refreshKey > 0 means a forced re-query, skip the prefetch cache.
    const prefetched = refreshKey === 0 ? consumePrefetch(target) : undefined;
    const streamUrl = `/api/lookup-stream?query=${encodeURIComponent(target)}${refreshKey > 0 ? "&nocache=1" : ""}`;
    const responsePromise = prefetched ?? fetch(streamUrl);

    (async () => {
      try {
        const r = await responsePromise;
        if (cancelled) return;

        if (r.status === 401) {
          toast.warning(t("auth.require_login_notice"));
          setTimeout(() => router.replace(`/login?callbackUrl=${encodeURIComponent(router.asPath)}&msg=require_login`), 1200);
          return;
        }

        if (!r.ok || !r.body) {
          // Non-streaming fallback: parse single JSON response
          const d = await r.json().catch(() => null) as WhoisResult | null;
          if (!cancelled && d) {
            setData({ ...d, result: d.result ?? { ...initialWhoisAnalyzeResult } });
          }
          if (!cancelled) { setLoading(false); setRefreshing(false); }
          return;
        }

        // ── Consume NDJSON stream ──────────────────────────────────────────
        // Each newline-delimited JSON line is either a partial (RDAP-only)
        // or final (merged RDAP+WHOIS) result.  Partial results clear the
        // loading skeleton immediately; the final result stops the subtle
        // refreshing indicator.
        const reader = r.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (!cancelled) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            if (!line.trim() || cancelled) continue;
            try {
              const d = JSON.parse(line) as WhoisResult & { partial?: boolean };
              if (cancelled) break;
              setData({ ...d, result: d.result ?? { ...initialWhoisAnalyzeResult } });
              if (d.partial) {
                // First chunk: RDAP data — show result immediately, keep subtle refresh spinner
                setLoading(false);
                setRefreshing(true);
              } else {
                // Final chunk: fully merged result
                setLoading(false);
                setRefreshing(false);
              }
            } catch { /* malformed JSON line, skip */ }
          }
        }

        if (!cancelled) {
          // If stream ended without a final chunk (e.g. single-chunk response),
          // ensure loading/refreshing states are cleared.
          setLoading(false);
          setRefreshing(false);
        }
      } catch {
        if (!cancelled) {
          setData({ status: false, time: 0, cached: false, error: "", result: { ...initialWhoisAnalyzeResult } });
          setLoading(false);
          setRefreshing(false);
        }
      }
    })();

    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, refreshKey]);

  const [showImagePreview, setShowImagePreview] = React.useState(false);
  const [imgWidth, setImgWidth] = React.useState(1200);
  const [imgHeight, setImgHeight] = React.useState(630);
  const [imgTheme, setImgTheme] = React.useState<"light" | "dark">("light");
  const [imgActing, setImgActing] = React.useState<"download" | "copy" | null>(null);
  const copy = useClipboard();
  useSearchHotkeys({});

  useEffect(() => {
    setImgTheme(
      document.documentElement.classList.contains("dark") ? "dark" : "light",
    );
  }, []);

  const isChinese = locale === "zh" || locale === "zh-tw";
  const isZh = isChinese;

  const [reminderDialogOpen, setReminderDialogOpen] = React.useState(false);
  const [stampDetailOpen, setStampDetailOpen] = React.useState(false);
  const [officialPopoverOpen, setOfficialPopoverOpen] = React.useState(false);
  const [officialPopoverPos, setOfficialPopoverPos] = React.useState<{ bottom: number; centerX: number; isMobile: boolean } | null>(null);

  const [verifiedStamps, setVerifiedStamps] = React.useState<
    { id: string; tagName: string; tagStyle: string; cardTheme: string; link: string; nickname: string; description?: string }[]
  >([]);

  const isOfficialDomain = React.useMemo(() => {
    const d = (target || "").toLowerCase().replace(/^www\./, "");
    return MAINSTREAM_DOMAINS.has(d);
  }, [target]);

  type CardThemeDef = {
    hero: string;       shimmer: string;
    badge: string;      btn: string;
    cardBg: string;     cardBorder: string; cardText: string;
    layout?: "default" | "celebrate" | "neon" | "gradient" | "split" | "flash";
    accent?: string;    accentText?: string;
  };
  const CARD_THEMES: Record<string, CardThemeDef> = {
    /* ── 8 standard themes — one per tag style, all default layout ── */
    app: {
      hero: "bg-gradient-to-br from-zinc-600 to-zinc-900",
      shimmer: "text-shimmer", badge: "bg-zinc-100 text-zinc-600 border border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",
      btn: "bg-zinc-900 text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    official: {
      hero: "bg-gradient-to-br from-blue-600 to-indigo-800",
      shimmer: "text-foreground font-black", badge: "bg-blue-50 text-blue-700 border border-blue-200/80 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800/60",
      btn: "bg-blue-700 text-white hover:bg-blue-800",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    aurora: {
      hero: "bg-gradient-to-br from-violet-500 via-fuchsia-500 to-purple-700",
      shimmer: "text-foreground font-black", badge: "bg-violet-50 text-violet-700 border border-violet-200/80 dark:bg-violet-950/60 dark:text-violet-300 dark:border-violet-800/60",
      btn: "bg-violet-600 text-white hover:bg-violet-700",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    emerald: {
      hero: "bg-gradient-to-br from-emerald-400 to-teal-700",
      shimmer: "text-foreground font-black", badge: "bg-emerald-50 text-emerald-700 border border-emerald-200/80 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/60",
      btn: "bg-emerald-600 text-white hover:bg-emerald-700",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    solar: {
      hero: "bg-gradient-to-br from-amber-400 to-orange-600",
      shimmer: "text-foreground font-black", badge: "bg-amber-50 text-amber-700 border border-amber-200/80 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/60",
      btn: "bg-orange-500 text-white hover:bg-orange-600",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    dev: {
      hero: "bg-gradient-to-br from-slate-600 to-[#0d1117]",
      shimmer: "text-[#58a6ff] font-black font-mono", badge: "bg-[#161b22] text-[#58a6ff] border border-[#30363d]",
      btn: "bg-[#238636] text-white hover:bg-[#2ea043]",
      cardBg: "bg-zinc-950", cardBorder: "border-zinc-800", cardText: "text-zinc-200",
    },
    warning: {
      hero: "bg-gradient-to-br from-yellow-400 to-amber-600",
      shimmer: "text-foreground font-black", badge: "bg-yellow-50 text-yellow-800 border border-yellow-300/80 dark:bg-yellow-950/60 dark:text-yellow-300 dark:border-yellow-800/60",
      btn: "bg-amber-500 text-white hover:bg-amber-600",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    premium: {
      hero: "bg-gradient-to-br from-purple-600 via-fuchsia-500 to-rose-500",
      shimmer: "text-foreground font-black", badge: "bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200/80 dark:bg-fuchsia-950/60 dark:text-fuchsia-300 dark:border-fuchsia-800/60",
      btn: "bg-gradient-to-r from-purple-600 to-fuchsia-500 text-white",
      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground",
    },
    /* ── 5 special layout themes ── */
    celebrate: {
      layout: "celebrate",
      hero: "bg-gradient-to-br from-red-700 to-red-900",
      shimmer: "text-white font-black", badge: "bg-amber-400 text-amber-900 border-0",
      btn: "bg-amber-500 text-white hover:bg-amber-600",
      cardBg: "bg-white", cardBorder: "border-amber-100", cardText: "text-gray-900",
      accent: "bg-amber-500", accentText: "text-white",
    },
    neon: {
      layout: "neon",
      hero: "bg-[#050d18]",
      shimmer: "text-white font-black", badge: "bg-cyan-400 text-slate-900 border-0",
      btn: "bg-gradient-to-r from-cyan-400 to-violet-600 text-white",
      cardBg: "bg-[#050d18]", cardBorder: "border-slate-800", cardText: "text-white",
      accent: "text-cyan-400", accentText: "text-cyan-400",
    },
    gradient: {
      layout: "gradient",
      hero: "bg-gradient-to-br from-rose-300 via-sky-300 to-emerald-300",
      shimmer: "text-gray-900 font-black", badge: "bg-black/10 text-gray-800 border border-black/20",
      btn: "bg-gray-900 text-white hover:bg-gray-800",
      cardBg: "bg-transparent", cardBorder: "border-0", cardText: "text-gray-900",
      accent: "bg-gray-900", accentText: "text-white",
    },
    split: {
      layout: "split",
      hero: "bg-black",
      shimmer: "text-white font-black", badge: "bg-blue-500 text-white border-0",
      btn: "bg-gray-900 text-white hover:bg-black",
      cardBg: "bg-white", cardBorder: "border-border/50", cardText: "text-foreground",
      accent: "bg-blue-600", accentText: "text-white",
    },
    flash: {
      layout: "flash",
      hero: "bg-[#FF3800]",
      shimmer: "text-white font-black", badge: "bg-[#FF3800] text-white border-0",
      btn: "bg-gradient-to-r from-orange-500 to-red-600 text-white",
      cardBg: "bg-white", cardBorder: "border-0", cardText: "text-gray-900",
      accent: "bg-yellow-300", accentText: "text-black",
    },
  };

  const STAMP_STYLE_MAP: Record<string, string> = {
    personal: "bg-teal-500 text-white border-0",
    default:  "bg-teal-500 text-white border-0",
    official: "bg-blue-500 text-white border-0",
    brand:    "bg-violet-500 text-white border-0",
    verified: "bg-emerald-500 text-white border-0",
    partner:  "bg-orange-500 text-white border-0",
    dev:      "bg-sky-500 text-white border-0",
    warning:  "bg-amber-400 text-white border-0",
    premium:  "bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-0",
  };

  const STAMP_ICON_MAP: Record<string, React.ElementType> = {
    personal: RiIdCardLine,
    official: RiBuildingLine,
    brand:    RiAwardLine,
    verified: RiShieldCheckLine,
    partner:  RiShakeHandsLine,
    dev:      RiCodeSLine,
    warning:  RiAlertLine,
    premium:  RiVipCrownLine,
    default:  RiShieldCheckLine,
  };

  const STAMP_CARD_MAP: Record<string, { border: string; bg: string; iconColor: string }> = {
    personal: { border: "border-l-teal-500",    bg: "bg-teal-50   dark:bg-teal-900/20",     iconColor: "text-teal-500" },
    official: { border: "border-l-blue-500",    bg: "bg-blue-50   dark:bg-blue-900/20",     iconColor: "text-blue-500" },
    brand:    { border: "border-l-violet-500",  bg: "bg-violet-50 dark:bg-violet-900/20",   iconColor: "text-violet-500" },
    verified: { border: "border-l-emerald-500", bg: "bg-emerald-50 dark:bg-emerald-900/20", iconColor: "text-emerald-500" },
    partner:  { border: "border-l-orange-500",  bg: "bg-orange-50 dark:bg-orange-900/20",   iconColor: "text-orange-500" },
    dev:      { border: "border-l-sky-500",     bg: "bg-sky-50    dark:bg-sky-900/20",      iconColor: "text-sky-500" },
    warning:  { border: "border-l-amber-400",   bg: "bg-amber-50  dark:bg-amber-900/20",    iconColor: "text-amber-500" },
    premium:  { border: "border-l-fuchsia-500", bg: "bg-fuchsia-50 dark:bg-fuchsia-900/20", iconColor: "text-fuchsia-500" },
    default:  { border: "border-l-teal-500",    bg: "bg-teal-50   dark:bg-teal-900/20",     iconColor: "text-teal-500" },
  };

  useEffect(() => {
    const domainKey = data.result?.domain || target;
    if (!domainKey) return;

    let ctrl = new AbortController();

    const fetchStamps = () => {
      ctrl.abort();
      ctrl = new AbortController();
      fetch(`/api/stamp/check?domain=${encodeURIComponent(domainKey)}`, { signal: ctrl.signal })
        .then((r) => r.json())
        .then((d) => setVerifiedStamps(d.stamps || []))
        .catch(() => {});
    };

    // Defer until after initial paint so it doesn't compete with critical rendering
    const timer = setTimeout(fetchStamps, 300);

    // Re-fetch when tab regains focus so admin stamp changes are reflected immediately
    const onVisibility = () => { if (document.visibilityState === "visible") fetchStamps(); };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      clearTimeout(timer);
      ctrl.abort();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [data.result?.domain, target]);

  const FALLBACK_EUR_RATES: Record<string, number> = {
    AUD: 1.65, CAD: 1.49, CHF: 0.94, CNY: 7.82, DKK: 7.46,
    GBP: 0.85, HKD: 8.50, JPY: 162, KRW: 1520, NOK: 11.7,
    NZD: 1.80, SEK: 11.3, SGD: 1.46, TWD: 34.8, USD: 1.09,
  };
  const [eurRates, setEurRates] = React.useState<Record<string, number>>(FALLBACK_EUR_RATES);
  useEffect(() => {
    fetch("https://api.frankfurter.dev/v1/latest")
      .then((r) => r.json())
      .then((d) => { if (d?.rates) setEurRates(d.rates); })
      .catch(() => {});
  }, []);

  function formatRegistrarPrice(amount: number, currency: string): string {
    const cur = (currency ?? "").toUpperCase();
    if (isChinese) {
      if (cur === "CNY") return `¥${amount.toFixed(2)}`;
      const cnyRate = eurRates["CNY"] ?? 7.82;
      const eurAmount = cur === "EUR" ? amount : amount / (eurRates[cur] ?? 1);
      return `¥${(eurAmount * cnyRate).toFixed(2)}`;
    }
    const SYMBOLS: Record<string, string> = {
      USD: "$", EUR: "€", CNY: "¥", GBP: "£",
      CAD: "CA$", AUD: "A$", HKD: "HK$", SGD: "S$",
      NZD: "NZ$", TWD: "NT$", KRW: "₩", JPY: "¥",
    };
    const sym = SYMBOLS[cur] ?? (cur ? cur + "\u00a0" : "$");
    const decimals = ["JPY", "KRW"].includes(cur) ? 0 : 2;
    return `${sym}${amount.toFixed(decimals)}`;
  }

  type TianhuTranslation = { src: string; dst: string | null; parts: { part_name: string; means: string[] }[] } | null;
  const [tianhuTranslation, setTianhuTranslation] = React.useState<TianhuTranslation>(null);

  useEffect(() => {
    setTianhuTranslation(null);
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(target);
    if (!target || isIp) return;
    const timer = setTimeout(() => {
      fetch(`/api/tianhu/translate?domain=${encodeURIComponent(target)}`)
        .then((r) => r.json())
        .then((d) => { if (d.dst) setTianhuTranslation(d); })
        .catch(() => {});
    }, 400);
    return () => clearTimeout(timer);
  }, [target]);

  const current = getWindowHref();
  const queryType = detectQueryType(target);
  const { status, result, error, time, dnsProbe, registryUrl, cached, cachedAt, cacheTtl } = data as typeof data & { registryUrl?: string };

  const { data: session, status: sessionStatus } = useSession();

  // Auto-open the reminder dialog when navigated here with ?subscribe=1
  const autoOpenedRef = React.useRef(false);
  // Reset the guard whenever the domain changes so re-visiting with ?subscribe=1 always works
  const prevTargetRef = React.useRef(target);
  if (prevTargetRef.current !== target) {
    prevTargetRef.current = target;
    autoOpenedRef.current = false;
  }
  useEffect(() => {
    if (router.query.subscribe !== "1") return;
    if (sessionStatus === "loading") return;
    if (autoOpenedRef.current) return;
    autoOpenedRef.current = true;

    // Capture current path with ?subscribe=1 for use in callbacks before we clean the URL
    const pathWithSubscribe = router.asPath;
    // Remove the param from the URL cleanly (no re-fetch)
    const { subscribe: _s, ...rest } = router.query;
    router.replace({ pathname: router.pathname, query: rest }, undefined, { shallow: true });

    if (!session) {
      // Keep ?subscribe=1 in callbackUrl so the modal auto-opens after login
      router.push(`/login?callbackUrl=${encodeURIComponent(pathWithSubscribe)}`);
      return;
    }
    if (!(session?.user as any)?.subscriptionAccess) {
      toast.info(isChinese ? "需要开通会员才能使用域名订阅提醒" : "Subscription required to use domain reminders.", {
        action: { label: isChinese ? "去开通" : "Upgrade", onClick: () => router.push("/payment/checkout") },
      });
      return;
    }
    setReminderDialogOpen(true);
  }, [router.query.subscribe, sessionStatus]);

  const handleSearch = (query: string) => {
    const url = toSearchURI(query);
    if (url === router.asPath) return;
    const cleaned = cleanDomain(query.replace(/\s+/g, ""));
    if (cleaned) prefetchLookup(cleaned);
    // Shallow routing: URL changes but SSR is skipped entirely (~500 ms saved).
    // router.query updates → targetFromRouterQuery → setTarget → useEffect
    // re-fetches the new domain without unmounting/remounting the page.
    router.push(url, undefined, { shallow: true });
  };

  /** Force a fresh lookup for the current target (bypasses cache). */
  const handleRefresh = () => setRefreshKey((k) => k + 1);

  useEffect(() => {
    if (!status) return;
    const regStatus =
      status && result ? "registered" :
      dnsProbe?.registrationStatus === "unregistered" ? "unregistered" :
      dnsProbe?.registrationStatus === "registered" ? "registered" :
      "unknown";

    addHistory(target, regStatus as any);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, target]);

  const registrarIcon = result
    ? getRegistrarIcon(result.registrar, result.registrarURL)
    : null;
  const registrarInitial = result
    ? result.registrar && result.registrar !== "Unknown"
      ? result.registrar.charAt(0).toUpperCase()
      : "?"
    : "?";

  const displayStatuses = useMemo(() => {
    if (!result || result.status.length === 0) return [];
    if (result.status.length > 5 && !expandStatus)
      return result.status.slice(0, 5);
    return result.status;
  }, [result, expandStatus]);

  const hasIpFields =
    result &&
    ((result.cidr && result.cidr !== "Unknown") ||
      (result.netRange && result.netRange !== "Unknown") ||
      (result.netName && result.netName !== "Unknown") ||
      (result.netType && result.netType !== "Unknown") ||
      (result.originAS && result.originAS !== "Unknown") ||
      (result.inetNum && result.inetNum !== "Unknown") ||
      (result.inet6Num && result.inet6Num !== "Unknown"));

  const INVALID_FIELD_VALUES = new Set([
    "unknown", "n/a", "na", "none", "null", "undefined", "-", "--",
  ]);
  const isValidField = (v: string | null | undefined): boolean => {
    if (!v || !v.trim()) return false;
    return !INVALID_FIELD_VALUES.has(v.trim().toLowerCase());
  };

  const hasRegistrant =
    result &&
    (isValidField(result.registrantName) ||
      isValidField(result.registrantOrganization) ||
      isValidField(result.registrantCountry) ||
      isValidField(result.registrantProvince) ||
      isValidField(result.registrantCity) ||
      isValidField(result.registrantAddress) ||
      isValidField(result.registrantPostalCode) ||
      isValidField(result.registrantEmail) ||
      isValidField(result.registrantPhone) ||
      isValidField(result.registrantFax));

  const hasAdminContact =
    result &&
    (isValidField(result.adminName) ||
      isValidField(result.adminOrganization) ||
      isValidField(result.adminEmail) ||
      isValidField(result.adminPhone) ||
      isValidField(result.adminCountry));

  const hasTechContact =
    result &&
    (isValidField(result.techName) ||
      isValidField(result.techOrganization) ||
      isValidField(result.techEmail) ||
      isValidField(result.techPhone));

  return (
    <>
      <Head>
        <link rel="preconnect" href="https://www.nazhumi.com" />
        <link rel="preconnect" href="https://api.frankfurter.dev" />
        <link rel="dns-prefetch" href="https://www.miqingju.com" />
        {(() => {
          const r = result;
          const isRegistered = status && r;
          const registrar = isRegistered && r.registrar && r.registrar !== "Unknown" ? r.registrar : null;
          const creation = isRegistered && r.creationDate && r.creationDate !== "Unknown" ? r.creationDate : null;
          const expiry = isRegistered && r.expirationDate && r.expirationDate !== "Unknown" ? r.expirationDate : null;
          const ns = isRegistered && Array.isArray(r.nameServers) && r.nameServers.length > 0 ? r.nameServers[0] : null;
          const domainAge = isRegistered && typeof r.domainAge === "number" ? r.domainAge : null;
          const regStatus = !status
            ? "unknown"
            : r?.status?.some(s => s.status?.toLowerCase().includes("reserved")) ? "reserved"
            : r ? "registered" : "unknown";

          const isZhMeta = locale.startsWith("zh");
          const ogLocale = locale === "zh-tw" ? "zh_TW" : isZhMeta ? "zh_CN" : locale === "ja" ? "ja_JP" : locale === "ko" ? "ko_KR" : locale === "de" ? "de_DE" : locale === "fr" ? "fr_FR" : locale === "ru" ? "ru_RU" : "en_US";
          const metaLang = locale === "zh-tw" ? "zh-TW" : isZhMeta ? "zh-CN" : locale;

          const descParts: string[] = [isZhMeta
            ? `${displayTarget} 的 WHOIS / RDAP 查询结果`
            : `WHOIS / RDAP lookup result for ${displayTarget}`];
          if (regStatus === "registered") descParts.push(isZhMeta ? "已注册" : "Registered");
          if (registrar) descParts.push(isZhMeta ? `注册商：${registrar}` : `Registrar: ${registrar}`);
          if (creation) descParts.push(isZhMeta ? `注册：${creation.slice(0, 10)}` : `Created: ${creation.slice(0, 10)}`);
          if (expiry) descParts.push(isZhMeta ? `到期：${expiry.slice(0, 10)}` : `Expires: ${expiry.slice(0, 10)}`);
          if (domainAge) descParts.push(isZhMeta ? `域龄 ${domainAge} 天` : `${domainAge} days old`);
          if (ns) descParts.push(`NS: ${ns.toLowerCase()}`);
          const description = descParts.join(" · ");

          const keywords = isZhMeta
            ? [displayTarget, `${displayTarget} whois`, `${displayTarget} 域名查询`,
               `${displayTarget} 注册信息`, `${displayTarget} 到期时间`,
               ...(registrar ? [`${registrar} 域名`] : []),
               "域名查询", "whois查询", "rdap", "域名信息"].join(", ")
            : [displayTarget, `${displayTarget} whois`, `${displayTarget} domain lookup`,
               `${displayTarget} registration`, `${displayTarget} expiry`,
               ...(registrar ? [`${registrar} domain`] : []),
               "domain lookup", "whois lookup", "rdap", "domain info"].join(", ");

          const canonicalUrl = `${origin}/${target}`;
          // Build OG URL with embedded WHOIS fields so the edge handler skips
          // the internal /api/lookup fetch (saves 3-10 s on first crawl).
          const ogParams = new URLSearchParams();
          ogParams.set("query", target);
          ogParams.set("theme", "dark");
          if (r && isRegistered) {
            const ok = (v: unknown): v is string =>
              typeof v === "string" && v.length > 0 && v !== "Unknown";
            if (ok(r.registrar))              ogParams.set("reg", r.registrar.slice(0, 60));
            if (ok(r.creationDate))           ogParams.set("cr",  r.creationDate.slice(0, 10));
            if (ok(r.expirationDate))         ogParams.set("ex",  r.expirationDate.slice(0, 10));
            if (ok(r.updatedDate))            ogParams.set("up",  r.updatedDate.slice(0, 10));
            if (r.remainingDays != null)      ogParams.set("rd",  String(r.remainingDays));
            if (r.domainAge != null)          ogParams.set("age", String(r.domainAge));
            if (Array.isArray(r.nameServers) && r.nameServers.length > 0)
              ogParams.set("ns", r.nameServers.slice(0, 3).join(","));
            if (Array.isArray(r.status) && r.status.length > 0)
              ogParams.set("st", r.status.slice(0, 4).map((s: { status: string }) => s.status).join(","));
            if (ok(r.registrantCountry))      ogParams.set("co",  r.registrantCountry);
            if (ok(r.registrantOrganization)) ogParams.set("org", r.registrantOrganization.slice(0, 50));
            if (ok(r.dnssec))                 ogParams.set("dn",  r.dnssec.slice(0, 30));
            if (ok(r.whoisServer))            ogParams.set("ws",  r.whoisServer.slice(0, 60));
          }
          const ogImage = `${origin}/api/og?${ogParams.toString()}`;

          const jsonLd = JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": isZhMeta ? `${displayTarget} WHOIS 查询` : `${displayTarget} WHOIS Lookup`,
            "description": description,
            "url": canonicalUrl,
            "inLanguage": metaLang,
            "isPartOf": { "@type": "WebSite", "url": origin, "name": isZhMeta ? "RDAP+WHOIS 域名查询" : "RDAP+WHOIS Domain Lookup" },
            "about": {
              "@type": "Dataset",
              "name": isZhMeta ? `${displayTarget} 域名注册信息` : `${displayTarget} Domain Registration Info`,
              "description": description,
              "keywords": isZhMeta
                ? `${displayTarget}, whois, rdap, 域名注册, 域名查询`
                : `${displayTarget}, whois, rdap, domain registration, domain lookup`,
              ...(isRegistered && r ? {
                "temporalCoverage": creation && expiry ? `${creation.slice(0,10)}/${expiry.slice(0,10)}` : undefined,
              } : {}),
            },
            "breadcrumb": {
              "@type": "BreadcrumbList",
              "itemListElement": [
                { "@type": "ListItem", "position": 1, "name": isZhMeta ? "首页" : "Home", "item": origin },
                { "@type": "ListItem", "position": 2, "name": isZhMeta ? "域名查询" : "Domain Lookup", "item": `${origin}/` },
                { "@type": "ListItem", "position": 3, "name": displayTarget, "item": canonicalUrl },
              ],
            },
          });

          const metaTitle = isZhMeta
            ? `${displayTarget} WHOIS 查询 · 注册信息 · 到期时间`
            : `${displayTarget} WHOIS Lookup · Registration · Expiry`;
          const ogTitle = isZhMeta
            ? `${displayTarget} WHOIS 查询 · 注册信息`
            : `${displayTarget} WHOIS Lookup · Registration`;
          const twTitle = isZhMeta
            ? `${displayTarget} WHOIS 查询`
            : `${displayTarget} WHOIS Lookup`;

          return (
            <>
              <title key="title">{metaTitle}</title>
              <meta name="description" content={description} />
              <meta name="keywords" content={keywords} />
              <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1" />
              <link rel="canonical" href={canonicalUrl} />

              <meta property="og:type" content="website" />
              <meta property="og:url" content={canonicalUrl} />
              <meta property="og:title" content={ogTitle} />
              <meta property="og:description" content={description} />
              <meta property="og:image" content={ogImage} />
              <meta property="og:image:width" content="1200" />
              <meta property="og:image:height" content="630" />
              <meta property="og:locale" content={ogLocale} />

              <meta name="twitter:card" content="summary_large_image" />
              <meta name="twitter:title" content={twTitle} />
              <meta name="twitter:description" content={description} />
              <meta name="twitter:image" content={ogImage} />

              <script
                type="application/ld+json"
                dangerouslySetInnerHTML={{ __html: jsonLd }}
              />
            </>
          );
        })()}
      </Head>
      <ScrollArea ref={scrollAreaRef} className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 min-h-[calc(100vh-4rem)]">
          <div className="mb-6 relative z-10">
            <div className="relative group">
              <SearchBox
                initialValue={target}
                onSearch={handleSearch}
                loading={loading}
              />
              <div className="absolute left-4 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none opacity-50 group-hover:opacity-100 transition-opacity">
                <KeyboardShortcut k="/" />
              </div>
            </div>
            <SearchHotkeysText className="hidden sm:flex mt-2 px-1 justify-end" />
          </div>

          <div className="relative">
            <QueryProgressBar loading={loading} refreshing={refreshing} />
            <motion.div
              initial={false}
              animate={{ opacity: loading ? 0.85 : 1 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              style={{ pointerEvents: loading ? "none" : undefined }}
            >

          {result && (
            <div
              className="hidden sm:flex items-center flex-wrap gap-2 mb-6"
            >
              {result.registerPrice &&
                result.registerPrice.new !== -1 &&
                result.registerPrice.currency !== "Unknown" && (
                  <Link
                    target="_blank"
                    href={result.registerPrice.externalLink}
                    className="flex px-2 py-0.5 rounded-md border bg-background items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                  >
                    <RiBillLine className={cn("w-3 h-3 shrink-0", result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                    <span
                      className={cn(
                        "text-[11px] sm:text-xs font-normal",
                        result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground",
                      )}
                    >
                      {t("register_price")}
                      {formatRegistrarPrice(result.registerPrice.new as number, result.registerPrice.currency)}
                    </span>
                  </Link>
                )}
              {result.renewPrice &&
                result.renewPrice.renew !== -1 &&
                result.renewPrice.currency !== "Unknown" && (
                  <Link
                    href={result.renewPrice.externalLink}
                    target="_blank"
                    className="flex px-2 py-0.5 rounded-md border bg-background items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                  >
                    <RiExchangeDollarFill className={cn("w-3 h-3 shrink-0", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                    <span className={cn("text-[11px] sm:text-xs font-normal", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")}>
                      {t("renew_price")}
                      {formatRegistrarPrice(result.renewPrice.renew as number, result.renewPrice.currency)}
                    </span>
                  </Link>
                )}
              {result.negotiable !== null && (
                <div className="flex px-2 py-0.5 rounded-md border bg-background items-center space-x-1">
                  <RiExchangeDollarFill className="w-3 h-3 text-muted-foreground shrink-0" />
                  <span className="text-[11px] sm:text-xs font-normal text-muted-foreground">
                    {t("negotiable")}
                    <span className={result.negotiable ? "text-amber-500" : "text-emerald-600 dark:text-emerald-400"}>
                      {result.negotiable ? t("negotiable_yes") : t("negotiable_no")}
                    </span>
                  </span>
                </div>
              )}
              <div className="flex-grow" />
            </div>
          )}

          <AnimatePresence initial={false}>
          {loading && !status && (
            <motion.div
              key="skeleton"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, transition: { duration: 0.15, ease: "easeIn" } }}
              transition={{ duration: 0.12 }}
              className="grid grid-cols-1 gap-6"
            >
              {/* Main domain info card */}
              <div className="glass-panel rounded-xl p-8 sm:p-10">
                <div className="space-y-6">
                  {/* Header: icon + domain name */}
                  <div className="flex items-center gap-4">
                    <div className="h-11 w-11 rounded-full bg-muted/40 animate-pulse shrink-0" />
                    <div className="flex-1 min-w-0">
                      {target ? (
                        <div className="flex items-center gap-2">
                          <p className="text-lg font-semibold font-mono truncate">{target}</p>
                          <RiLoader4Line className="w-4 h-4 text-muted-foreground/60 animate-spin shrink-0" />
                        </div>
                      ) : (
                        <div className="h-5 w-40 rounded bg-muted/40 animate-pulse" />
                      )}
                      <div className="h-3.5 w-28 rounded bg-muted/30 animate-pulse mt-2" />
                    </div>
                  </div>
                  {/* Status badge row */}
                  <div className="flex gap-2 flex-wrap">
                    <div className="h-6 w-24 rounded-full bg-muted/40 animate-pulse" />
                    <div className="h-6 w-32 rounded-full bg-muted/30 animate-pulse" />
                  </div>
                  {/* Date rows */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
                    {[1,2,3].map(i => (
                      <div key={i} className="space-y-1.5">
                        <div className="h-3 w-16 rounded bg-muted/25 animate-pulse" />
                        <div className="h-4 w-24 rounded bg-muted/35 animate-pulse" />
                      </div>
                    ))}
                  </div>
                  {/* Registrar row */}
                  <div className="space-y-1.5 pt-1">
                    <div className="h-3 w-14 rounded bg-muted/25 animate-pulse" />
                    <div className="h-4 w-48 rounded bg-muted/35 animate-pulse" />
                  </div>
                  {/* Action buttons */}
                  <div className="flex gap-3 pt-1">
                    <div className="h-8 w-24 rounded-md bg-muted/40 animate-pulse" />
                    <div className="h-8 w-24 rounded-md bg-muted/30 animate-pulse" />
                    <div className="h-8 w-20 rounded-md bg-muted/25 animate-pulse" />
                  </div>
                </div>
              </div>

              {/* Secondary cards row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                <div className="glass-panel rounded-xl p-6">
                  <div className="space-y-3">
                    <div className="h-4 w-28 rounded bg-muted/40 animate-pulse" />
                    <div className="space-y-2">
                      <div className="h-3.5 w-full rounded bg-muted/25 animate-pulse" />
                      <div className="h-3.5 w-5/6 rounded bg-muted/25 animate-pulse" />
                      <div className="h-3.5 w-4/6 rounded bg-muted/25 animate-pulse" />
                    </div>
                  </div>
                </div>
                <div className="glass-panel rounded-xl p-6">
                  <div className="space-y-3">
                    <div className="h-4 w-24 rounded bg-muted/40 animate-pulse" />
                    <div className="space-y-2">
                      <div className="h-3.5 w-full rounded bg-muted/25 animate-pulse" />
                      <div className="h-3.5 w-3/4 rounded bg-muted/25 animate-pulse" />
                      <div className="h-3.5 w-5/6 rounded bg-muted/25 animate-pulse" />
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
          </AnimatePresence>

          {!loading && !status && (() => {
            const hasErrorRaw = !!(result && (result.rawWhoisContent || result.rawRdapContent));
            return (
            <motion.div
              key={target}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.26, ease: [0.22, 1, 0.36, 1], delay: 0.06 }}
            >
            <div
              className="grid grid-cols-1 lg:grid-cols-12 gap-6"
            >
              <div className={cn(hasErrorRaw ? "lg:col-span-8" : "lg:col-span-12", "space-y-6")}>
                {error === "INVALID_DOMAIN_TLD" ? (
                  <div className="glass-panel border border-amber-300/50 dark:border-amber-700/40 rounded-xl p-8 sm:p-12 text-center">
                    <div className="w-16 h-16 bg-amber-50 dark:bg-amber-950/30 rounded-full flex items-center justify-center mx-auto mb-5">
                      <RiErrorWarningLine className="w-8 h-8 text-amber-500" />
                    </div>
                    <Badge variant="outline" className="mb-4 font-mono text-[10px] font-bold uppercase tracking-wider text-amber-600 border-amber-400/50">
                      INVALID TLD
                    </Badge>
                    <h2 className="text-2xl font-bold mb-2">
                      {isChinese ? `".${target.split(".").pop()}" 不是真实的域名后缀` : `".${target.split(".").pop()}" isn't a real TLD`}
                    </h2>
                    <p className="text-muted-foreground max-w-md mx-auto text-sm leading-relaxed mb-2">
                      {isChinese
                        ? `我们查遍了 ICANN 的所有顶级域名列表，没找到 `
                        : `We searched the entire ICANN TLD registry and couldn't find `}
                      <span className="font-mono font-semibold text-foreground">{`.${target.split(".").pop()}`}</span>
                      {isChinese ? `。请检查拼写，常见的有 .com .net .org .io .cn` : `. Check for typos — try .com .net .org .io`}
                    </p>
                    <p className="text-xs text-muted-foreground/60 mb-8">
                      {isChinese ? "WHOIS 查询不支持不存在的后缀，这不是 bug，是常识。" : "WHOIS doesn't work for non-existent TLDs. Not a bug — just how the internet works."}
                    </p>
                    <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                      <Link href="/">
                        <Button className="gap-2">
                          <RiSearchLine className="w-4 h-4" />
                          {isChinese ? "重新搜索" : "Search Again"}
                        </Button>
                      </Link>
                    </div>
                  </div>
                ) : dnsProbe?.registrationStatus === "registered" ? (
                  <>
                    <div className="glass-panel border border-emerald-400/40 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-xl p-6 sm:p-8 relative overflow-hidden">
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                        <div>
                          <div className="flex items-center gap-3 mb-2">
                            <Badge
                              variant="outline"
                              className="text-[10px] font-bold uppercase tracking-wider font-mono"
                            >
                              {queryType}
                            </Badge>
                          </div>
                          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-1 uppercase">
                            {displayTarget}
                          </h2>
                          <p className="text-muted-foreground text-sm mt-2 max-w-sm leading-relaxed">
                            {t("registered_no_whois_desc")}
                          </p>
                        </div>
                        <div className="flex flex-col items-start sm:items-end gap-2 shrink-0">
                          <Badge
                            variant="outline"
                            className="text-emerald-600 border-emerald-400/50 bg-emerald-50 dark:bg-emerald-950/30 font-medium"
                          >
                            <div className="w-2 h-2 rounded-full bg-emerald-500 mr-1.5" />
                            {t("registered_no_whois")}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground font-mono">
                            {time.toFixed(2)}s
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-3">
                      <Button variant="outline" size="sm" onClick={handleRefresh}>
                        {t("re_query")}
                      </Button>
                      {registryUrl && (
                        <a href={registryUrl} target="_blank" rel="noopener noreferrer">
                          <Button variant="outline" size="sm" className="gap-2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                            {t("registry_lookup")}
                          </Button>
                        </a>
                      )}
                      <Link href="/">
                        <Button variant="outline" size="sm">{t("new_search")}</Button>
                      </Link>
                    </div>
                  </>
                ) : dnsProbe?.registrationStatus === "unregistered" ? (
                  <AvailableDomainCard domain={target} locale={locale} isPremiumByWhois={result ? getDomainRegistrationStatus(result, locale).isPremiumReserved : false} />
                ) : (
                  <>
                    <div className="glass-panel border border-border rounded-xl p-8 sm:p-12 text-center">
                      <div className="w-16 h-16 bg-red-50 dark:bg-red-950/30 rounded-full flex items-center justify-center mx-auto mb-6">
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          width="32"
                          height="32"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          className="text-red-500"
                        >
                          <path d="m21 21-4.3-4.3" />
                          <circle cx="11" cy="11" r="8" />
                          <path d="m8 8 6 6" />
                          <path d="m14 8-6 6" />
                        </svg>
                      </div>
                      <h2 className="text-2xl font-bold mb-2">
                        {t("lookup_failed")}
                      </h2>
                      <p className="text-muted-foreground max-w-md mx-auto text-sm leading-relaxed mb-8">
                        {t("lookup_failed_description")}{" "}
                        <span className="font-mono font-medium text-foreground">
                          {target}
                        </span>
                        {". "}
                        {error || t("lookup_failed_fallback")}
                      </p>
                      <div className="flex flex-col sm:flex-row items-center justify-center gap-3 flex-wrap">
                        <Button onClick={handleRefresh}>
                          {t("try_again")}
                        </Button>
                        {registryUrl && (
                          <a href={registryUrl} target="_blank" rel="noopener noreferrer">
                            <Button variant="outline" className="gap-2">
                              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                              {isChinese ? "在注册局查询" : "Look up at Registry"}
                            </Button>
                          </a>
                        )}
                        <Link href="/">
                          <Button variant="outline">{t("new_search")}</Button>
                        </Link>
                      </div>
                    </div>
                  </>
                )}

                {/* External search engine links — controlled by admin toggle */}
                {queryType === "domain" && enableSearchLinks && (
                  <div className="glass-panel border border-border rounded-xl p-5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                      <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
                      </svg>
                      {isChinese ? "在搜索引擎中查询" : "Search Engine Lookup"}
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {/* Google search for the domain */}
                      <a
                        href={`https://www.google.com/search?q=${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Google
                      </a>
                      {/* Bing search for the domain */}
                      <a
                        href={`https://www.bing.com/search?q=${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg width="13" height="13" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                          <path d="M5 3v14.544l4.038 2.285 7.103-4.55-4.442-1.59V5.98L5 3zm4.038 10.285 3.647 1.305-3.647 2.337v-3.642z" fill="#0078D4"/>
                        </svg>
                        Bing
                      </a>
                      {/* Baidu search for the domain */}
                      <a
                        href={`https://www.baidu.com/s?wd=${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                          <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 2.5a7.5 7.5 0 1 1 0 15 7.5 7.5 0 0 1 0-15z" fill="#2932E1"/>
                          <text x="12" y="16" textAnchor="middle" fontSize="9" fontWeight="bold" fill="#2932E1">百</text>
                        </svg>
                        {isChinese ? "百度" : "Baidu"}
                      </a>
                      {/* Google site: check if this page is indexed */}
                      <a
                        href={`https://www.google.com/search?q=site:x.rw/${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg className="w-3 h-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                        </svg>
                        {isChinese ? "谷歌收录查询" : "Google Index Check"}
                      </a>
                      {/* Bing site: check */}
                      <a
                        href={`https://www.bing.com/search?q=site:x.rw/${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg className="w-3 h-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                        </svg>
                        {isChinese ? "必应收录查询" : "Bing Index Check"}
                      </a>
                    </div>
                  </div>
                )}

                {dnsProbe?.registrationStatus !== "registered" &&
                dnsProbe?.registrationStatus !== "unregistered" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                  <div className="glass-panel border border-border rounded-xl p-6">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                      <svg
                        className="w-4 h-4"
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <circle cx="12" cy="12" r="10" />
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                        <line x1="12" y1="17" x2="12.01" y2="17" />
                      </svg>
                      {t("common_issues")}
                    </h3>
                    <ul className="space-y-3">
                      {[
                        {
                          title: t("issue_invalid_tld"),
                          desc: t("issue_invalid_tld_desc"),
                        },
                        {
                          title: t("issue_not_registered"),
                          desc: t("issue_not_registered_desc"),
                        },
                        {
                          title: t("issue_rate_limited"),
                          desc: t("issue_rate_limited_desc"),
                        },
                      ].map((item) => (
                        <li key={item.title} className="flex items-start gap-2">
                          <div className="mt-1.5 w-1 h-1 rounded-full bg-muted-foreground/30 shrink-0" />
                          <p className="text-[11px] text-muted-foreground leading-normal">
                            <strong className="text-foreground">
                              {item.title}:
                            </strong>{" "}
                            {item.desc}
                          </p>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="glass-panel border border-border rounded-xl p-6">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                      <RiTimeLine className="w-4 h-4" />
                      {t("query_details")}
                    </h3>
                    <div className="space-y-3 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground font-mono uppercase">
                          {t("target")}
                        </span>
                        <span className="font-mono font-medium">{target}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground font-mono uppercase">
                          {t("type")}
                        </span>
                        <Badge
                          variant="outline"
                          className="text-[10px] font-mono"
                        >
                          {queryType}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground font-mono uppercase">
                          {t("time")}
                        </span>
                        <span className="font-mono">{time.toFixed(2)}s</span>
                      </div>
                    </div>
                  </div>
                </div>
                )}
              </div>

              {hasErrorRaw && !hideRawWhois && (
                <div className="lg:col-span-4">
                  <ResponsePanel
                    whoisContent={result!.rawWhoisContent || ""}
                    rdapContent={result!.rawRdapContent}
                    target={target}
                    copy={copy}
                  />
                </div>
              )}
            </div>
            </motion.div>
            );
          })()}

          {status && result && (
            <>
              <motion.div
                variants={CARD_CONTAINER_VARIANTS}
                initial="hidden"
                animate="visible"
                className="grid grid-cols-1 lg:grid-cols-12 gap-6"
              >
                {" "}
                <motion.div variants={CARD_ITEM_VARIANTS} className="lg:col-span-8 space-y-6">
                  <div className="glass-panel border border-border rounded-xl p-6 sm:p-8 relative overflow-hidden">
                    {(() => {
                      const rc = result.registrantCountry?.trim().toUpperCase();
                      const hasCountryDot = !!rc && rc !== "UNKNOWN" && rc in GLOBE_COUNTRY_COORDS;
                      return (
                        <div className={cn(
                          "absolute top-3 right-2 select-none w-[120px] h-[120px]",
                          hasCountryDot ? "opacity-80 z-10" : "opacity-60 pointer-events-none overflow-hidden"
                        )}>
                          <CssGlobe countryCode={hasCountryDot ? rc : undefined} />
                        </div>
                      );
                    })()}
                    <div className="relative z-10">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge
                          variant="outline"
                          className="text-[10px] font-bold uppercase tracking-wider font-mono"
                        >
                          {queryType}
                        </Badge>
                        <button
                          onClick={() => {
                            if (!session) {
                              toast.info(isChinese ? "请先登录再订阅域名提醒" : "Please log in to subscribe for reminders");
                              router.push(`/login?callbackUrl=${encodeURIComponent(`/${result.domain || target}`)}`);
                              return;
                            }
                            if (!(session?.user as any)?.subscriptionAccess) {
                              toast.info(isChinese ? "需要开通会员才能使用域名订阅提醒" : "Subscription required to use domain reminders.", {
                                action: { label: isChinese ? "去开通" : "Upgrade", onClick: () => router.push("/payment/checkout") },
                              });
                              return;
                            }
                            setReminderDialogOpen(true);
                          }}
                          title={isChinese ? "域名订阅" : "Subscribe"}
                          className={cn(
                            "sm:hidden flex items-center justify-center w-6 h-6 rounded-full text-xs border transition-all active:scale-[0.93]",
                            (result.remainingDays !== null && result.remainingDays <= 30)
                              ? "bg-red-100 dark:bg-red-900/30 border-red-400/60 text-red-500"
                              : "bg-muted/50 border-border/50 text-muted-foreground hover:border-sky-400/50 hover:text-sky-500",
                          )}
                        >
                          <RiTimerLine className="w-3 h-3" />
                        </button>
                        {isOfficialDomain ? (
                          <button
                            onClick={(e) => {
                              const rect = e.currentTarget.getBoundingClientRect();
                              if (officialPopoverOpen) {
                                setOfficialPopoverOpen(false);
                                setOfficialPopoverPos(null);
                              } else {
                                setOfficialPopoverOpen(true);
                                setOfficialPopoverPos({ bottom: window.innerHeight - rect.top + 10, centerX: rect.left + rect.width / 2, isMobile: window.innerWidth < 640 });
                              }
                            }}
                            className={cn(
                              "stamp-claimed-badge sm:hidden flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border transition-all active:scale-[0.93]",
                              officialPopoverOpen
                                ? "bg-blue-100 dark:bg-blue-900/40 border-blue-500/80 text-blue-700 dark:text-blue-300"
                                : "bg-blue-50 dark:bg-blue-900/20 border-blue-400/60 text-blue-600 dark:text-blue-400"
                            )}
                          >
                            <RiGlobalLine className="w-3 h-3" />
                            {isChinese ? "官网认证" : "Official"}
                          </button>
                        ) : verifiedStamps.length > 0 ? (
                          <button
                            onClick={() => setStampDetailOpen(true)}
                            className="stamp-claimed-badge sm:hidden flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border transition-all active:scale-[0.93] bg-teal-50 dark:bg-teal-900/20 border-teal-400/50 text-teal-600 dark:text-teal-400"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                            {isChinese ? "已认领" : "Claimed"}
                          </button>
                        ) : (
                          <button
                            onClick={() => {
                              const domain = result.domain || target;
                              if (!session) {
                                router.push(`/login?callbackUrl=${encodeURIComponent(`/stamp?domain=${encodeURIComponent(domain)}`)}`);
                                return;
                              }
                              router.push(`/stamp?domain=${encodeURIComponent(domain)}`);
                            }}
                            title={isChinese ? "认领域名" : "Claim domain"}
                            className="sm:hidden flex items-center justify-center w-6 h-6 rounded-full text-xs border transition-all active:scale-[0.93] bg-muted/50 border-border/50 text-muted-foreground hover:border-violet-400/50 hover:text-violet-500"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                      <motion.h2
                        className="text-3xl sm:text-4xl font-bold tracking-tight mb-1 cursor-pointer hover:opacity-80 transition-opacity uppercase select-none"
                        onClick={() => copy(result.domain || target)}
                        whileTap={{ scale: 0.97 }}
                        transition={{ type: "spring", stiffness: 500, damping: 30 }}
                      >
                        {result.domain || displayTarget}
                      </motion.h2>
                      {result.domainPunycode && (
                        <p
                          className="text-xs text-muted-foreground font-mono mb-3 cursor-pointer hover:opacity-70 transition-opacity"
                          onClick={() => copy(result.domainPunycode!)}
                        >
                          {result.domainPunycode}
                        </p>
                      )}
                      {!result.domainPunycode && <div className="mb-3" />}
                      <div className="flex items-center gap-2 flex-wrap">
                        {result.remainingDays !== null ? (
                          result.remainingDays <= 0 ? (
                            <Badge className="bg-red-500 hover:bg-red-600 text-white border-0">
                              <div className="w-2 h-2 rounded-full bg-white/80 animate-pulse mr-1.5" />
                              {t("expired")}
                            </Badge>
                          ) : result.remainingDays <= 60 ? (
                            <Badge className="bg-amber-500 hover:bg-amber-600 text-white border-0">
                              <div className="w-2 h-2 rounded-full bg-white/80 animate-pulse mr-1.5" />
                              {t("expiring_soon")}
                            </Badge>
                          ) : (
                            <Badge className="bg-primary hover:bg-primary/90 text-primary-foreground border-0">
                              <div className="w-2 h-2 rounded-full bg-emerald-400 mr-1.5" />
                              {t("active")}
                            </Badge>
                          )
                        ) : (
                          (() => {
                            const regStatus = getDomainRegistrationStatus(result, locale);
                            return (
                              <Badge
                                variant="outline"
                                className={cn("font-medium", regStatus.color)}
                              >
                                <div className={cn("w-2 h-2 rounded-full mr-1.5", regStatus.dotColor)} />
                                {regStatus.label}
                              </Badge>
                            );
                          })()
                        )}
                        {result.domainAge !== null && (
                          <div className="flex items-center gap-1 px-2 py-0.5 rounded-md border border-primary/30 bg-primary/5">
                            <RiTimeLine className="w-3 h-3 text-primary shrink-0" />
                            <span className="text-[11px] font-normal text-primary">
                              {result.domainAge === 0 ? "<1" : result.domainAge}{" "}
                              {result.domainAge === 1 ? t("year") : t("years")}
                            </span>
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-3 flex-wrap">
                        {/* Mobile-only price tags (moved from above on mobile) */}
                        {result.registerPrice &&
                          result.registerPrice.new !== -1 &&
                          result.registerPrice.currency !== "Unknown" && (
                            <Link
                              target="_blank"
                              href={result.registerPrice.externalLink}
                              className="sm:hidden px-2 py-0.5 rounded-md border bg-background flex items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                            >
                              <RiBillLine className={cn("w-3 h-3 shrink-0", result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                              <span className={cn("text-[11px] font-normal", result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground")}>
                                {t("register_price")}
                                {formatRegistrarPrice(result.registerPrice.new as number, result.registerPrice.currency)}
                              </span>
                            </Link>
                          )}
                        {result.renewPrice &&
                          result.renewPrice.renew !== -1 &&
                          result.renewPrice.currency !== "Unknown" && (
                            <Link
                              href={result.renewPrice.externalLink}
                              target="_blank"
                              className="sm:hidden px-2 py-0.5 rounded-md border bg-background flex items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                            >
                              <RiExchangeDollarFill className={cn("w-3 h-3 shrink-0", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                              <span className={cn("text-[11px] font-normal", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")}>
                                {t("renew_price")}
                                {formatRegistrarPrice(result.renewPrice.renew as number, result.renewPrice.currency)}
                              </span>
                            </Link>
                          )}
                        {result.negotiable !== null && (
                          <div className="sm:hidden px-2 py-0.5 rounded-md border bg-background flex items-center space-x-1">
                            <RiExchangeDollarFill className="w-3 h-3 text-muted-foreground shrink-0" />
                            <span className="text-[11px] font-normal text-muted-foreground">
                              {t("negotiable")}
                              <span className={result.negotiable ? "text-amber-500" : "text-emerald-600 dark:text-emerald-400"}>
                                {result.negotiable ? t("negotiable_yes") : t("negotiable_no")}
                              </span>
                            </span>
                          </div>
                        )}
                        {/* Desktop-only Subscribe text button */}
                        <button
                          onClick={() => {
                            if (!session) {
                              toast.info(isChinese ? "请先登录再订阅域名提醒" : "Please log in to subscribe for reminders");
                              router.push(`/login?callbackUrl=${encodeURIComponent(`/${result.domain || target}`)}`);
                              return;
                            }
                            if (!(session?.user as any)?.subscriptionAccess) {
                              toast.info(isChinese ? "需要开通会员才能使用域名订阅提醒" : "Subscription required to use domain reminders.", {
                                action: { label: isChinese ? "去开通" : "Upgrade", onClick: () => router.push("/payment/checkout") },
                              });
                              return;
                            }
                            setReminderDialogOpen(true);
                          }}
                          className={cn(
                            "hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border transition-all active:scale-[0.93]",
                            (result.remainingDays !== null && result.remainingDays <= 30)
                              ? "bg-red-100 dark:bg-red-900/30 border-red-400/60 text-red-500"
                              : "bg-muted/50 border-border/50 text-muted-foreground hover:border-sky-400/50 hover:text-sky-500",
                          )}
                        >
                          <RiTimerLine className="w-3 h-3" />
                          {isChinese ? "域名订阅" : "Subscribe"}
                        </button>
                        {isOfficialDomain ? (
                          <button
                            onClick={(e) => {
                              const rect = e.currentTarget.getBoundingClientRect();
                              if (officialPopoverOpen) {
                                setOfficialPopoverOpen(false);
                                setOfficialPopoverPos(null);
                              } else {
                                setOfficialPopoverOpen(true);
                                setOfficialPopoverPos({ bottom: window.innerHeight - rect.top + 10, centerX: rect.left + rect.width / 2, isMobile: window.innerWidth < 640 });
                              }
                            }}
                            className={cn(
                              "stamp-claimed-badge hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border transition-all active:scale-[0.93]",
                              officialPopoverOpen
                                ? "bg-blue-100 dark:bg-blue-900/40 border-blue-500/80 text-blue-700 dark:text-blue-300"
                                : "bg-blue-50 dark:bg-blue-900/20 border-blue-400/60 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40"
                            )}
                          >
                            <RiGlobalLine className="w-3 h-3" />
                            {isChinese ? "官网认证" : "Official"}
                          </button>
                        ) : verifiedStamps.length > 0 ? (
                          <button
                            onClick={() => setStampDetailOpen(true)}
                            className="stamp-claimed-badge hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border transition-all active:scale-[0.93] bg-teal-50 dark:bg-teal-900/20 border-teal-400/50 text-teal-600 dark:text-teal-400 hover:bg-teal-100 dark:hover:bg-teal-900/40"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                            {isChinese ? "已认领" : "Claimed"}
                          </button>
                        ) : (
                          <button
                            onClick={() => {
                              const domain = result.domain || target;
                              if (!session) {
                                router.push(`/login?callbackUrl=${encodeURIComponent(`/stamp?domain=${encodeURIComponent(domain)}`)}`);
                                return;
                              }
                              router.push(`/stamp?domain=${encodeURIComponent(domain)}`);
                            }}
                            className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border transition-all active:scale-[0.93] bg-muted/50 border-border/50 text-muted-foreground hover:border-violet-400/50 hover:text-violet-500"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                            {isChinese ? "域名认领" : "Claim"}
                          </button>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {time.toFixed(2)}s
                          {cached && (
                            <>
                              {" · "}{t("cached")}
                              {cacheTtl && cacheTtl > 0 && (
                                <span className="opacity-60">
                                  {" "}({cacheTtl >= 3600
                                    ? `${Math.round(cacheTtl / 3600)}h`
                                    : cacheTtl >= 60
                                      ? `${Math.round(cacheTtl / 60)}m`
                                      : `${cacheTtl}s`})
                                </span>
                              )}
                            </>
                          )}
                          {data.source && (
                            <>
                              {" · "}
                              {(data.source === "tian.hu" || data.source === "YISI.YUN") ? (
                                <a
                                  href={data.source === "tian.hu" ? "https://tian.hu" : "https://yisi.yun"}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  title={isChinese ? "通过第三方 API 获取" : "Via third-party API"}
                                  className="text-amber-500/80 hover:text-amber-500 hover:underline transition-colors"
                                >
                                  {data.source}
                                </a>
                              ) : (
                                data.source
                              )}
                            </>
                          )}
                        </span>
                        {refreshing && (
                          <span className="flex items-center gap-1 text-[10px] text-primary/60 font-mono animate-pulse">
                            <RiLoader4Line className="w-2.5 h-2.5 animate-spin" />
                            {isChinese ? "更新中" : "Updating"}
                          </span>
                        )}
                        <div className="ml-auto flex items-center gap-1">
                          <button
                            onClick={() => setFeedbackOpen(true)}
                            title={t("feedback.issue_title")}
                            className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-muted-foreground hover:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-950/30 border border-transparent hover:border-amber-300/50 transition-all"
                          >
                            <RiErrorWarningLine className="w-3.5 h-3.5" />
                            {t("feedback.title")}
                          </button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <button
                                title={t("share")}
                                className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-muted-foreground hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-950/30 border border-transparent hover:border-blue-300/50 transition-all"
                              >
                                <RiShareLine className="w-3.5 h-3.5" />
                                {t("share")}
                              </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="min-w-[200px]">
                              <DropdownMenuLabel className="text-xs text-muted-foreground">
                                {t("share")}
                              </DropdownMenuLabel>
                              <DropdownMenuItem asChild>
                                <Link href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(`Whois Lookup: ${target}`)}&url=${encodeURIComponent(current)}`} target="_blank">
                                  <RiTwitterXLine className="w-4 h-4 mr-2" />Twitter / X
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(current)}`} target="_blank">
                                  <RiFacebookFill className="w-4 h-4 mr-2" />Facebook
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://reddit.com/submit?url=${encodeURIComponent(current)}`} target="_blank">
                                  <RiRedditLine className="w-4 h-4 mr-2" />Reddit
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://api.whatsapp.com/send?text=${encodeURIComponent(current)}`} target="_blank">
                                  <RiWhatsappLine className="w-4 h-4 mr-2" />WhatsApp
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://t.me/share/url?url=${encodeURIComponent(current)}`} target="_blank">
                                  <RiTelegramLine className="w-4 h-4 mr-2" />Telegram
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => copy(current)}>
                                <RiLinkM className="w-4 h-4 mr-2" />{t("copy_url")}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuLabel className="text-xs text-muted-foreground">
                                {t("image")}
                              </DropdownMenuLabel>
                              <DropdownMenuItem
                                onClick={async () => {
                                  const ogUrl = buildOgUrl(target, result);
                                  const tid = toast.loading(isZh ? "正在生成图片…" : "Generating image…");
                                  try {
                                    const res = await fetch(ogUrl);
                                    const blob = await res.blob();
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement("a");
                                    a.href = url;
                                    a.download = `whois-${target}.png`;
                                    a.click();
                                    URL.revokeObjectURL(url);
                                    toast.success(t("toast.downloaded"), { id: tid });
                                  } catch {
                                    toast.error(t("toast.download_failed"), { id: tid });
                                  }
                                }}
                              >
                                <RiDownloadLine className="w-4 h-4 mr-2" />{t("download_png")}
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={async () => {
                                  const ogUrl = buildOgUrl(target, result);
                                  const tid = toast.loading(isZh ? "正在生成图片…" : "Generating image…");
                                  try {
                                    const res = await fetch(ogUrl);
                                    const blob = await res.blob();
                                    await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
                                    toast.success(t("toast.copied_to_clipboard"), { id: tid });
                                  } catch {
                                    toast.error(t("toast.copy_to_clipboard_failed"), { id: tid });
                                  }
                                }}
                              >
                                <RiFileCopyLine className="w-4 h-4 mr-2" />{t("copy_image")}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => setShowImagePreview(true)}>
                                <RiCameraLine className="w-4 h-4 mr-2" />{t("preview_customize")}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                    </div>

                    {tianhuTranslation && tianhuTranslation.dst && (
                      <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.2 }}
                        className="flex flex-wrap items-center gap-x-3 gap-y-1.5 mt-3 px-3 py-2 rounded-lg bg-violet-50/60 dark:bg-violet-950/20 border border-violet-200/50 dark:border-violet-800/30"
                      >
                        <span className="text-[11px] font-mono text-muted-foreground/60 shrink-0">
                          {isChinese ? "含义" : "Meaning"}
                        </span>
                        <span className="text-[13px] font-semibold text-violet-700 dark:text-violet-300">
                          {tianhuTranslation.dst}
                        </span>
                        {tianhuTranslation.parts.flatMap((p, pi) =>
                          p.means.slice(0, 3).map((m, i) => (
                            <span key={`${pi}-${i}`} className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                              {i === 0 && p.part_name && (
                                <span className="text-[10px] font-medium text-muted-foreground/50 border border-border/40 rounded px-1 py-px">
                                  {p.part_name}
                                </span>
                              )}
                              {m}
                            </span>
                          ))
                        )}
                      </motion.div>
                    )}

                    {officialPopoverOpen && officialPopoverPos && typeof window !== "undefined" && ReactDOM.createPortal(
                      (() => {
                        const domainKey = (result?.domain || target || "").toLowerCase().replace(/^www\./, "");
                        const domainInfo = OFFICIAL_DOMAIN_DESC[domainKey];
                        const domainName = domainInfo?.name || (result?.domain || target || "").split(".")[0].toUpperCase();
                        const domainDesc = isChinese
                          ? (domainInfo?.zh || "该域名已被识别为全球知名主流网站，系统自动授予官网认证标识，无需人工审核。")
                          : (domainInfo?.en || "Recognized as a globally mainstream website and auto-certified without manual review.");
                        const isMob = officialPopoverPos.isMobile;
                        return (
                          <>
                            <motion.div
                              key="official-popover-backdrop"
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              className="fixed inset-0 z-[9998]"
                              style={{ background: isMob ? "rgba(0,0,0,0.35)" : "transparent" }}
                              onClick={() => { setOfficialPopoverOpen(false); setOfficialPopoverPos(null); }}
                            />
                            <AnimatePresence>
                              {isMob ? (
                                <div
                                  key="official-popover-mobile-wrapper"
                                  style={{ position: "fixed", inset: 0, zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}
                                >
                                  <motion.div
                                    initial={{ opacity: 0, scale: 0.92, y: 20 }}
                                    animate={{ opacity: 1, scale: 1, y: 0 }}
                                    exit={{ opacity: 0, scale: 0.94, y: 16 }}
                                    transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                                    style={{ pointerEvents: "auto", width: "calc(100vw - 40px)", maxWidth: "320px" }}
                                    onClick={e => e.stopPropagation()}
                                  >
                                    <div className="rounded-2xl border border-blue-200/70 dark:border-blue-700/50 bg-white dark:bg-zinc-900 shadow-2xl shadow-blue-500/15 overflow-hidden relative">
                                      <div className="h-[3px] w-full bg-gradient-to-r from-blue-400 via-sky-400 to-indigo-500" />
                                      <div className="px-4 pt-4 pb-5">
                                        <div className="flex items-center gap-3 mb-3">
                                          <div className="relative shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/40 dark:to-indigo-900/40 border border-blue-200/60 dark:border-blue-700/50 flex items-center justify-center overflow-hidden">
                                            <DomainFavicon domain={domainKey} size={20} fallback={<RiGlobalLine className="w-5 h-5 text-blue-500" />} />
                                            <motion.span className="absolute inset-0 rounded-xl border-2 border-blue-400/40" animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }} transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }} />
                                          </div>
                                          <div className="min-w-0">
                                            <div className="flex items-center gap-1.5 flex-wrap">
                                              <p className="text-[13.5px] font-bold text-foreground leading-tight">{domainName}</p>
                                              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 border border-blue-200/60 dark:border-blue-700/40">
                                                <RiCheckLine className="w-2.5 h-2.5 text-blue-500" />
                                                <span className="text-[9.5px] text-blue-500 font-semibold leading-none">{isChinese ? "官网认证" : "Verified"}</span>
                                              </span>
                                            </div>
                                            <p className="text-[10px] text-muted-foreground mt-0.5">{isChinese ? "系统自动认证 · 无需人工审核" : "Auto-certified · No manual review"}</p>
                                          </div>
                                        </div>
                                        <p className="text-[11px] text-muted-foreground leading-relaxed">{domainDesc}</p>
                                        <button
                                          onClick={() => { setOfficialPopoverOpen(false); setOfficialPopoverPos(null); }}
                                          className="mt-4 w-full py-2 rounded-xl bg-blue-50 dark:bg-blue-900/30 border border-blue-200/50 dark:border-blue-700/40 text-[12px] font-semibold text-blue-600 dark:text-blue-400 active:scale-[0.97] transition-transform"
                                        >
                                          {isChinese ? "我知道了" : "Got it"}
                                        </button>
                                      </div>
                                    </div>
                                  </motion.div>
                                </div>
                              ) : (
                                <motion.div
                                  key="official-popover-portal-desktop"
                                  initial={{ opacity: 0, y: 8, scale: 0.94 }}
                                  animate={{ opacity: 1, y: 0, scale: 1 }}
                                  exit={{ opacity: 0, y: 5, scale: 0.96 }}
                                  transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                                  style={{ position: "fixed", bottom: `${officialPopoverPos.bottom}px`, left: `${officialPopoverPos.centerX}px`, transform: "translateX(-50%)", width: "260px", zIndex: 9999 }}
                                  onClick={e => e.stopPropagation()}
                                >
                                  <div className="rounded-2xl border border-blue-200/70 dark:border-blue-700/50 bg-white dark:bg-zinc-900 shadow-2xl shadow-blue-500/15 overflow-hidden relative">
                                    <div className="h-[3px] w-full bg-gradient-to-r from-blue-400 via-sky-400 to-indigo-500" />
                                    <div className="px-4 pt-4 pb-4">
                                      <div className="flex items-center gap-3 mb-3">
                                        <div className="relative shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/40 dark:to-indigo-900/40 border border-blue-200/60 dark:border-blue-700/50 flex items-center justify-center overflow-hidden">
                                          <DomainFavicon domain={domainKey} size={20} fallback={<RiGlobalLine className="w-5 h-5 text-blue-500" />} />
                                          <motion.span className="absolute inset-0 rounded-xl border-2 border-blue-400/40" animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }} transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }} />
                                        </div>
                                        <div className="min-w-0">
                                          <div className="flex items-center gap-1.5 flex-wrap">
                                            <p className="text-[13.5px] font-bold text-foreground leading-tight">{domainName}</p>
                                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 border border-blue-200/60 dark:border-blue-700/40">
                                              <RiCheckLine className="w-2.5 h-2.5 text-blue-500" />
                                              <span className="text-[9.5px] text-blue-500 font-semibold leading-none">{isChinese ? "官网认证" : "Verified"}</span>
                                            </span>
                                          </div>
                                          <p className="text-[10px] text-muted-foreground mt-0.5">{isChinese ? "系统自动认证 · 无需人工审核" : "Auto-certified · No manual review"}</p>
                                        </div>
                                      </div>
                                      <p className="text-[11px] text-muted-foreground leading-relaxed">{domainDesc}</p>
                                    </div>
                                    <div className="absolute -bottom-[7px] left-1/2 -translate-x-1/2 w-3.5 h-3.5 rotate-45 bg-white dark:bg-zinc-900 border-r border-b border-blue-200/70 dark:border-blue-700/50" />
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </>
                        );
                      })(),
                      document.body
                    )}

                    <FeedbackDrawer
                      open={feedbackOpen}
                      onOpenChange={setFeedbackOpen}
                      query={result.domain || target}
                      queryType={queryType}
                    />

                    <DomainReminderDialog
                      domain={result.domain || target}
                      expirationDate={result.expirationDate}
                      remainingDays={result.remainingDays}
                      open={reminderDialogOpen}
                      onOpenChange={setReminderDialogOpen}
                      isZh={isChinese}
                      userEmail={session?.user?.email ?? ""}
                      registerPriceFmt={
                        result.registerPrice && result.registerPrice.new !== -1 && result.registerPrice.currency !== "Unknown"
                          ? formatRegistrarPrice(result.registerPrice.new as number, result.registerPrice.currency)
                          : undefined
                      }
                      renewPriceFmt={
                        result.renewPrice && result.renewPrice.renew !== -1 && result.renewPrice.currency !== "Unknown"
                          ? formatRegistrarPrice(result.renewPrice.renew as number, result.renewPrice.currency)
                          : undefined
                      }
                      isPremium={result.registerPrice?.isPremium ?? false}
                      eppStatuses={result.status?.map((s) => s.status) ?? []}
                      regStatusType={getDomainRegistrationStatus(result, locale).type}
                    />

                    {result.remainingDays === null &&
                      (() => {
                        const regStatus = getDomainRegistrationStatus(result, locale);
                        if (regStatus.type === "registered") return null;
                        const cnInfo = getCnReservedSldInfo(result.domain);
                        const premiumCustomDesc =
                          regStatus.type === "reserved" && regStatus.isPremiumReserved
                            ? {
                                zh: "该域名已被注册局列入高价值保留名单，目前正等待有缘人上门购买。如有意向，请直接联系该 TLD 注册局咨询报价与购买流程。",
                                en: "This domain is held in the registry's reserved list as a high-value premium name. It may be available for purchase at a premium price — contact the registry directly to inquire about pricing and the acquisition process.",
                              }
                            : undefined;
                        return (
                          <DomainStatusInfoCard
                            type={regStatus.type}
                            locale={locale}
                            customDesc={
                              cnInfo && regStatus.type === "reserved"
                                ? { zh: cnInfo.descZh, en: cnInfo.descEn }
                                : premiumCustomDesc
                            }
                          />
                        );
                      })()}

                    {(result.creationDate !== "Unknown" ||
                      result.expirationDate !== "Unknown" ||
                      result.updatedDate !== "Unknown") && (
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-6 mt-8 pt-8 border-t border-border/50">
                        {result.creationDate &&
                          result.creationDate !== "Unknown" && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                {t("whois_fields.creation_date")}
                              </p>
                              <p className="font-mono text-sm font-medium">
                                {formatDate(result.creationDate)}
                              </p>
                              <p className="text-[10px] text-muted-foreground mt-0.5">
                                {getRelativeTime(result.creationDate, t)}
                              </p>
                            </div>
                          )}
                        {result.expirationDate &&
                          result.expirationDate !== "Unknown" && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                {t("whois_fields.expiration_date")}
                              </p>
                              <p className="font-mono text-sm font-medium">
                                {formatDate(result.expirationDate)}
                              </p>
                              <p
                                className={cn(
                                  "text-[10px] mt-0.5 font-medium",
                                  result.remainingDays !== null &&
                                    result.remainingDays > 60
                                    ? "text-emerald-600 dark:text-emerald-400"
                                    : result.remainingDays !== null &&
                                        result.remainingDays <= 30
                                      ? "text-red-600 dark:text-red-400"
                                      : "text-amber-600 dark:text-amber-400",
                                )}
                              >
                                {result.remainingDays !== null
                                  ? result.remainingDays > 0
                                    ? t("d_remaining", {
                                        days: result.remainingDays,
                                      })
                                    : t("expired")
                                  : getRelativeTime(result.expirationDate, t)}
                              </p>
                            </div>
                          )}
                        {result.updatedDate &&
                          result.updatedDate !== "Unknown" && (
                            <div className="col-span-2 sm:col-span-1">
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                {t("whois_fields.updated_date")}
                              </p>
                              <p className="font-mono text-sm font-medium">
                                {formatDate(result.updatedDate)}
                              </p>
                              <p className="text-[10px] text-muted-foreground mt-0.5">
                                {getRelativeTime(result.updatedDate, t)}
                              </p>
                            </div>
                          )}
                      </div>
                    )}

                    {/* Stamp detail dialog — triggered by "已认领" badge */}
                    <Dialog open={stampDetailOpen} onOpenChange={setStampDetailOpen}>
                      <DialogContent hideClose className="max-w-[360px] p-0 overflow-hidden gap-0 rounded-[22px]">
                        <DialogHeader className="sr-only">
                          <DialogTitle>{isChinese ? "品牌认领信息" : "Claimed Brand"}</DialogTitle>
                        </DialogHeader>
                        <div className="divide-y divide-border/30">
                          {verifiedStamps.map((stamp) => {
                            const theme     = CARD_THEMES[stamp.cardTheme] || CARD_THEMES.app;
                            const StampIcon = STAMP_ICON_MAP[stamp.tagStyle] || STAMP_ICON_MAP.default;
                            const labelMap: Record<string, { zh: string; en: string }> = {
                              personal: { zh: "个人认领", en: "Personal"  },
                              official: { zh: "官方认证", en: "Official"  },
                              brand:    { zh: "品牌认领", en: "Brand"     },
                              verified: { zh: "已认证",   en: "Verified"  },
                              partner:  { zh: "合作伙伴", en: "Partner"   },
                              dev:      { zh: "开发者",   en: "Developer" },
                              warning:  { zh: "注意",     en: "Warning"   },
                              premium:  { zh: "高级认证", en: "Premium"   },
                            };
                            const lbl = labelMap[stamp.tagStyle] ?? { zh: "已认领", en: "Claimed" };
                            let linkHostname = "";
                            if (stamp.link) {
                              try { linkHostname = new URL(stamp.link).hostname; } catch { linkHostname = stamp.link; }
                            }

                            const CloseBtn = ({ cls }: { cls?: string }) => (
                              <button onClick={() => setStampDetailOpen(false)}
                                className={cn("absolute top-3 right-3 w-8 h-8 flex items-center justify-center rounded-xl backdrop-blur-sm border transition-all active:scale-95 z-10", cls ?? "bg-black/25 hover:bg-black/40 border-white/20 text-white")}
                                aria-label="Close">
                                <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                                  <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
                                </svg>
                              </button>
                            );

                            const CtaLink = ({ btnCls }: { btnCls?: string }) => stamp.link ? (
                              <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                                className={cn("flex items-center justify-center gap-2 w-full px-4 py-3 rounded-2xl shadow-md transition-all hover:opacity-90 active:scale-[0.98]", btnCls ?? theme.btn)}>
                                <span className="text-[14px] font-bold leading-none">{isChinese ? "访问主页" : "Visit Profile"}</span>
                                <RiArrowRightSLine className="w-5 h-5 opacity-70 shrink-0" />
                              </a>
                            ) : (
                              <p className="text-[11px] text-muted-foreground/40 text-center font-mono py-1">
                                {isChinese ? "该认领未设置主页链接" : "No profile link set"}
                              </p>
                            );

                            /* ════════════════════════════════════════
                               Layout: celebrate — 中国红·节庆
                            ════════════════════════════════════════ */
                            if (theme.layout === "celebrate") return (
                              <div key={stamp.id} className="relative overflow-hidden bg-white">
                                {/* ── Hero: crimson red gradient with gold diamonds ── */}
                                <div className="relative overflow-hidden" style={{height:210, background:"linear-gradient(160deg,#C8102E 0%,#7B0D1E 100%)"}}>
                                  {[
                                    {x:"7%",y:"10%",s:12,r:"45deg"},{x:"20%",y:"5%",s:8,r:"0"},
                                    {x:"36%",y:"18%",s:14,r:"30deg"},{x:"53%",y:"4%",s:9,r:"0"},
                                    {x:"68%",y:"13%",s:12,r:"-30deg"},{x:"84%",y:"7%",s:7,r:"0"},
                                    {x:"13%",y:"42%",s:9,r:"20deg"},{x:"48%",y:"38%",s:7,r:"0"},
                                    {x:"76%",y:"40%",s:11,r:"-20deg"},{x:"90%",y:"35%",s:6,r:"15deg"},
                                  ].map((p,i)=>(
                                    <span key={i} className="absolute pointer-events-none"
                                      style={{left:p.x,top:p.y,width:p.s,height:p.s,background:"rgba(212,175,55,0.72)",transform:`rotate(${p.r})`,borderRadius:2}} />
                                  ))}
                                  <button onClick={() => setStampDetailOpen(false)}
                                    className="absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full z-10 transition-colors"
                                    style={{background:"rgba(0,0,0,0.22)"}}
                                    aria-label="Close">
                                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                                      <path d="M1 1l10 10M11 1L1 11" stroke="white" strokeWidth="2.2" strokeLinecap="round"/>
                                    </svg>
                                  </button>
                                  <div className="absolute bottom-0 left-0 right-0 pointer-events-none z-[2]">
                                    <svg viewBox="0 0 400 40" preserveAspectRatio="none" className="w-full h-10 block">
                                      <path d="M0 40 C100 8, 300 26, 400 4 L400 40 Z" fill="white"/>
                                    </svg>
                                  </div>
                                </div>

                                {/* ── Gold checkmark seal badge ── */}
                                <div className="flex justify-center -mt-12 relative z-10 mb-4">
                                  <div className="w-[88px] h-[88px] rounded-full border-[6px] border-white shadow-2xl flex items-center justify-center"
                                    style={{background:"linear-gradient(135deg,#D4AF37 0%,#F7C948 50%,#B8860B 100%)",boxShadow:"0 8px 24px rgba(180,140,30,0.45)"}}>
                                    <svg width="38" height="38" viewBox="0 0 40 40" fill="none">
                                      <path d="M9 22l8 9L32 12" stroke="white" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round"/>
                                    </svg>
                                  </div>
                                </div>

                                {/* ── White body ── */}
                                <div className="px-8 pb-3 text-center">
                                  <h2 className="text-[27px] font-black text-gray-900 leading-tight tracking-tight">{stamp.tagName}</h2>
                                  <p className="text-[13px] text-gray-400 leading-relaxed mt-2 max-w-[260px] mx-auto">
                                    {stamp.description || (isChinese ? `恭喜！${result.domain || target} 已通过认领。` : `Congratulations! ${result.domain || target} has been claimed.`)}
                                  </p>
                                </div>

                                {/* ── Gold CTA ── */}
                                <div className="px-6 pt-4 pb-8 space-y-3">
                                  {stamp.link
                                    ? <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                                        className="flex items-center justify-center w-full py-4 rounded-full text-white text-[15px] font-bold transition-all active:scale-[0.98]"
                                        style={{background:"linear-gradient(135deg,#D4AF37,#B8860B)",boxShadow:"0 8px 24px rgba(180,140,30,0.4)"}}>
                                        {isChinese ? "访问主页" : "Visit Profile"}
                                      </a>
                                    : null
                                  }
                                  <button onClick={() => setStampDetailOpen(false)}
                                    className="w-full text-center text-[13px] text-gray-400 hover:text-gray-600 font-medium py-0.5 transition-colors">
                                    {isChinese ? "关闭" : "Cancel"}
                                  </button>
                                </div>
                              </div>
                            );

                            /* ════════════════════════════════════════
                               Layout: neon — 赛博·霓虹
                            ════════════════════════════════════════ */
                            if (theme.layout === "neon") return (
                              <div key={stamp.id} className="relative overflow-hidden" style={{background:"#050d18", borderRadius:"inherit"}}>
                                {/* Close */}
                                <button onClick={() => setStampDetailOpen(false)}
                                  className="absolute top-4 right-4 z-20 transition-colors"
                                  style={{color:"rgba(255,255,255,0.3)"}}
                                  aria-label="Close">
                                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                                    <path d="M2 2l10 10M12 2L2 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                                  </svg>
                                </button>

                                {/* Hero */}
                                <div className="relative flex flex-col items-center pt-10 pb-6 overflow-hidden" style={{background:"#050d18"}}>
                                  {/* ambient radial glow */}
                                  <div className="absolute inset-0 pointer-events-none"
                                    style={{background:"radial-gradient(ellipse 80% 60% at 50% 0%,rgba(0,210,255,0.13) 0%,transparent 70%)"}}/>
                                  {/* badge */}
                                  <div className="relative z-10 mb-5">
                                    <span className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-[11px] font-bold font-mono"
                                      style={{background:"rgba(0,210,255,0.1)",border:"1px solid rgba(0,210,255,0.4)",color:"#00D2FF",
                                        boxShadow:"0 0 14px rgba(0,210,255,0.2)"}}>
                                      <RiShieldCheckLine className="w-3 h-3" />
                                      {isChinese ? lbl.zh : lbl.en}
                                    </span>
                                  </div>
                                  {/* icon in pulsing ring */}
                                  <div className="relative z-10 w-[110px] h-[110px] rounded-full flex items-center justify-center"
                                    style={{background:"rgba(0,210,255,0.06)",border:"2px solid rgba(0,210,255,0.45)",
                                      boxShadow:"0 0 30px rgba(0,210,255,0.22), 0 0 60px rgba(0,210,255,0.08)"}}>
                                    <StampIcon className="w-12 h-12 text-cyan-400"/>
                                  </div>
                                  {/* domain */}
                                  <p className="relative z-10 text-[10px] font-mono tracking-[0.25em] uppercase mt-3"
                                    style={{color:"rgba(0,210,255,0.3)"}}>
                                    {result.domain || target}
                                  </p>
                                </div>

                                {/* Info */}
                                <div className="px-8 pt-2 pb-4 text-center">
                                  <h2 className="text-[26px] font-black text-white leading-tight tracking-tight"
                                    style={{textShadow:"0 0 24px rgba(0,210,255,0.3)"}}>{stamp.tagName}</h2>
                                  {stamp.description && (
                                    <p className="text-[13px] mt-2 leading-relaxed max-w-[240px] mx-auto"
                                      style={{color:"rgba(100,130,160,0.88)"}}>
                                      {stamp.description}
                                    </p>
                                  )}
                                </div>

                                {/* CTA */}
                                <div className="px-5 pt-2 pb-8 space-y-2.5">
                                  {stamp.link
                                    ? <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                                        className="flex items-center justify-center w-full py-4 rounded-2xl font-bold text-[15px] text-white transition-all active:scale-[0.98]"
                                        style={{background:"linear-gradient(135deg,#00D2FF,#7B2FBE)",
                                          boxShadow:"0 4px 20px rgba(0,210,255,0.3)"}}>
                                        {isChinese ? "访问主页" : "Visit Profile"}
                                      </a>
                                    : null
                                  }
                                  <button onClick={() => setStampDetailOpen(false)}
                                    className="flex items-center justify-center w-full py-3 rounded-2xl font-medium text-[13px] transition-all active:scale-[0.98]"
                                    style={{border:"1px solid rgba(255,255,255,0.1)",color:"rgba(255,255,255,0.35)"}}>
                                    {isChinese ? "关闭" : "Cancel"}
                                  </button>
                                </div>
                              </div>
                            );

                            /* ════════════════════════════════════════
                               Layout: gradient — 全息·流光
                            ════════════════════════════════════════ */
                            if (theme.layout === "gradient") return (
                              <div key={stamp.id} className="relative flex flex-col overflow-hidden" style={{minHeight:420, background:"linear-gradient(135deg,#FF6B6B 0%,#FFD93D 18%,#6BCB77 36%,#4D96FF 55%,#C77DFF 75%,#FF6B6B 100%)"}}>

                                {/* Close: top-left, bare X */}
                                <button onClick={() => setStampDetailOpen(false)}
                                  className="absolute top-5 left-5 flex items-center justify-center w-9 h-9 transition-colors z-10"
                                  style={{color:"rgba(20,20,20,0.6)"}}
                                  aria-label="Close">
                                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                                    <path d="M3 3l14 14M17 3L3 17" stroke="currentColor" strokeWidth="2.8" strokeLinecap="round"/>
                                  </svg>
                                </button>

                                {/* ── Center content ── */}
                                <div className="relative z-10 flex-1 flex flex-col items-center justify-center text-center px-8 pt-14 pb-4">
                                  <span className="inline-flex items-center px-6 py-2.5 rounded-full text-[13px] font-bold mb-7 tracking-tight"
                                    style={{border:"2px solid rgba(10,10,10,0.6)",color:"rgba(10,10,10,0.78)",background:"rgba(255,255,255,0.38)",backdropFilter:"blur(8px)"}}>
                                    {isChinese ? lbl.zh : lbl.en}
                                  </span>
                                  <h2 className="font-black text-gray-900 leading-[1.05] tracking-tight mb-1.5 max-w-[270px]"
                                    style={{fontSize:34,textShadow:"0 1px 6px rgba(255,255,255,0.7)"}}>
                                    {stamp.tagName}
                                  </h2>
                                  <p className="text-[11px] font-mono tracking-widest mb-4"
                                    style={{color:"rgba(10,10,10,0.38)",textShadow:"0 1px 2px rgba(255,255,255,0.5)"}}>
                                    {result.domain || target}
                                  </p>
                                  <p className="text-[14px] leading-relaxed max-w-[248px]" style={{color:"rgba(20,20,20,0.72)",textShadow:"0 1px 3px rgba(255,255,255,0.5)"}}>
                                    {stamp.description || (isChinese
                                      ? `该域名已由持有人认领，点击下方访问主页了解更多。`
                                      : `This domain has been claimed. Visit the profile to learn more.`
                                    )}
                                  </p>
                                </div>

                                {/* ── CTA — clean centered button ── */}
                                <div className="relative z-10 flex justify-center pb-8 pt-2">
                                  {stamp.link
                                    ? <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                                        className="inline-flex items-center gap-2 px-8 py-3 rounded-full text-white text-[14px] font-bold transition-all active:scale-[0.98]"
                                        style={{background:"rgba(8,10,25,0.82)",backdropFilter:"blur(12px)"}}>
                                        <span>{isChinese ? "访问主页" : "Visit Profile"}</span>
                                        <RiArrowRightSLine className="w-5 h-5 opacity-70 shrink-0"/>
                                      </a>
                                    : null
                                  }
                                </div>
                              </div>
                            );

                            /* ════════════════════════════════════════
                               Layout: split — 高反差·黑白
                            ════════════════════════════════════════ */
                            if (theme.layout === "split") return (
                              <div key={stamp.id} className="relative flex" style={{minHeight:310}}>
                                {/* ── Left: pure black with ghost letter ── */}
                                <div className="relative flex flex-col items-center justify-center w-[42%] shrink-0 overflow-hidden"
                                  style={{background:"#000"}}>
                                  {/* Giant ghost letter */}
                                  <div className="absolute inset-0 flex items-center justify-center overflow-hidden select-none pointer-events-none">
                                    <span className="font-black leading-none"
                                      style={{fontSize:200,color:"rgba(255,255,255,0.04)",lineHeight:1}}>
                                      {(stamp.tagName||result.domain||target||"A")[0].toUpperCase()}
                                    </span>
                                  </div>
                                  {/* Electric blue accent line at right edge */}
                                  <div className="absolute top-0 right-0 w-[3px] h-full"
                                    style={{background:"linear-gradient(to bottom,#3B82F6,#6366F1)"}}/>
                                  {/* Icon */}
                                  <div className="relative z-10 flex flex-col items-center gap-2 px-4 py-6 w-full overflow-hidden">
                                    <div className="w-12 h-12 rounded-2xl flex items-center justify-center"
                                      style={{background:"rgba(255,255,255,0.07)",border:"1px solid rgba(255,255,255,0.1)"}}>
                                      <StampIcon className="w-6 h-6 text-white/70"/>
                                    </div>
                                    <p className="font-mono tracking-widest uppercase text-center"
                                      style={{fontSize:8,color:"rgba(255,255,255,0.18)"}}>
                                      {result.domain || target}
                                    </p>
                                  </div>
                                </div>

                                {/* ── Right: off-white editorial ── */}
                                <div className="flex-1 flex flex-col justify-between px-5 py-5 relative" style={{background:"#FAFAFA"}}>
                                  {/* Red X */}
                                  <button onClick={() => setStampDetailOpen(false)}
                                    className="absolute top-3 right-3 z-10 w-7 h-7 flex items-center justify-center transition-colors"
                                    style={{color:"#ef4444"}}
                                    aria-label="Close">
                                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                                      <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="2.3" strokeLinecap="round"/>
                                    </svg>
                                  </button>

                                  <div className="mt-1">
                                    <p className="text-[9px] font-semibold uppercase tracking-[0.22em] mb-2" style={{color:"#9ca3af"}}>
                                      {isChinese ? "品牌认领" : "Brand Verified"}
                                    </p>
                                    <h2 className="font-black text-gray-900 leading-[1.0] tracking-tight mb-2"
                                      style={{fontSize:30}}>{stamp.tagName}</h2>
                                    {stamp.description && (
                                      <p className="text-[11.5px] leading-relaxed" style={{color:"#6b7280"}}>{stamp.description}</p>
                                    )}
                                  </div>

                                  {/* CTA */}
                                  <div className="pt-4">
                                    {stamp.link
                                      ? <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                                          className="flex items-center justify-between w-full px-4 py-2.5 text-white text-[12px] font-bold rounded-xl transition-all active:scale-[0.97]"
                                          style={{background:"#111827"}}>
                                          <span>{isChinese ? "访问主页" : "Visit Profile"}</span>
                                          <RiArrowRightSLine className="w-4 h-4 opacity-70" />
                                        </a>
                                      : <p className="text-[10px] font-mono text-center py-2" style={{color:"#d1d5db"}}>{isChinese ? "未设置主页链接" : "No profile link"}</p>
                                    }
                                  </div>
                                </div>
                              </div>
                            );

                            /* ════════════════════════════════════════
                               Layout: flash — 闪购·电光
                            ════════════════════════════════════════ */
                            if ((theme as any).layout === "flash") return (
                              <div key={stamp.id} className="relative overflow-hidden" style={{borderRadius:"inherit"}}>
                                {/* ── Orange-red header ── */}
                                <div className="flex items-center justify-between px-4 py-3" style={{background:"#FF3800"}}>
                                  <div className="flex items-center gap-2">
                                    <div className="w-5 h-5 rounded-full flex items-center justify-center" style={{background:"rgba(255,255,255,0.22)"}}>
                                      <StampIcon className="w-3 h-3 text-white"/>
                                    </div>
                                    <p className="text-[11px] font-semibold tracking-wide" style={{color:"rgba(255,255,255,0.88)"}}>{result.domain || target}</p>
                                  </div>
                                  <button onClick={() => setStampDetailOpen(false)} className="transition-colors" style={{color:"rgba(255,255,255,0.6)"}} aria-label="Close">
                                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                                      <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                                    </svg>
                                  </button>
                                </div>

                                {/* ── Two-column body ── */}
                                <div className="flex" style={{minHeight:256}}>
                                  {/* Left: electric yellow + monogram + lightning */}
                                  <div className="w-[44%] shrink-0 flex flex-col items-center justify-center px-4 pb-5 pt-5 relative overflow-hidden" style={{background:"#FFE500"}}>
                                    {/* Lightning bolt decoration */}
                                    <svg className="absolute top-3 right-3 pointer-events-none" width={18} height={28} viewBox="0 0 10 18" fill="rgba(255,80,0,0.4)">
                                      <path d="M7 0L1 10h5L3 18l8-11H6L7 0Z"/>
                                    </svg>
                                    <svg className="absolute bottom-4 left-3 pointer-events-none" width={11} height={17} viewBox="0 0 10 18" fill="rgba(255,80,0,0.25)">
                                      <path d="M7 0L1 10h5L3 18l8-11H6L7 0Z"/>
                                    </svg>
                                    {/* monogram — no duplicate tagName text */}
                                    <div className="font-black leading-none tracking-tight select-none" style={{fontSize:40, color:"#111"}}>
                                      {(stamp.tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase()}
                                    </div>
                                  </div>

                                  {/* Right: white + star sparkles + content */}
                                  <div className="flex-1 flex flex-col justify-between px-4 py-4 bg-white relative">
                                    {/* Star sparkles */}
                                    {[{x:8,y:8,s:13},{x:28,y:5,s:8},{x:6,y:60,s:12},{x:30,y:56,s:8}].map((sp,i)=>(
                                      <svg key={i} width={sp.s} height={sp.s} viewBox="0 0 10 10" className="absolute pointer-events-none"
                                        style={{right:`${sp.x}px`, bottom:`${sp.y}px`, fill:"#FFB800"}}>
                                        <path d="M5 0 L6 4 L10 5 L6 6 L5 10 L4 6 L0 5 L4 4 Z"/>
                                      </svg>
                                    ))}

                                    <div>
                                      <h2 className="font-black text-gray-900 leading-none tracking-tight"
                                        style={{fontSize:28}}>{stamp.tagName}</h2>
                                      <p className="text-[10px] font-bold uppercase tracking-widest mt-1 mb-3" style={{color:"#FF3800"}}>
                                        {isChinese ? "域名认领" : "Domain Claimed"}
                                      </p>
                                      {stamp.description && (
                                        <p className="text-[11px] leading-relaxed" style={{color:"#9ca3af"}}>{stamp.description}</p>
                                      )}
                                    </div>

                                    {stamp.link
                                      ? <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                                          className="flex items-center justify-center w-full py-3 rounded-xl font-bold text-white text-[13px] transition-all active:scale-[0.98]"
                                          style={{background:"linear-gradient(135deg,#FF3800,#FF6B00)", boxShadow:"0 4px 14px rgba(255,56,0,0.28)"}}>
                                          {isChinese ? "访问主页" : "Visit Profile"}
                                        </a>
                                      : null
                                    }
                                  </div>
                                </div>
                              </div>
                            );

                            /* ════════════════════════════════════════
                               Layout: default
                            ════════════════════════════════════════ */
                            const isDarkCard = theme.cardBg === "bg-zinc-950" || theme.cardBg === "bg-slate-900";
                            return (
                              <div key={stamp.id}>
                                {/* ── Hero — compact monogram ── */}
                                <div className={cn("relative px-5 pt-8 pb-12 text-center select-none overflow-hidden", theme.hero)}>
                                  <div className="absolute inset-0 opacity-[0.04]"
                                    style={{ backgroundImage: "radial-gradient(circle, white 1px, transparent 1px)", backgroundSize: "18px 18px" }} />
                                  <div className="absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-black/40 to-transparent" />
                                  <CloseBtn />
                                  <div className="relative flex flex-col items-center">
                                    <div className="relative">
                                      <div className="absolute inset-0 rounded-2xl bg-white/15 blur-xl scale-150 pointer-events-none" />
                                      <div className="relative w-[62px] h-[62px] rounded-2xl bg-white/20 backdrop-blur-sm border border-white/30 flex items-center justify-center shadow-2xl ring-8 ring-white/[0.06] font-black text-white/90 text-[18px] leading-none">
                                        {(stamp.tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase()}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* ── Floating card ── */}
                                <div className={cn("relative -mt-7 mx-4 rounded-[22px] border shadow-2xl overflow-hidden", theme.cardBg, theme.cardBorder)}>
                                  {/* accent stripe */}
                                  <div className={cn("h-1 w-full", theme.hero)} />
                                  <div className="px-4 pt-3.5 pb-4">
                                    {/* name + badge */}
                                    <div className="flex items-start justify-between gap-3 mb-0.5">
                                      <div className="flex-1 min-w-0">
                                        <p className={cn("text-[21px] font-black leading-tight tracking-tight", theme.shimmer)}>{stamp.tagName}</p>
                                        <p className={cn("text-[10px] font-mono tracking-wider mt-0.5 truncate", isDarkCard ? "text-zinc-600" : "text-muted-foreground/35")}>
                                          {result.domain || target}
                                        </p>
                                      </div>
                                      <span className={cn("inline-flex items-center gap-1 text-[10px] font-bold px-2.5 py-[5px] rounded-full shrink-0 whitespace-nowrap mt-1.5 leading-none", theme.badge)}>
                                        <RiShieldCheckLine className="w-2.5 h-2.5" />
                                        {isChinese ? lbl.zh : lbl.en}
                                      </span>
                                    </div>
                                    {/* description */}
                                    {stamp.description && (
                                      <p className={cn("text-[13px] leading-relaxed mt-2.5 mb-4", isDarkCard ? "text-zinc-500" : "text-muted-foreground/65")}>
                                        {stamp.description}
                                      </p>
                                    )}
                                    {/* CTA */}
                                    <CtaLink />
                                  </div>
                                </div>

                                {/* ── bottom fill ── */}
                                <div className={cn("h-5", theme.cardBg)} />
                              </div>
                            );
                          })}
                        </div>
                      </DialogContent>
                    </Dialog>

                    {hasRegistrant && (
                      <div className="mt-6 pt-6 border-t border-border/50 space-y-4">
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                          {[
                            {
                              label: t("whois_fields.registrant_name"),
                              value: result.registrantName,
                            },
                            {
                              label: t("whois_fields.registrant_organization"),
                              value: result.registrantOrganization,
                            },
                            {
                              label: t("whois_fields.registrant_country"),
                              value: result.registrantCountry,
                              country: true,
                            },
                            {
                              label: t("whois_fields.registrant_province"),
                              value: result.registrantProvince,
                            },
                            {
                              label: t("whois_fields.registrant_city"),
                              value: result.registrantCity,
                            },
                            {
                              label: t("whois_fields.registrant_address"),
                              value: result.registrantAddress,
                            },
                            {
                              label: t("whois_fields.registrant_postal_code"),
                              value: result.registrantPostalCode,
                            },
                            {
                              label: t("whois_fields.registrant_email"),
                              value: result.registrantEmail,
                            },
                            {
                              label: t("whois_fields.registrant_phone"),
                              value: result.registrantPhone,
                            },
                            {
                              label: t("whois_fields.registrant_fax"),
                              value: result.registrantFax,
                            },
                          ]
                            .filter((f) => isValidField(f.value))
                            .map((f, i) => (
                              <div key={i} className="min-w-0">
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                  {f.label}
                                </p>
                                <p className="text-xs font-mono whitespace-pre-wrap break-all flex items-center gap-1.5">
                                  {"country" in f &&
                                    f.country &&
                                    f.value &&
                                    /^[A-Z]{2}$/i.test(f.value.trim()) && (
                                      <img
                                        src={`https://flagcdn.com/w40/${f.value.trim().toLowerCase()}.png`}
                                        alt=""
                                        className="w-4 h-3 object-cover rounded-[2px]"
                                      />
                                    )}
                                  {f.value}
                                </p>
                              </div>
                            ))}
                        </div>

                        {/* Admin contact */}
                        {hasAdminContact && (
                          <div className="pt-3 border-t border-border/30">
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-2">
                              {t("whois_fields.admin_contact")}
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                              {[
                                { label: t("whois_fields.admin_name"), value: result.adminName },
                                { label: t("whois_fields.admin_organization"), value: result.adminOrganization },
                                { label: t("whois_fields.admin_country"), value: result.adminCountry, country: true },
                                { label: t("whois_fields.admin_email"), value: result.adminEmail },
                                { label: t("whois_fields.admin_phone"), value: result.adminPhone },
                              ]
                                .filter((f) => isValidField(f.value))
                                .map((f, i) => (
                                  <div key={i} className="min-w-0">
                                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-0.5">
                                      {f.label}
                                    </p>
                                    <p className="text-xs font-mono break-all flex items-center gap-1.5">
                                      {"country" in f && f.country && f.value && /^[A-Z]{2}$/i.test(f.value.trim()) && (
                                        <img src={`https://flagcdn.com/w40/${f.value.trim().toLowerCase()}.png`} alt="" className="w-4 h-3 object-cover rounded-[2px]" />
                                      )}
                                      {f.value}
                                    </p>
                                  </div>
                                ))}
                            </div>
                          </div>
                        )}

                        {/* Tech contact */}
                        {hasTechContact && (
                          <div className="pt-3 border-t border-border/30">
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-2">
                              {t("whois_fields.tech_contact")}
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                              {[
                                { label: t("whois_fields.tech_name"), value: result.techName },
                                { label: t("whois_fields.tech_organization"), value: result.techOrganization },
                                { label: t("whois_fields.tech_email"), value: result.techEmail },
                                { label: t("whois_fields.tech_phone"), value: result.techPhone },
                              ]
                                .filter((f) => isValidField(f.value))
                                .map((f, i) => (
                                  <div key={i} className="min-w-0">
                                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-0.5">
                                      {f.label}
                                    </p>
                                    <p className="text-xs font-mono break-all">{f.value}</p>
                                  </div>
                                ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Mobile-only inline ad — above status / nameservers cards */}
                  <ResultTextAd loading={loading} inline />

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                    {result.status.length > 0 && (
                      <div className="glass-panel border border-border rounded-xl p-5">
                        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                          <svg
                            className="w-4 h-4 text-muted-foreground"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          >
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            <path d="m9 12 2 2 4-4" />
                          </svg>
                          {t("whois_fields.status")}
                        </h3>
                        <div className="space-y-2.5">
                          {displayStatuses.map((s, i) => {
                            const info = getEppStatusInfo(s.status);
                            const color = getEppStatusColor(s.status);
                            const displayName = getEppStatusDisplayName(
                              s.status,
                            );
                            const link = getEppStatusLink(s.status);
                            return (
                              <div key={i} className="flex items-start gap-2.5">
                                <span
                                  className="w-1.5 h-1.5 rounded-full shrink-0 mt-[0.65rem]"
                                  style={{ backgroundColor: color }}
                                />
                                <div className="min-w-0">
                                  <a
                                    href={link}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs font-mono font-medium leading-tight hover:underline"
                                  >
                                    {displayName}
                                  </a>
                                  <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
                                    {info
                                      ? getEppStatusDescription(s.status, locale)
                                      : locale === "zh" || locale === "zh-tw"
                                        ? "注册局特定状态码，暂无标准释义。请参阅对应注册局文档了解详情。"
                                        : "Registry-specific status code with no standard description. Refer to the registry's documentation for details."}
                                  </p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                        {result.status.length > 5 && (
                          <button
                            onClick={() => setExpandStatus(!expandStatus)}
                            className="text-xs text-muted-foreground hover:text-foreground transition-colors font-medium mt-3"
                          >
                            {expandStatus
                              ? t("show_less")
                              : t("more_count", {
                                  count: result.status.length - 5,
                                })}
                          </button>
                        )}
                      </div>
                    )}

                    {result.nameServers.length > 0 && (
                      <div className="glass-panel border border-border rounded-xl p-5 flex flex-col">
                        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                          <RiServerLine className="w-4 h-4 text-muted-foreground" />
                          {t("whois_fields.name_servers")}
                        </h3>
                        <div className="space-y-2">
                          {result.nameServers.map((ns, i) => {
                            const nsBrand = getNsBrand(ns);
                            return (
                              <motion.div
                                key={i}
                                className="flex items-center gap-3 p-2 bg-muted/30 border border-border/50 rounded-md cursor-pointer hover:bg-muted/50 transition-colors"
                                onClick={() => copy(ns)}
                                whileTap={{ scale: 0.97 }}
                                whileHover={{ x: 2 }}
                                transition={{ type: "spring", stiffness: 500, damping: 30 }}
                              >
                                {nsBrand ? (
                                  nsBrand.slug ? (
                                    nsBrand.slug.startsWith("/") ? (
                                      <div className="w-4 h-4 shrink-0 flex items-center justify-center">
                                        <img
                                          src={nsBrand.slug}
                                          alt=""
                                          className="w-3.5 h-3.5 object-contain rounded-sm"
                                        />
                                      </div>
                                    ) : (
                                      <div className="w-4 h-4 shrink-0 flex items-center justify-center">
                                        <img
                                          src={resolveIconUrl(
                                            nsBrand.slug,
                                            nsBrand.color,
                                            false,
                                          )}
                                          alt=""
                                          className="w-3.5 h-3.5 object-contain dark:hidden"
                                        />
                                        <img
                                          src={resolveIconUrl(
                                            nsBrand.slug,
                                            nsBrand.color,
                                            true,
                                          )}
                                          alt=""
                                          className="w-3.5 h-3.5 object-contain hidden dark:block"
                                        />
                                      </div>
                                    )
                                  ) : (
                                    <div
                                      className="w-4 h-4 rounded-full shrink-0 flex items-center justify-center text-white text-[8px] font-bold"
                                      style={{ backgroundColor: nsBrand.color }}
                                    >
                                      {nsBrand.brand.charAt(0)}
                                    </div>
                                  )
                                ) : (
                                  <div className="w-2 h-2 rounded-full bg-emerald-500 shrink-0 ml-1" />
                                )}
                                <span className="font-mono text-xs text-muted-foreground truncate flex-1">
                                  {ns}
                                </span>
                                {nsBrand && (
                                  <span className="text-[9px] text-muted-foreground/60 shrink-0">
                                    {nsBrand.brand}
                                  </span>
                                )}
                              </motion.div>
                            );
                          })}
                        </div>
                        {result.dnssec && (
                          <div className="mt-auto pt-4 border-t border-border/50 flex justify-between items-center">
                            <span className="text-[10px] text-muted-foreground font-medium uppercase">
                              {t("whois_fields.dnssec")}
                            </span>
                            <span className="text-xs font-mono text-muted-foreground">
                              {translateDnssecValue(result.dnssec, locale)}
                            </span>
                          </div>
                        )}
                      </div>
                    )}


                    {hasIpFields && (
                      <div className="glass-panel border border-border rounded-xl p-5">
                        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                          <RiGlobalLine className="w-4 h-4 text-muted-foreground" />
                          {t("whois_fields.network_info")}
                        </h3>
                        <div className="space-y-3">
                          {[
                            {
                              label: t("whois_fields.cidr"),
                              value: result.cidr,
                            },
                            {
                              label: t("whois_fields.net_range"),
                              value: result.netRange,
                            },
                            {
                              label: t("whois_fields.net_name"),
                              value: result.netName,
                            },
                            {
                              label: t("whois_fields.net_type"),
                              value: result.netType,
                            },
                            {
                              label: t("whois_fields.origin_as"),
                              value: result.originAS,
                            },
                            {
                              label: t("whois_fields.inet_num"),
                              value: result.inetNum,
                            },
                            {
                              label: t("whois_fields.inet6_num"),
                              value: result.inet6Num,
                            },
                          ]
                            .filter((f) => isValidField(f.value))
                            .map((f, i) => (
                              <div key={i}>
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                  {f.label}
                                </p>
                                <p className="font-mono text-xs">{f.value}</p>
                              </div>
                            ))}
                        </div>
                      </div>
                    )}
                  </div>

                </motion.div>
                <motion.div variants={CARD_ITEM_VARIANTS} className="lg:col-span-4 relative overflow-hidden">
                  <div className="flex flex-col gap-6 lg:absolute lg:inset-0 lg:overflow-y-auto">
                    {isValidField(result.registrar) && (() => {
                      const hasAbuseContact = isValidField(result.abuseEmail) || isValidField(result.abusePhone);
                      const hasRegistrantContact = isValidField(result.registrantName) || isValidField(result.registrantOrganization) || isValidField(result.registrantEmail) || isValidField(result.registrantPhone) || isValidField(result.registrantCountry) || isValidField(result.registrantProvince) || isValidField(result.registrantCity) || isValidField(result.registrantAddress) || isValidField(result.registrantPostalCode) || isValidField(result.registrantFax) || hasAdminContact || hasTechContact;
                      return (
                      <div className="glass-panel border border-border rounded-xl overflow-hidden shrink-0">
                        {/* Header: icon + name + IANA */}
                        <div className="p-5 pb-4">
                          <div className="flex items-center justify-between mb-3">
                            <h3 className="text-sm font-semibold">{t("whois_fields.registrar")}</h3>
                            {isValidField(result.ianaId) && (
                              <Link
                                href={`https://www.internic.net/registrars/registrar-${result.ianaId}.html`}
                                target="_blank"
                                className="text-[10px] bg-muted px-2 py-0.5 rounded text-muted-foreground font-mono hover:bg-muted/80 transition-colors"
                              >
                                IANA: {result.ianaId}
                              </Link>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            {registrarIcon && registrarIcon.slug ? (
                              registrarIcon.slug.startsWith("/") ? (
                                <div className="w-10 h-10 bg-white dark:bg-zinc-800 rounded-lg flex items-center justify-center p-1.5 border shrink-0">
                                  <img src={registrarIcon.slug} alt="" className="w-full h-full object-contain rounded-md" />
                                </div>
                              ) : (
                                <div className="w-10 h-10 bg-white dark:bg-zinc-800 rounded-lg flex items-center justify-center p-1.5 border shrink-0">
                                  <img src={resolveIconUrl(registrarIcon.slug, registrarIcon.color, false)} alt="" className="w-full h-full object-contain dark:hidden" />
                                  <img src={resolveIconUrl(registrarIcon.slug, registrarIcon.color, true)} alt="" className="w-full h-full object-contain hidden dark:block" />
                                </div>
                              )
                            ) : (
                              <div className="w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold text-lg shrink-0"
                                style={{ backgroundColor: registrarIcon ? registrarIcon.color : getRegistrarFallbackColor(result.registrar) }}>
                                {registrarInitial}
                              </div>
                            )}
                            <div className="min-w-0 flex-1">
                              <p className="font-semibold text-sm leading-tight">{result.registrar}</p>
                              {isValidField(result.registrarURL) && (
                                <a href={result.registrarURL.startsWith("http") ? result.registrarURL : `http://${result.registrarURL}`}
                                  target="_blank" rel="noopener noreferrer"
                                  className="text-[11px] text-blue-600 dark:text-blue-400 hover:underline break-all">
                                  {result.registrarURL}
                                </a>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Registrar technical info */}
                        {(isValidField(result.whoisServer) || isValidField(result.registryDomainId)) && (
                          <div className="border-t border-border/50 px-5 py-3 space-y-2.5">
                            {isValidField(result.whoisServer) && (
                              <div className="flex items-start justify-between gap-3">
                                <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{t("whois_fields.whois_server")}</span>
                                <span className="text-xs font-mono text-foreground/80 break-all text-right">{result.whoisServer}</span>
                              </div>
                            )}
                            {isValidField(result.registryDomainId) && (
                              <div className="flex items-start justify-between gap-3">
                                <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{t("whois_fields.registry_domain_id")}</span>
                                <span className="text-xs font-mono text-foreground/80 break-all text-right">{result.registryDomainId}</span>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Abuse contact */}
                        {hasAbuseContact && (
                          <div className="border-t border-border/50 px-5 py-3">
                            <p className="text-[10px] uppercase font-semibold text-muted-foreground/60 tracking-wider mb-2">
                              {isZh ? "滥用联系" : "Abuse Contact"}
                            </p>
                            <div className="space-y-2">
                              {isValidField(result.abuseEmail) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "邮箱" : "Email"}</span>
                                  <a href={`mailto:${result.abuseEmail}`} className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all text-right">{result.abuseEmail}</a>
                                </div>
                              )}
                              {isValidField(result.abusePhone) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "电话" : "Phone"}</span>
                                  <span className="text-xs font-mono text-foreground/80 text-right">{result.abusePhone}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Registrant contact */}
                        {hasRegistrantContact && (
                          <div className="border-t border-border/50 px-5 py-3">
                            <p className="text-[10px] uppercase font-semibold text-muted-foreground/60 tracking-wider mb-2">
                              {isZh ? "注册人信息" : "Registrant"}
                            </p>
                            <div className="space-y-2">
                              {isValidField(result.registrantName) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "姓名" : "Name"}</span>
                                  <span className="text-xs text-foreground/80 text-right break-all">{result.registrantName}</span>
                                </div>
                              )}
                              {isValidField(result.registrantOrganization) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "机构" : "Org"}</span>
                                  <span className="text-xs text-foreground/80 text-right break-all">{result.registrantOrganization}</span>
                                </div>
                              )}
                              {(isValidField(result.registrantCountry) || isValidField(result.registrantProvince)) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "地区" : "Location"}</span>
                                  <span className="text-xs text-foreground/80 text-right">
                                    {[result.registrantProvince, result.registrantCountry].filter(v => isValidField(v)).join(", ")}
                                  </span>
                                </div>
                              )}
                              {isValidField(result.registrantEmail) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "邮箱" : "Email"}</span>
                                  <a href={`mailto:${result.registrantEmail}`} className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all text-right">{result.registrantEmail}</a>
                                </div>
                              )}
                              {isValidField(result.registrantPhone) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "电话" : "Phone"}</span>
                                  <span className="text-xs font-mono text-foreground/80 text-right">{result.registrantPhone}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                      );
                    })()}

                    {(result.rawWhoisContent || result.rawRdapContent) && !hideRawWhois && (
                      <div className="flex-1 min-h-[250px]">
                        <ResponsePanel
                          whoisContent={result.rawWhoisContent}
                          rdapContent={result.rawRdapContent}
                          target={target}
                          copy={copy}
                        />
                      </div>
                    )}
                  </div>
                </motion.div>
              </motion.div>
            </>
          )}

          {/* Text ad — shown after successful result, desktop only (mobile version is inline) */}
          <ResultTextAd loading={loading} />

            </motion.div>
          </div>
        </main>
      </ScrollArea>
      <Dialog open={showImagePreview} onOpenChange={setShowImagePreview}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("image_preview")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">{t("width")}</Label>
                <Input
                  type="number"
                  value={imgWidth}
                  onChange={(e) =>
                    setImgWidth(
                      Math.min(
                        4096,
                        Math.max(200, parseInt(e.target.value) || 1200),
                      ),
                    )
                  }
                  className="h-8 text-xs font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("height")}</Label>
                <Input
                  type="number"
                  value={imgHeight}
                  onChange={(e) =>
                    setImgHeight(
                      Math.min(
                        4096,
                        Math.max(200, parseInt(e.target.value) || 630),
                      ),
                    )
                  }
                  className="h-8 text-xs font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("theme")}</Label>
                <Select
                  value={imgTheme}
                  onValueChange={(v: "light" | "dark") => setImgTheme(v)}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="light">{t("light")}</SelectItem>
                    <SelectItem value="dark">{t("dark")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="rounded-lg border overflow-hidden bg-muted/30">
              <img
                src={buildOgUrl(target, result, {
                  w: imgWidth,
                  h: imgHeight,
                  theme: imgTheme,
                })}
                alt="OG Preview"
                className="w-full h-auto"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                disabled={imgActing !== null}
                onClick={async () => {
                  const ogUrl = buildOgUrl(target, result, {
                    w: imgWidth,
                    h: imgHeight,
                    theme: imgTheme,
                  });
                  setImgActing("download");
                  try {
                    const res = await fetch(ogUrl);
                    const blob = await res.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `whois-${target}-${imgWidth}x${imgHeight}.png`;
                    a.click();
                    URL.revokeObjectURL(url);
                    toast.success(t("toast.downloaded"));
                  } catch {
                    toast.error(t("toast.download_failed"));
                  } finally {
                    setImgActing(null);
                  }
                }}
              >
                {imgActing === "download"
                  ? <><RiLoader4Line className="w-3.5 h-3.5 mr-1.5 animate-spin" />{isZh ? "生成中…" : "Generating…"}</>
                  : <><RiDownloadLine className="w-3.5 h-3.5 mr-1.5" />{t("download")}</>
                }
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={imgActing !== null}
                onClick={async () => {
                  const ogUrl = buildOgUrl(target, result, {
                    w: imgWidth,
                    h: imgHeight,
                    theme: imgTheme,
                  });
                  setImgActing("copy");
                  try {
                    const res = await fetch(ogUrl);
                    const blob = await res.blob();
                    await navigator.clipboard.write([
                      new ClipboardItem({ "image/png": blob }),
                    ]);
                    toast.success(t("toast.copied_to_clipboard"));
                  } catch {
                    toast.error(t("toast.copy_to_clipboard_failed"));
                  } finally {
                    setImgActing(null);
                  }
                }}
              >
                {imgActing === "copy"
                  ? <><RiLoader4Line className="w-3.5 h-3.5 mr-1.5 animate-spin" />{isZh ? "生成中…" : "Generating…"}</>
                  : <><RiFileCopyLine className="w-3.5 h-3.5 mr-1.5" />{t("copy")}</>
                }
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const ogUrl = buildOgUrl(target, result, {
                    w: imgWidth,
                    h: imgHeight,
                    theme: imgTheme,
                  });
                  copy(window.location.origin + ogUrl);
                }}
              >
                <RiLinkM className="w-3.5 h-3.5 mr-1.5" />
                {t("copy_link")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
