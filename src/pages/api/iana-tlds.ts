import type { NextApiRequest, NextApiResponse } from "next";
import {
  getAllCustomServers,
  getStaticWhoisServer,
} from "@/lib/whois/custom-servers";
import { GTLD_RDAP_BOOTSTRAP } from "@/lib/whois/rdap_gtld_bootstrap";
import { getCctldRdapOverrides } from "@/lib/whois/rdap_client";
import {
  isRedisAvailable,
  getJsonRedisValue,
  setJsonRedisValue,
} from "@/lib/server/redis";

const REDIS_IANA_KEY = "iana_tlds:v3";
const REDIS_IANA_TTL = 43_200; // 12 hours — shared across all Vercel instances

export type TldInfo = {
  tld: string;
  type: "cctld" | "gtld";
  country?: string;
  countryEn?: string;
  hasWhois: boolean;
  whoisServer?: string;
  hasRdap: boolean;
  rdapServer?: string;
};

export type IanaTldsResponse = {
  tlds: TldInfo[];
  total: number;
  ccTldCount: number;
  gTldCount: number;
  /** Suffixes with a known WHOIS and/or RDAP query path. */
  supportedCount: number;
  /** Suffixes with no known WHOIS or RDAP server. */
  unsupportedCount: number;
};

const CC_NAMES: Record<string, { zh: string; en: string }> = {
  ac: { zh: "阿森松岛", en: "Ascension Island" },
  ad: { zh: "安道尔", en: "Andorra" },
  ae: { zh: "阿联酋", en: "United Arab Emirates" },
  af: { zh: "阿富汗", en: "Afghanistan" },
  ag: { zh: "安提瓜和巴布达", en: "Antigua and Barbuda" },
  ai: { zh: "安圭拉", en: "Anguilla" },
  al: { zh: "阿尔巴尼亚", en: "Albania" },
  am: { zh: "亚美尼亚", en: "Armenia" },
  ao: { zh: "安哥拉", en: "Angola" },
  aq: { zh: "南极洲", en: "Antarctica" },
  ar: { zh: "阿根廷", en: "Argentina" },
  as: { zh: "美属萨摩亚", en: "American Samoa" },
  at: { zh: "奥地利", en: "Austria" },
  au: { zh: "澳大利亚", en: "Australia" },
  aw: { zh: "阿鲁巴", en: "Aruba" },
  ax: { zh: "奥兰群岛", en: "Åland Islands" },
  az: { zh: "阿塞拜疆", en: "Azerbaijan" },
  ba: { zh: "波黑", en: "Bosnia and Herzegovina" },
  bb: { zh: "巴巴多斯", en: "Barbados" },
  bd: { zh: "孟加拉国", en: "Bangladesh" },
  be: { zh: "比利时", en: "Belgium" },
  bf: { zh: "布基纳法索", en: "Burkina Faso" },
  bg: { zh: "保加利亚", en: "Bulgaria" },
  bh: { zh: "巴林", en: "Bahrain" },
  bi: { zh: "布隆迪", en: "Burundi" },
  bj: { zh: "贝宁", en: "Benin" },
  bl: { zh: "圣巴泰勒米", en: "Saint Barthélemy" },
  bm: { zh: "百慕大", en: "Bermuda" },
  bn: { zh: "文莱", en: "Brunei" },
  bo: { zh: "玻利维亚", en: "Bolivia" },
  bq: { zh: "荷属加勒比区", en: "Caribbean Netherlands" },
  br: { zh: "巴西", en: "Brazil" },
  bs: { zh: "巴哈马", en: "Bahamas" },
  bt: { zh: "不丹", en: "Bhutan" },
  bw: { zh: "博茨瓦纳", en: "Botswana" },
  by: { zh: "白俄罗斯", en: "Belarus" },
  bz: { zh: "伯利兹", en: "Belize" },
  ca: { zh: "加拿大", en: "Canada" },
  cc: { zh: "科科斯群岛", en: "Cocos Islands" },
  cd: { zh: "刚果（金）", en: "DR Congo" },
  cf: { zh: "中非共和国", en: "Central African Republic" },
  cg: { zh: "刚果（布）", en: "Republic of the Congo" },
  ch: { zh: "瑞士", en: "Switzerland" },
  ci: { zh: "科特迪瓦", en: "Ivory Coast" },
  ck: { zh: "库克群岛", en: "Cook Islands" },
  cl: { zh: "智利", en: "Chile" },
  cm: { zh: "喀麦隆", en: "Cameroon" },
  cn: { zh: "中国", en: "China" },
  co: { zh: "哥伦比亚", en: "Colombia" },
  cr: { zh: "哥斯达黎加", en: "Costa Rica" },
  cu: { zh: "古巴", en: "Cuba" },
  cv: { zh: "佛得角", en: "Cape Verde" },
  cw: { zh: "库拉索", en: "Curaçao" },
  cx: { zh: "圣诞岛", en: "Christmas Island" },
  cy: { zh: "塞浦路斯", en: "Cyprus" },
  cz: { zh: "捷克", en: "Czech Republic" },
  de: { zh: "德国", en: "Germany" },
  dj: { zh: "吉布提", en: "Djibouti" },
  dk: { zh: "丹麦", en: "Denmark" },
  dm: { zh: "多米尼克", en: "Dominica" },
  do: { zh: "多米尼加", en: "Dominican Republic" },
  dz: { zh: "阿尔及利亚", en: "Algeria" },
  ec: { zh: "厄瓜多尔", en: "Ecuador" },
  ee: { zh: "爱沙尼亚", en: "Estonia" },
  eg: { zh: "埃及", en: "Egypt" },
  eh: { zh: "西撒哈拉", en: "Western Sahara" },
  er: { zh: "厄立特里亚", en: "Eritrea" },
  es: { zh: "西班牙", en: "Spain" },
  et: { zh: "埃塞俄比亚", en: "Ethiopia" },
  eu: { zh: "欧盟", en: "European Union" },
  fi: { zh: "芬兰", en: "Finland" },
  fj: { zh: "斐济", en: "Fiji" },
  fk: { zh: "福克兰群岛", en: "Falkland Islands" },
  fm: { zh: "密克罗尼西亚", en: "Micronesia" },
  fo: { zh: "法罗群岛", en: "Faroe Islands" },
  fr: { zh: "法国", en: "France" },
  ga: { zh: "加蓬", en: "Gabon" },
  gb: { zh: "英国", en: "United Kingdom" },
  gd: { zh: "格林纳达", en: "Grenada" },
  ge: { zh: "格鲁吉亚", en: "Georgia" },
  gf: { zh: "法属圭亚那", en: "French Guiana" },
  gg: { zh: "根西岛", en: "Guernsey" },
  gh: { zh: "加纳", en: "Ghana" },
  gi: { zh: "直布罗陀", en: "Gibraltar" },
  gl: { zh: "格陵兰", en: "Greenland" },
  gm: { zh: "冈比亚", en: "Gambia" },
  gn: { zh: "几内亚", en: "Guinea" },
  gp: { zh: "瓜德罗普", en: "Guadeloupe" },
  gq: { zh: "赤道几内亚", en: "Equatorial Guinea" },
  gr: { zh: "希腊", en: "Greece" },
  gs: { zh: "南乔治亚岛", en: "South Georgia" },
  gt: { zh: "危地马拉", en: "Guatemala" },
  gu: { zh: "关岛", en: "Guam" },
  gw: { zh: "几内亚比绍", en: "Guinea-Bissau" },
  gy: { zh: "圭亚那", en: "Guyana" },
  hk: { zh: "香港", en: "Hong Kong" },
  hm: { zh: "赫德岛", en: "Heard Island" },
  hn: { zh: "洪都拉斯", en: "Honduras" },
  hr: { zh: "克罗地亚", en: "Croatia" },
  ht: { zh: "海地", en: "Haiti" },
  hu: { zh: "匈牙利", en: "Hungary" },
  id: { zh: "印度尼西亚", en: "Indonesia" },
  ie: { zh: "爱尔兰", en: "Ireland" },
  il: { zh: "以色列", en: "Israel" },
  im: { zh: "马恩岛", en: "Isle of Man" },
  in: { zh: "印度", en: "India" },
  io: { zh: "英属印度洋领地", en: "British Indian Ocean Territory" },
  iq: { zh: "伊拉克", en: "Iraq" },
  ir: { zh: "伊朗", en: "Iran" },
  is: { zh: "冰岛", en: "Iceland" },
  it: { zh: "意大利", en: "Italy" },
  je: { zh: "泽西岛", en: "Jersey" },
  jm: { zh: "牙买加", en: "Jamaica" },
  jo: { zh: "约旦", en: "Jordan" },
  jp: { zh: "日本", en: "Japan" },
  ke: { zh: "肯尼亚", en: "Kenya" },
  kg: { zh: "吉尔吉斯斯坦", en: "Kyrgyzstan" },
  kh: { zh: "柬埔寨", en: "Cambodia" },
  ki: { zh: "基里巴斯", en: "Kiribati" },
  km: { zh: "科摩罗", en: "Comoros" },
  kn: { zh: "圣基茨和尼维斯", en: "Saint Kitts and Nevis" },
  kp: { zh: "朝鲜", en: "North Korea" },
  kr: { zh: "韩国", en: "South Korea" },
  kw: { zh: "科威特", en: "Kuwait" },
  ky: { zh: "开曼群岛", en: "Cayman Islands" },
  kz: { zh: "哈萨克斯坦", en: "Kazakhstan" },
  la: { zh: "老挝", en: "Laos" },
  lb: { zh: "黎巴嫩", en: "Lebanon" },
  lc: { zh: "圣卢西亚", en: "Saint Lucia" },
  li: { zh: "列支敦士登", en: "Liechtenstein" },
  lk: { zh: "斯里兰卡", en: "Sri Lanka" },
  lr: { zh: "利比里亚", en: "Liberia" },
  ls: { zh: "莱索托", en: "Lesotho" },
  lt: { zh: "立陶宛", en: "Lithuania" },
  lu: { zh: "卢森堡", en: "Luxembourg" },
  lv: { zh: "拉脱维亚", en: "Latvia" },
  ly: { zh: "利比亚", en: "Libya" },
  ma: { zh: "摩洛哥", en: "Morocco" },
  mc: { zh: "摩纳哥", en: "Monaco" },
  md: { zh: "摩尔多瓦", en: "Moldova" },
  me: { zh: "黑山", en: "Montenegro" },
  mf: { zh: "法属圣马丁", en: "Saint Martin" },
  mg: { zh: "马达加斯加", en: "Madagascar" },
  mh: { zh: "马绍尔群岛", en: "Marshall Islands" },
  mk: { zh: "北马其顿", en: "North Macedonia" },
  ml: { zh: "马里", en: "Mali" },
  mm: { zh: "缅甸", en: "Myanmar" },
  mn: { zh: "蒙古", en: "Mongolia" },
  mo: { zh: "澳门", en: "Macao" },
  mp: { zh: "北马里亚纳群岛", en: "Northern Mariana Islands" },
  mq: { zh: "马提尼克", en: "Martinique" },
  mr: { zh: "毛里塔尼亚", en: "Mauritania" },
  ms: { zh: "蒙特塞拉特", en: "Montserrat" },
  mt: { zh: "马耳他", en: "Malta" },
  mu: { zh: "毛里求斯", en: "Mauritius" },
  mv: { zh: "马尔代夫", en: "Maldives" },
  mw: { zh: "马拉维", en: "Malawi" },
  mx: { zh: "墨西哥", en: "Mexico" },
  my: { zh: "马来西亚", en: "Malaysia" },
  mz: { zh: "莫桑比克", en: "Mozambique" },
  na: { zh: "纳米比亚", en: "Namibia" },
  nc: { zh: "新喀里多尼亚", en: "New Caledonia" },
  ne: { zh: "尼日尔", en: "Niger" },
  nf: { zh: "诺福克岛", en: "Norfolk Island" },
  ng: { zh: "尼日利亚", en: "Nigeria" },
  ni: { zh: "尼加拉瓜", en: "Nicaragua" },
  nl: { zh: "荷兰", en: "Netherlands" },
  no: { zh: "挪威", en: "Norway" },
  np: { zh: "尼泊尔", en: "Nepal" },
  nr: { zh: "瑙鲁", en: "Nauru" },
  nu: { zh: "纽埃", en: "Niue" },
  nz: { zh: "新西兰", en: "New Zealand" },
  om: { zh: "阿曼", en: "Oman" },
  pa: { zh: "巴拿马", en: "Panama" },
  pe: { zh: "秘鲁", en: "Peru" },
  pf: { zh: "法属波利尼西亚", en: "French Polynesia" },
  pg: { zh: "巴布亚新几内亚", en: "Papua New Guinea" },
  ph: { zh: "菲律宾", en: "Philippines" },
  pk: { zh: "巴基斯坦", en: "Pakistan" },
  pl: { zh: "波兰", en: "Poland" },
  pm: { zh: "圣皮埃尔和密克隆", en: "Saint Pierre and Miquelon" },
  pn: { zh: "皮特凯恩群岛", en: "Pitcairn Islands" },
  pr: { zh: "波多黎各", en: "Puerto Rico" },
  ps: { zh: "巴勒斯坦", en: "Palestine" },
  pt: { zh: "葡萄牙", en: "Portugal" },
  pw: { zh: "帕劳", en: "Palau" },
  py: { zh: "巴拉圭", en: "Paraguay" },
  qa: { zh: "卡塔尔", en: "Qatar" },
  re: { zh: "留尼汪", en: "Réunion" },
  ro: { zh: "罗马尼亚", en: "Romania" },
  rs: { zh: "塞尔维亚", en: "Serbia" },
  ru: { zh: "俄罗斯", en: "Russia" },
  rw: { zh: "卢旺达", en: "Rwanda" },
  sa: { zh: "沙特阿拉伯", en: "Saudi Arabia" },
  sb: { zh: "所罗门群岛", en: "Solomon Islands" },
  sc: { zh: "塞舌尔", en: "Seychelles" },
  sd: { zh: "苏丹", en: "Sudan" },
  se: { zh: "瑞典", en: "Sweden" },
  sg: { zh: "新加坡", en: "Singapore" },
  sh: { zh: "圣赫勒拿", en: "Saint Helena" },
  si: { zh: "斯洛文尼亚", en: "Slovenia" },
  sj: { zh: "斯瓦尔巴和扬马延", en: "Svalbard and Jan Mayen" },
  sk: { zh: "斯洛伐克", en: "Slovakia" },
  sl: { zh: "塞拉利昂", en: "Sierra Leone" },
  sm: { zh: "圣马力诺", en: "San Marino" },
  sn: { zh: "塞内加尔", en: "Senegal" },
  so: { zh: "索马里", en: "Somalia" },
  sr: { zh: "苏里南", en: "Suriname" },
  ss: { zh: "南苏丹", en: "South Sudan" },
  st: { zh: "圣多美和普林西比", en: "São Tomé and Príncipe" },
  su: { zh: "苏联（历史）", en: "Soviet Union (historical)" },
  sv: { zh: "萨尔瓦多", en: "El Salvador" },
  sx: { zh: "荷属圣马丁", en: "Sint Maarten" },
  sy: { zh: "叙利亚", en: "Syria" },
  sz: { zh: "斯威士兰", en: "Eswatini" },
  tc: { zh: "特克斯和凯科斯群岛", en: "Turks and Caicos Islands" },
  td: { zh: "乍得", en: "Chad" },
  tf: { zh: "法属南部领地", en: "French Southern Territories" },
  tg: { zh: "多哥", en: "Togo" },
  th: { zh: "泰国", en: "Thailand" },
  tj: { zh: "塔吉克斯坦", en: "Tajikistan" },
  tk: { zh: "托克劳", en: "Tokelau" },
  tl: { zh: "东帝汶", en: "Timor-Leste" },
  tm: { zh: "土库曼斯坦", en: "Turkmenistan" },
  tn: { zh: "突尼斯", en: "Tunisia" },
  to: { zh: "汤加", en: "Tonga" },
  tp: { zh: "东帝汶（旧）", en: "East Timor (old)" },
  tr: { zh: "土耳其", en: "Turkey" },
  tt: { zh: "特立尼达和多巴哥", en: "Trinidad and Tobago" },
  tv: { zh: "图瓦卢", en: "Tuvalu" },
  tw: { zh: "台湾", en: "Taiwan" },
  tz: { zh: "坦桑尼亚", en: "Tanzania" },
  ua: { zh: "乌克兰", en: "Ukraine" },
  ug: { zh: "乌干达", en: "Uganda" },
  uk: { zh: "英国", en: "United Kingdom" },
  um: { zh: "美国本土外小岛屿", en: "U.S. Minor Outlying Islands" },
  us: { zh: "美国", en: "United States" },
  uy: { zh: "乌拉圭", en: "Uruguay" },
  uz: { zh: "乌兹别克斯坦", en: "Uzbekistan" },
  va: { zh: "梵蒂冈", en: "Vatican City" },
  vc: { zh: "圣文森特和格林纳丁斯", en: "Saint Vincent and the Grenadines" },
  ve: { zh: "委内瑞拉", en: "Venezuela" },
  vg: { zh: "英属维尔京群岛", en: "British Virgin Islands" },
  vi: { zh: "美属维尔京群岛", en: "U.S. Virgin Islands" },
  vn: { zh: "越南", en: "Vietnam" },
  vu: { zh: "瓦努阿图", en: "Vanuatu" },
  wf: { zh: "瓦利斯和富图纳", en: "Wallis and Futuna" },
  ws: { zh: "萨摩亚", en: "Samoa" },
  ye: { zh: "也门", en: "Yemen" },
  yt: { zh: "马约特", en: "Mayotte" },
  za: { zh: "南非", en: "South Africa" },
  zm: { zh: "赞比亚", en: "Zambia" },
  zw: { zh: "津巴布韦", en: "Zimbabwe" },
};

let cache: { data: IanaTldsResponse; at: number } | null = null;
const CACHE_TTL = 86400 * 1000;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  // L1: in-process memory cache (per-instance, instant)
  if (cache && Date.now() - cache.at < CACHE_TTL) {
    res.setHeader("Cache-Control", "public, max-age=86400, stale-while-revalidate=86400");
    return res.status(200).json(cache.data);
  }

  // L2: Redis cache (shared across all Vercel serverless instances)
  if (isRedisAvailable()) {
    try {
      const cached = await getJsonRedisValue<IanaTldsResponse>(REDIS_IANA_KEY);
      if (cached) {
        cache = { data: cached, at: Date.now() };
        res.setHeader("Cache-Control", "public, max-age=86400, stale-while-revalidate=86400");
        return res.status(200).json(cached);
      }
    } catch { /* ignore — fall through to fetch */ }
  }

  try {
    const [ianaResp, rdapResp, serversData] = await Promise.all([
      fetch("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", {
        headers: { "User-Agent": "RDAP+WHOIS/1.6" },
        signal: AbortSignal.timeout(8000),
      }),
      fetch("https://data.iana.org/rdap/dns.json", {
        headers: { "User-Agent": "RDAP+WHOIS/1.6" },
        signal: AbortSignal.timeout(8000),
      }).catch(() => null),
      getAllCustomServers().catch(() => ({})),
    ]);

    if (!ianaResp.ok) throw new Error("IANA TLD fetch failed");

    const text = await ianaResp.text();
    const ianaTlds = text
      .split("\n")
      .map((l) => l.trim().toLowerCase())
      .filter((l) => l && !l.startsWith("#"));

    const rdapMap: Record<string, string> = {};
    if (rdapResp && rdapResp.ok) {
      const rdapData = await rdapResp.json();
      if (Array.isArray(rdapData?.services)) {
        for (const [[...tldList], [...urlList]] of rdapData.services as [string[], string[]][]) {
          const url = urlList[0];
          if (!url) continue;
          for (const t of tldList) rdapMap[t.toLowerCase()] = url.replace(/\/$/, "");
        }
      }
    }

    const serverMap = serversData as Record<string, unknown>;
    const rdapOverrides = getCctldRdapOverrides();

    const tlds: TldInfo[] = ianaTlds.map((tld) => {
      const isCc = tld.length === 2 && /^[a-z]{2}$/.test(tld);
      const serverEntry = serverMap[tld];
      let hasWhois = false;
      let whoisServer: string | undefined;

      // 1) Runtime sources: tld_registry_info DB + built-in scrapers + user overrides
      if (typeof serverEntry === "string" && serverEntry) {
        hasWhois = true;
        whoisServer = serverEntry;
      } else if (serverEntry && typeof serverEntry === "object") {
        const h = (serverEntry as any).host || (serverEntry as any).url || (serverEntry as any).name || (serverEntry as any).registryUrl;
        if (h) { hasWhois = true; whoisServer = String(h); }
      }

      // 2) Static sources: whois-servers.json + gTLD WHOIS bootstrap.
      //    Merge even when the DB is populated — getStaticWhoisServer reads the
      //    file + bootstrap directly and always represents a usable TCP path.
      if (!hasWhois) {
        const staticWhois = getStaticWhoisServer(tld);
        if (staticWhois) { hasWhois = true; whoisServer = staticWhois; }
      }

      // RDAP path = hand-verified ccTLD overrides ∪ bundled bootstrap ∪ live IANA.
      // The bundled maps keep hasRdap accurate even when the live fetch fails,
      // and the live map catches TLDs added after the last bundle generation.
      const rdapServer =
        rdapOverrides[tld] ?? GTLD_RDAP_BOOTSTRAP[tld] ?? rdapMap[tld];
      const hasRdap = Boolean(rdapServer);

      const names = isCc ? CC_NAMES[tld] : undefined;
      return {
        tld,
        type: isCc ? "cctld" : "gtld",
        country: names?.zh,
        countryEn: names?.en,
        hasWhois,
        whoisServer,
        hasRdap,
        rdapServer,
      };
    });

    const ccTldCount = tlds.filter((t) => t.type === "cctld").length;
    const gTldCount = tlds.filter((t) => t.type === "gtld").length;
    const supportedCount = tlds.filter((t) => t.hasWhois || t.hasRdap).length;

    const result: IanaTldsResponse = {
      tlds,
      total: tlds.length,
      ccTldCount,
      gTldCount,
      supportedCount,
      unsupportedCount: tlds.length - supportedCount,
    };
    cache = { data: result, at: Date.now() };

    // Write to Redis so other Vercel instances skip the IANA fetch
    if (isRedisAvailable()) {
      setJsonRedisValue(REDIS_IANA_KEY, result, REDIS_IANA_TTL).catch(() => {});
    }

    res.setHeader("Cache-Control", "public, max-age=86400, stale-while-revalidate=86400");
    return res.status(200).json(result);
  } catch (e) {
    return res.status(500).json({ error: "Failed to fetch IANA TLD list" });
  }
}
