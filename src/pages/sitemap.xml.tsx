import { GetServerSideProps } from "next";
import { many } from "@/lib/db-query";
import { getOrigin } from "@/lib/seo";

const STATIC_PAGES = [
  { path: "/",            changefreq: "daily",   priority: "1.0" },
  { path: "/about",       changefreq: "monthly",  priority: "0.8" },
  { path: "/guide",       changefreq: "monthly",  priority: "0.7" },
  { path: "/tlds",        changefreq: "weekly",   priority: "0.7" },
  { path: "/directory",   changefreq: "weekly",   priority: "0.7" },
  { path: "/dns",         changefreq: "monthly",  priority: "0.7" },
  { path: "/ip",          changefreq: "monthly",  priority: "0.7" },
  { path: "/ssl",         changefreq: "monthly",  priority: "0.7" },
  { path: "/icp",         changefreq: "monthly",  priority: "0.6" },
  { path: "/http",        changefreq: "monthly",  priority: "0.6" },
  { path: "/tools",       changefreq: "monthly",  priority: "0.6" },
  { path: "/docs",        changefreq: "monthly",  priority: "0.6" },
  { path: "/faq",         changefreq: "monthly",  priority: "0.6" },
  { path: "/feedback",    changefreq: "monthly",  priority: "0.5" },
  { path: "/sponsor",     changefreq: "monthly",  priority: "0.5" },
  { path: "/links",       changefreq: "monthly",  priority: "0.6" },
  { path: "/changelog",   changefreq: "weekly",   priority: "0.6" },
  { path: "/login",       changefreq: "monthly",  priority: "0.4" },
  { path: "/register",    changefreq: "monthly",  priority: "0.4" },
];

function escXml(str: string) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export const getServerSideProps: GetServerSideProps = async ({ req, res }) => {
  const origin = getOrigin(req);

  // Fetch recently searched, unique public domains from DB (exclude IPs/ASNs)
  let domainRows: { query: string; latest: string }[] = [];
  try {
    const result = await many<{ query: string; latest: string }>(
      `SELECT query, MAX(created_at)::text AS latest
       FROM search_history
       WHERE query NOT LIKE '%:%'        -- exclude IPv6
         AND query NOT SIMILAR TO '[0-9.]+' -- exclude IPv4
         AND query NOT ILIKE 'AS%'       -- exclude ASNs
         AND query LIKE '%.%'            -- must have dot (domain-like)
         AND length(query) <= 100
       GROUP BY query
       ORDER BY MAX(created_at) DESC
       LIMIT 5000`,
    );
    domainRows = result ?? [];
  } catch {
    domainRows = [];
  }

  const now = new Date().toISOString().slice(0, 10);

  const staticUrls = STATIC_PAGES.map(p => `
  <url>
    <loc>${escXml(`${origin}${p.path}`)}</loc>
    <changefreq>${p.changefreq}</changefreq>
    <priority>${p.priority}</priority>
    <lastmod>${now}</lastmod>
  </url>`).join("");

  const domainUrls = domainRows.map(row => {
    const loc = escXml(`${origin}/${row.query}`);
    const lastmod = row.latest ? row.latest.slice(0, 10) : now;
    return `
  <url>
    <loc>${loc}</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
    <lastmod>${lastmod}</lastmod>
  </url>`;
  }).join("");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
          http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
${staticUrls}
${domainUrls}
</urlset>`;

  res.setHeader("Content-Type", "application/xml; charset=utf-8");
  res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=86400");
  res.write(xml);
  res.end();

  return { props: {} };
};

export default function SitemapXml() {
  return null;
}
