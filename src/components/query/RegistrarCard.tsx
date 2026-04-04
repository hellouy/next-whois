import React from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { useTranslation } from "@/lib/i18n";
import { WhoisAnalyzeResult } from "@/lib/whois/types";
import { REGISTRAR_ICONS } from "@/data/query-page/registrar-icons";

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

function isValidField(v: string | null | undefined): boolean {
  if (!v || !v.trim()) return false;
  const INVALID_FIELD_VALUES = new Set([
    "unknown", "n/a", "na", "none", "null", "undefined", "-", "--",
  ]);
  return !INVALID_FIELD_VALUES.has(v.trim().toLowerCase());
}

export function RegistrarCard({
  result,
  isZh,
  hasAdminContact,
  hasTechContact,
}: {
  result: WhoisAnalyzeResult;
  isZh: boolean;
  hasAdminContact: boolean;
  hasTechContact: boolean;
}) {
  const { t } = useTranslation();

  const registrarIcon = getRegistrarIcon(result.registrar, result.registrarURL);
  const registrarInitial =
    result.registrar && result.registrar !== "Unknown"
      ? result.registrar.charAt(0).toUpperCase()
      : "?";

  const hasAbuseContact = isValidField(result.abuseEmail) || isValidField(result.abusePhone);
  const hasRegistrantContact =
    isValidField(result.registrantName) ||
    isValidField(result.registrantOrganization) ||
    isValidField(result.registrantEmail) ||
    isValidField(result.registrantPhone) ||
    isValidField(result.registrantCountry) ||
    isValidField(result.registrantProvince) ||
    isValidField(result.registrantCity) ||
    isValidField(result.registrantAddress) ||
    isValidField(result.registrantPostalCode) ||
    isValidField(result.registrantFax) ||
    hasAdminContact ||
    hasTechContact;

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
                <img src={registrarIcon.slug} alt="" loading="lazy" decoding="async" className="w-full h-full object-contain rounded-md" />
              </div>
            ) : (
              <div className="w-10 h-10 bg-white dark:bg-zinc-800 rounded-lg flex items-center justify-center p-1.5 border shrink-0">
                <img src={resolveIconUrl(registrarIcon.slug, registrarIcon.color, false)} alt="" loading="lazy" decoding="async" className="w-full h-full object-contain dark:hidden" />
                <img src={resolveIconUrl(registrarIcon.slug, registrarIcon.color, true)} alt="" loading="lazy" decoding="async" className="w-full h-full object-contain hidden dark:block" />
              </div>
            )
          ) : (
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold text-lg shrink-0"
              style={{ backgroundColor: registrarIcon ? registrarIcon.color : getRegistrarFallbackColor(result.registrar) }}
            >
              {registrarInitial}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <p className="font-semibold text-sm leading-tight">{result.registrar}</p>
            {isValidField(result.registrarURL) && (
              <a
                href={result.registrarURL.startsWith("http") ? result.registrarURL : `http://${result.registrarURL}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] text-blue-600 dark:text-blue-400 hover:underline break-all"
              >
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
}
