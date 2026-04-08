import React from "react";
import { useTranslation } from "@/lib/i18n";
import { WhoisAnalyzeResult } from "@/lib/whois/types";

// Exact-match invalid values — only filter when the entire trimmed value matches
const INVALID_FIELD_VALUES = new Set([
  "unknown", "n/a", "none", "null", "undefined", "-", "--", "redacted for privacy",
  "not disclosed", "withheld for privacy",
]);

function isValidField(v: string | null | undefined): boolean {
  if (!v || !v.trim()) return false;
  const lower = v.trim().toLowerCase();
  // Only filter if the whole value is an invalid placeholder (not substrings like "na" in a name)
  if (INVALID_FIELD_VALUES.has(lower)) return false;
  // Filter standalone "n/a" variants but not names like "Na Li"
  if (/^n\/?a\.?$/i.test(lower)) return false;
  return true;
}

function CountryFlag({ code }: { code: string }) {
  if (!/^[A-Z]{2}$/i.test(code.trim())) return null;
  const lower = code.trim().toLowerCase();
  return (
    <img
      src={`https://flagcdn.com/w40/${lower}.png`}
      alt={code.trim().toUpperCase()}
      loading="lazy"
      decoding="async"
      className="w-4 h-3 object-cover rounded-[2px] inline-block"
      onError={(e) => {
        // Hide broken flag image gracefully
        (e.currentTarget as HTMLImageElement).style.display = "none";
      }}
    />
  );
}

export function WhoisFieldsTable({
  result,
  hasRegistrant,
  hasAdminContact,
  hasTechContact,
}: {
  result: WhoisAnalyzeResult;
  hasRegistrant: boolean;
  hasAdminContact: boolean;
  hasTechContact: boolean;
}) {
  const { t } = useTranslation();

  if (!hasRegistrant) return null;

  return (
    <div className="mt-6 pt-6 border-t border-border/50 space-y-4">
      {/* Registrant */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {[
          { label: t("whois_fields.registrant_name"),        value: result.registrantName },
          { label: t("whois_fields.registrant_organization"), value: result.registrantOrganization },
          { label: t("whois_fields.registrant_country"),     value: result.registrantCountry,    country: true },
          { label: t("whois_fields.registrant_province"),    value: result.registrantProvince },
          { label: t("whois_fields.registrant_city"),        value: result.registrantCity },
          { label: t("whois_fields.registrant_address"),     value: result.registrantAddress },
          { label: t("whois_fields.registrant_postal_code"), value: result.registrantPostalCode },
          { label: t("whois_fields.registrant_email"),       value: result.registrantEmail },
          { label: t("whois_fields.registrant_phone"),       value: result.registrantPhone },
          { label: t("whois_fields.registrant_fax"),         value: result.registrantFax },
        ]
          .filter((f) => isValidField(f.value))
          .map((f, i) => (
            <div key={i} className="min-w-0">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                {f.label}
              </p>
              <p className="text-xs font-mono whitespace-pre-wrap break-all flex items-center gap-1.5">
                {"country" in f && f.country && f.value && (
                  <CountryFlag code={f.value} />
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
              { label: t("whois_fields.admin_name"),         value: result.adminName },
              { label: t("whois_fields.admin_organization"), value: result.adminOrganization },
              { label: t("whois_fields.admin_country"),      value: result.adminCountry,    country: true },
              { label: t("whois_fields.admin_email"),        value: result.adminEmail },
              { label: t("whois_fields.admin_phone"),        value: result.adminPhone },
            ]
              .filter((f) => isValidField(f.value))
              .map((f, i) => (
                <div key={i} className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-0.5">
                    {f.label}
                  </p>
                  <p className="text-xs font-mono break-all flex items-center gap-1.5">
                    {"country" in f && f.country && f.value && (
                      <CountryFlag code={f.value} />
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
              { label: t("whois_fields.tech_name"),         value: result.techName },
              { label: t("whois_fields.tech_organization"), value: result.techOrganization },
              { label: t("whois_fields.tech_email"),        value: result.techEmail },
              { label: t("whois_fields.tech_phone"),        value: result.techPhone },
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
  );
}
