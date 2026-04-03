import React from "react";
import Link from "next/link";
import {
  RiShareLine,
  RiTwitterXLine,
  RiFacebookFill,
  RiRedditLine,
  RiWhatsappLine,
  RiTelegramLine,
  RiLinkM,
  RiDownloadLine,
  RiFileCopyLine,
  RiCameraLine,
} from "@remixicon/react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { useTranslation } from "@/lib/i18n";
import { useClipboard } from "@/lib/utils";
import { toast } from "sonner";
import { WhoisAnalyzeResult } from "@/lib/whois/types";

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

export function SharePanel({
  target,
  result,
  currentUrl,
  isZh,
  onOpenImagePreview,
}: {
  target: string;
  result: WhoisAnalyzeResult | undefined;
  currentUrl: string;
  isZh: boolean;
  onOpenImagePreview: () => void;
}) {
  const { t } = useTranslation();
  const copy = useClipboard();

  return (
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
          <Link href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(`Whois Lookup: ${target}`)}&url=${encodeURIComponent(currentUrl)}`} target="_blank">
            <RiTwitterXLine className="w-4 h-4 mr-2" />Twitter / X
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href={`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(currentUrl)}`} target="_blank">
            <RiFacebookFill className="w-4 h-4 mr-2" />Facebook
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href={`https://reddit.com/submit?url=${encodeURIComponent(currentUrl)}`} target="_blank">
            <RiRedditLine className="w-4 h-4 mr-2" />Reddit
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href={`https://api.whatsapp.com/send?text=${encodeURIComponent(currentUrl)}`} target="_blank">
            <RiWhatsappLine className="w-4 h-4 mr-2" />WhatsApp
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href={`https://t.me/share/url?url=${encodeURIComponent(currentUrl)}`} target="_blank">
            <RiTelegramLine className="w-4 h-4 mr-2" />Telegram
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => copy(currentUrl)}>
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
        <DropdownMenuItem onClick={onOpenImagePreview}>
          <RiCameraLine className="w-4 h-4 mr-2" />{t("preview_customize")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
