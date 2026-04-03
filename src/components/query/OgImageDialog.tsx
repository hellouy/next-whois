import React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  RiDownloadLine,
  RiFileCopyLine,
  RiLinkM,
  RiLoader4Line,
} from "@remixicon/react";
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

export function OgImageDialog({
  open,
  onOpenChange,
  target,
  result,
  isZh,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  target: string;
  result: WhoisAnalyzeResult | undefined;
  isZh: boolean;
}) {
  const { t } = useTranslation();
  const copy = useClipboard();
  const [imgWidth, setImgWidth] = React.useState(1200);
  const [imgHeight, setImgHeight] = React.useState(630);
  const [imgTheme, setImgTheme] = React.useState<"light" | "dark">("light");
  const [imgActing, setImgActing] = React.useState<"download" | "copy" | null>(null);

  React.useEffect(() => {
    if (open) {
      setImgTheme(
        document.documentElement.classList.contains("dark") ? "dark" : "light",
      );
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
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
                    Math.min(4096, Math.max(200, parseInt(e.target.value) || 1200)),
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
                    Math.min(4096, Math.max(200, parseInt(e.target.value) || 630)),
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
  );
}
