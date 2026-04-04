import { one } from "@/lib/db-query";

export async function getCaptchaConfig(
  scope?: "login" | "register",
): Promise<{ provider: string; siteKey: string; secretKey: string }> {
  try {
    const provider = (await one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'captcha_provider'"))?.value ?? "";
    if (!provider) return { provider: "", siteKey: "", secretKey: "" };

    // Check if CAPTCHA is enabled for this specific scope
    if (scope) {
      const scopeKey = scope === "login" ? "captcha_on_login" : "captcha_on_register";
      const scopeRow = await one<{ value: string }>(`SELECT value FROM site_settings WHERE key = '${scopeKey}'`);
      // Default: enabled (treat missing row as enabled)
      const scopeEnabled = scopeRow === null || (scopeRow?.value ?? "1") !== "";
      if (!scopeEnabled) return { provider: "", siteKey: "", secretKey: "" };
    }

    // Read per-provider keys first, fall back to legacy shared keys
    const [perSiteKey, perSecretKey, legacySiteKey, legacySecretKey] = await Promise.all([
      one<{ value: string }>(`SELECT value FROM site_settings WHERE key = 'captcha_${provider}_site_key'`),
      one<{ value: string }>(`SELECT value FROM site_settings WHERE key = 'captcha_${provider}_secret_key'`),
      one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'captcha_site_key'"),
      one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'captcha_secret_key'"),
    ]);

    return {
      provider,
      siteKey: perSiteKey?.value || legacySiteKey?.value || "",
      secretKey: perSecretKey?.value || legacySecretKey?.value || "",
    };
  } catch {
    return { provider: "", siteKey: "", secretKey: "" };
  }
}

export async function verifyCaptchaToken(token: string, provider: string, secretKey: string): Promise<boolean> {
  if (!token || !secretKey) return false;

  try {
    if (provider === "mtcaptcha") {
      const url = `https://service.mtcaptcha.com/mtcv1/api/siteverify?sitekey=${encodeURIComponent(secretKey)}&token=${encodeURIComponent(token)}`;
      const res = await fetch(url, { method: "GET" });
      if (!res.ok) return false;
      const data = await res.json();
      return data.success === true;
    }

    const endpoints: Record<string, string> = {
      turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      hcaptcha: "https://hcaptcha.com/siteverify",
    };
    const url = endpoints[provider];
    if (!url) return false;

    const body = new URLSearchParams({ secret: secretKey, response: token });
    const res = await fetch(url, { method: "POST", body, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    if (!res.ok) return false;
    const data = await res.json();
    return data.success === true;
  } catch (err) {
    console.error("[captcha] verify error:", err);
    return false;
  }
}
