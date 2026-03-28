import { one } from "@/lib/db-query";

export async function getCaptchaConfig(): Promise<{ provider: string; siteKey: string; secretKey: string }> {
  try {
    const rows = await Promise.all([
      one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'captcha_provider'"),
      one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'captcha_site_key'"),
      one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'captcha_secret_key'"),
    ]);
    return {
      provider: rows[0]?.value ?? "",
      siteKey: rows[1]?.value ?? "",
      secretKey: rows[2]?.value ?? "",
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
