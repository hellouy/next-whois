import React from "react";

export interface SiteSettings {
  // Branding
  site_title: string;
  site_subtitle: string;
  site_description: string;
  site_keywords: string;
  site_footer: string;
  site_logo_text: string;
  site_icon_url: string;
  site_announcement: string;
  // OG / Social
  og_site_name: string;
  og_url: string;
  og_image: string;
  og_image_twitter: string;
  og_image_wechat: string;
  og_image_facebook: string;
  og_image_youtube: string;
  twitter_card: string;
  // Admin
  admin_email: string;
  // Auth & access control
  allow_registration: string;
  require_login: string;
  disable_login: string;
  maintenance_mode: string;
  maintenance_message: string;
  query_only_mode: string;
  hide_raw_whois: string;
  // Core feature toggles
  enable_search_links: string;
  enable_feedback: string;
  enable_stamps: string;
  enable_sponsor: string;
  enable_share: string;
  enable_dns: string;
  enable_ip: string;
  enable_ssl: string;
  enable_icp: string;
  enable_http: string;
  enable_tools: string;
  enable_remind: string;
  enable_links: string;
  enable_about: string;
  enable_changelog: string;
  enable_docs: string;
  // Home page content
  home_hero_title: string;
  home_hero_subtitle: string;
  home_placeholder: string;
  home_show_stats: string;
  // Home announcement
  home_announcement_enabled: string;
  home_announcement_text: string;
  home_announcement_type: string;
  home_announcement_url: string;
  // Result page ad
  result_ad_enabled: string;
  result_ad_text: string;
  result_ad_url: string;
  result_ad_label: string;
  // About page
  about_title: string;
  about_content: string;
  about_intro_en: string;
  about_contact_email: string;
  about_github_url: string;
  about_author_name: string;
  about_author_url: string;
  about_thanks: string;
  // Changelog page
  changelog_title: string;
  // Links page
  links_title: string;
  links_content: string;
  // Sponsor settings
  sponsor_page_title: string;
  sponsor_page_desc: string;
  sponsor_alipay_qr: string;
  sponsor_wechat_qr: string;
  sponsor_github_url: string;
  sponsor_extra_links: string;
  sponsor_paypal_url: string;
  sponsor_crypto_btc: string;
  sponsor_crypto_eth: string;
  sponsor_crypto_usdt: string;
  sponsor_crypto_usdt_network: string;
  sponsor_crypto_okx: string;
  // SEO / Analytics
  analytics_google: string;
  analytics_umami: string;
  analytics_umami_src: string;
  custom_head_script: string;
  // Invite code
  require_invite_code: string;
  // CAPTCHA / Human verification
  captcha_provider: string;
  captcha_site_key: string;
  captcha_secret_key: string;
  // Per-provider keys (independent, never overwrite each other)
  captcha_turnstile_site_key: string;
  captcha_turnstile_secret_key: string;
  captcha_hcaptcha_site_key: string;
  captcha_hcaptcha_secret_key: string;
  captcha_mtcaptcha_site_key: string;
  captcha_mtcaptcha_secret_key: string;
  // OG image styles
  og_enabled_styles: string;
  // SMTP email config
  smtp_enabled: string;
  smtp_host: string;
  smtp_port: string;
  smtp_user: string;
  smtp_pass: string;
  smtp_from: string;
  smtp_secure: string;
  // Payment gateway config
  payment_stripe_enabled: string;
  payment_stripe_pk: string;
  payment_stripe_sk: string;
  payment_stripe_webhook_secret: string;
  payment_xunhupay_enabled: string;
  payment_xunhupay_appid: string;
  payment_xunhupay_secret: string;
  payment_alipay_enabled: string;
  payment_alipay_appid: string;
  payment_alipay_notify_url: string;
  payment_alipay_public_key: string;
  payment_alipay_private_key: string;
  payment_paypal_enabled: string;
  payment_paypal_client_id: string;
  payment_paypal_client_secret: string;
  payment_paypal_webhook_id: string;
  payment_paypal_env: string;
  payment_currency: string;
  payment_success_url: string;
  // Email / Resend config
  resend_api_key: string;
  resend_from_email: string;
}

export const DEFAULT_SETTINGS: SiteSettings = {
  site_title: "X.RW · RDAP+WHOIS",
  site_subtitle: "专业的 WHOIS / RDAP 查询工具",
  site_description: "快速查询域名、IP、ASN、CIDR 的 WHOIS / RDAP 信息，支持多节点并行查询。",
  site_keywords: "Whois, RDAP, Lookup, Domain, IPv4, IPv6, ASN, CIDR, X.RW",
  site_footer: "© 2025 X.RW · WHOIS & RDAP Lookup Service",
  site_logo_text: "X.RW",
  site_icon_url: "",
  site_announcement: "",
  og_site_name: "X.RW",
  og_url: "",
  og_image: "",
  og_image_twitter: "",
  og_image_wechat: "",
  og_image_facebook: "",
  og_image_youtube: "",
  twitter_card: "summary_large_image",
  admin_email: "",
  allow_registration: "1",
  require_login: "",
  disable_login: "",
  maintenance_mode: "",
  maintenance_message: "",
  query_only_mode: "",
  hide_raw_whois: "",
  enable_search_links: "1",
  enable_feedback: "1",
  enable_stamps: "1",
  enable_sponsor: "1",
  enable_share: "1",
  enable_dns: "1",
  enable_ip: "1",
  enable_ssl: "1",
  enable_icp: "1",
  enable_http: "1",
  enable_tools: "1",
  enable_remind: "1",
  enable_links: "1",
  enable_about: "1",
  enable_changelog: "1",
  enable_docs: "1",
  home_hero_title: "",
  home_hero_subtitle: "",
  home_placeholder: "",
  home_show_stats: "1",
  home_announcement_enabled: "",
  home_announcement_text: "",
  home_announcement_type: "info",
  home_announcement_url: "",
  result_ad_enabled: "",
  result_ad_text: "",
  result_ad_url: "",
  result_ad_label: "广告",
  about_title: "",
  about_content: "",
  about_intro_en: "",
  about_contact_email: "",
  about_github_url: "",
  about_author_name: "",
  about_author_url: "",
  about_thanks: "",
  changelog_title: "",
  links_title: "",
  links_content: "",
  sponsor_page_title: "赞助支持",
  sponsor_page_desc: "感谢您对本项目的支持！您的赞助将帮助我们持续维护和改进服务。",
  sponsor_alipay_qr: "",
  sponsor_wechat_qr: "",
  sponsor_github_url: "",
  sponsor_extra_links: "",
  sponsor_paypal_url: "",
  sponsor_crypto_btc: "",
  sponsor_crypto_eth: "",
  sponsor_crypto_usdt: "",
  sponsor_crypto_usdt_network: "",
  sponsor_crypto_okx: "",
  analytics_google: "",
  analytics_umami: "",
  analytics_umami_src: "",
  custom_head_script: "",
  require_invite_code: "",
  captcha_provider: "",
  captcha_site_key: "",
  captcha_secret_key: "",
  captcha_turnstile_site_key: "",
  captcha_turnstile_secret_key: "",
  captcha_hcaptcha_site_key: "",
  captcha_hcaptcha_secret_key: "",
  captcha_mtcaptcha_site_key: "",
  captcha_mtcaptcha_secret_key: "",
  og_enabled_styles: "0,1,2,3,4,5,6,7",
  smtp_enabled: "",
  smtp_host: "",
  smtp_port: "465",
  smtp_user: "",
  smtp_pass: "",
  smtp_from: "",
  smtp_secure: "ssl",
  payment_stripe_enabled: "",
  payment_stripe_pk: "",
  payment_stripe_sk: "",
  payment_stripe_webhook_secret: "",
  payment_xunhupay_enabled: "",
  payment_xunhupay_appid: "",
  payment_xunhupay_secret: "",
  payment_alipay_enabled: "",
  payment_alipay_appid: "",
  payment_alipay_notify_url: "",
  payment_alipay_public_key: "",
  payment_alipay_private_key: "",
  payment_paypal_enabled: "",
  payment_paypal_client_id: "",
  payment_paypal_client_secret: "",
  payment_paypal_webhook_id: "",
  payment_paypal_env: "live",
  payment_currency: "CNY",
  payment_success_url: "",
  resend_api_key: "",
  resend_from_email: "",
};

const STORAGE_KEY = "next_whois_settings_ts";
const SESSION_CACHE_KEY = "next_whois_settings_cache";

const SiteSettingsContext = React.createContext<SiteSettings>(DEFAULT_SETTINGS);

function readSessionCache(): Partial<SiteSettings> | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(SESSION_CACHE_KEY);
    if (raw) return JSON.parse(raw) as Partial<SiteSettings>;
  } catch {}
  return null;
}

function writeSessionCache(s: Partial<SiteSettings>) {
  try { sessionStorage.setItem(SESSION_CACHE_KEY, JSON.stringify(s)); } catch {}
}

// On the server useLayoutEffect is a no-op (and triggers a warning), so we
// fall back to useEffect there.  On the client we use useLayoutEffect so the
// sessionStorage cache is applied synchronously BEFORE the first paint,
// eliminating any visible "X.RW → real name" flash for returning visitors.
const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? React.useLayoutEffect : React.useEffect;

export function SiteSettingsProvider({
  children,
  initialSettings,
}: {
  children: React.ReactNode;
  initialSettings?: Partial<SiteSettings>;
}) {
  // initialSettings may come from SSR props (e.g. the homepage passes them).
  // The useState initializer runs on both server and client, so both start with
  // the same value — no hydration mismatch.
  const [settings, setSettings] = React.useState<SiteSettings>({
    ...DEFAULT_SETTINGS,
    ...(initialSettings || {}),
  });

  const fetchSettings = React.useCallback(() => {
    fetch("/api/admin/settings")
      .then((r) => r.json())
      .then((data) => {
        if (data.settings) {
          const merged = { ...DEFAULT_SETTINGS, ...data.settings };
          setSettings(merged);
          writeSessionCache(data.settings);
        }
      })
      .catch(() => {});
  }, []);

  // --- Phase 1: apply cached settings BEFORE the first paint ---
  // useLayoutEffect fires synchronously after React hydrates the DOM but
  // before the browser paints the frame.  Reading sessionStorage here means
  // the user never sees the default "X.RW" text — only the cached real value.
  useIsomorphicLayoutEffect(() => {
    const cache = readSessionCache();
    if (cache) {
      setSettings({ ...DEFAULT_SETTINGS, ...(initialSettings || {}), ...cache });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Phase 2: network refresh + live-update listeners ---
  // These don't need to block the paint, so a regular useEffect is fine.
  React.useEffect(() => {
    const cache = readSessionCache();
    // Delay first fetch: sessionStorage already hydrates the UI.
    // Without cache we still fetch quickly (500 ms) so the first view isn't stale.
    const initialDelay = setTimeout(fetchSettings, cache ? 1500 : 500);

    function onStorage(e: StorageEvent) {
      if (e.key === STORAGE_KEY) fetchSettings();
    }
    window.addEventListener("storage", onStorage);

    function onUpdate() { fetchSettings(); }
    window.addEventListener("site-settings-updated", onUpdate);

    const timer = setInterval(fetchSettings, 300_000);

    return () => {
      clearTimeout(initialDelay);
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("site-settings-updated", onUpdate);
      clearInterval(timer);
    };
  }, [fetchSettings]);

  return (
    <SiteSettingsContext.Provider value={settings}>
      {children}
    </SiteSettingsContext.Provider>
  );
}

export function useSiteSettings(): SiteSettings {
  return React.useContext(SiteSettingsContext);
}

export function notifySettingsUpdated() {
  window.dispatchEvent(new Event("site-settings-updated"));
  try {
    localStorage.setItem(STORAGE_KEY, String(Date.now()));
  } catch {}
}
