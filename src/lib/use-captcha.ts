import React from "react";

type CaptchaProvider = "turnstile" | "hcaptcha" | "mtcaptcha" | "";

interface UseCaptchaOptions {
  provider: CaptchaProvider;
  siteKey: string;
  /** Whether captcha is enabled for this specific scope (login / register).
   *  Pass the raw string from site settings: non-empty = enabled, empty = disabled. */
  scopeEnabled: string;
  onToken: (token: string) => void;
  onReset: () => void;
}

interface UseCaptchaResult {
  captchaRef: React.RefObject<HTMLDivElement>;
  /** True when the captcha is required on this page (provider + key + scope all active). */
  captchaRequired: boolean;
  /** True when the captcha script failed to load or the widget could not be rendered
   *  (e.g. blocked by an ad-blocker / content-blocker). Lets the UI surface an error. */
  captchaBlocked: boolean;
  reset: () => void;
  /** Manually retry loading the captcha after a block/failure. */
  retryLoad: () => void;
}

const SCRIPT_URLS: Record<string, string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  hcaptcha: "https://js.hcaptcha.com/1/api.js?render=explicit",
  mtcaptcha: "https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js",
};

export function useCaptcha({
  provider,
  siteKey,
  scopeEnabled,
  onToken,
  onReset,
}: UseCaptchaOptions): UseCaptchaResult {
  const captchaRef = React.useRef<HTMLDivElement>(null);
  const widgetIdRef = React.useRef<unknown>(null);
  const pollTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const [captchaBlocked, setCaptchaBlocked] = React.useState(false);
  const [retryCount, setRetryCount] = React.useState(0);

  const captchaRequired = !!(provider && siteKey && scopeEnabled !== "");

  const clearPoll = () => {
    if (pollTimerRef.current !== null) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  React.useEffect(() => {
    if (!captchaRequired) return;

    // Reset blocked state on each (re-)attempt
    setCaptchaBlocked(false);

    const w = window as unknown as Record<string, unknown>;
    const scriptId = `captcha-script-${provider}`;

    function tryRender(attemptsLeft: number) {
      clearPoll();
      if (!captchaRef.current || widgetIdRef.current !== null) return;

      if (provider === "turnstile" && w.turnstile) {
        widgetIdRef.current = (w.turnstile as {
          render: (el: HTMLElement, opts: Record<string, unknown>) => unknown;
        }).render(captchaRef.current, {
          sitekey: siteKey,
          callback: (tk: string) => onToken(tk),
          "expired-callback": () => onToken(""),
          "error-callback": () => onToken(""),
        });
        return;
      }

      if (provider === "hcaptcha" && w.hcaptcha) {
        widgetIdRef.current = (w.hcaptcha as {
          render: (el: HTMLElement, opts: Record<string, unknown>) => unknown;
        }).render(captchaRef.current, {
          sitekey: siteKey,
          callback: (tk: string) => onToken(tk),
          "expired-callback": () => onToken(""),
          "error-callback": () => onToken(""),
        });
        return;
      }

      if (provider === "mtcaptcha" && (w as any).mtcaptcha) {
        (w as any).mtcaptcha.renderUI(captchaRef.current);
        widgetIdRef.current = true;
        return;
      }

      if (attemptsLeft > 0) {
        pollTimerRef.current = setTimeout(() => tryRender(attemptsLeft - 1), 200);
      } else {
        // All polling attempts exhausted — widget never appeared.
        // Most likely the script was blocked by an ad-blocker or content-blocker.
        setCaptchaBlocked(true);
      }
    }

    if (provider === "mtcaptcha") {
      (w as any).mtcaptchaConfig = {
        sitekey: siteKey,
        callback: (detail: { verifyResult: string }) => onToken(detail.verifyResult || ""),
        "expired-callback": () => onToken(""),
        "error-callback": () => onToken(""),
        "auto-render-on-load": true,
      };
    }

    const existingScript = document.getElementById(scriptId) as HTMLScriptElement | null;

    if (!existingScript) {
      const script = document.createElement("script");
      script.id = scriptId;
      script.src = SCRIPT_URLS[provider] ?? "";
      script.async = true;
      script.defer = true;
      script.addEventListener("load", () => {
        script.dataset.loaded = "1";
        tryRender(40);
      }, { once: true });
      script.addEventListener("error", () => setCaptchaBlocked(true), { once: true });
      document.head.appendChild(script);
    } else if (existingScript.dataset.loaded === "1") {
      // Script already loaded — render immediately
      tryRender(40);
    } else {
      // Script is still downloading — poll until the provider global appears
      // (the original script's load handler will set dataset.loaded and call tryRender,
      // but if this effect runs in parallel we just start our own polling)
      tryRender(60); // up to 12 s of polling
      existingScript.addEventListener("error", () => setCaptchaBlocked(true), { once: true });
    }

    return () => clearPoll();
  }, [captchaRequired, provider, siteKey, retryCount]);

  function reset() {
    clearPoll();
    setCaptchaBlocked(false);
    const w = window as unknown as Record<string, unknown>;
    const prevWidgetId = widgetIdRef.current;
    widgetIdRef.current = null;
    if (provider === "mtcaptcha" && (w as any).mtcaptcha) {
      (w as any).mtcaptcha.resetUI();
    } else if (provider === "turnstile" && w.turnstile && prevWidgetId !== null) {
      (w.turnstile as { reset: (id: unknown) => void }).reset(prevWidgetId);
    } else if (provider === "hcaptcha" && w.hcaptcha && prevWidgetId !== null) {
      (w.hcaptcha as { reset: (id: unknown) => void }).reset(prevWidgetId);
    }
    onReset();
  }

  function retryLoad() {
    clearPoll();
    widgetIdRef.current = null;
    setCaptchaBlocked(false);
    // Remove old script tag so it gets re-appended fresh
    const scriptId = `captcha-script-${provider}`;
    const old = document.getElementById(scriptId);
    if (old) old.remove();
    // Clear the captcha container
    if (captchaRef.current) captchaRef.current.innerHTML = "";
    // Bump retry counter to re-trigger the effect
    setRetryCount((c) => c + 1);
    onReset();
  }

  return { captchaRef, captchaRequired, captchaBlocked, reset, retryLoad };
}
