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
  reset: () => void;
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

  const captchaRequired = !!(provider && siteKey && scopeEnabled !== "");

  const clearPoll = () => {
    if (pollTimerRef.current !== null) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  React.useEffect(() => {
    if (!captchaRequired) return;

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

    if (!document.getElementById(scriptId)) {
      const script = document.createElement("script");
      script.id = scriptId;
      script.src = SCRIPT_URLS[provider] ?? "";
      script.async = true;
      script.defer = true;
      script.onload = () => tryRender(40);
      document.head.appendChild(script);
    } else {
      tryRender(40);
    }

    return () => clearPoll();
  }, [captchaRequired, provider, siteKey]);

  function reset() {
    clearPoll();
    const w = window as unknown as Record<string, unknown>;
    if (provider === "mtcaptcha" && (w as any).mtcaptcha) {
      (w as any).mtcaptcha.resetUI();
      widgetIdRef.current = null;
    } else if (provider === "turnstile" && w.turnstile && widgetIdRef.current !== null) {
      (w.turnstile as { reset: (id: unknown) => void }).reset(widgetIdRef.current);
    } else if (provider === "hcaptcha" && w.hcaptcha && widgetIdRef.current !== null) {
      (w.hcaptcha as { reset: (id: unknown) => void }).reset(widgetIdRef.current);
    }
    onReset();
  }

  return { captchaRef, captchaRequired, reset };
}
