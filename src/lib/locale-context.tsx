import React, { createContext, useContext, useState, useEffect, useLayoutEffect, useRef } from "react";
import { useSession } from "next-auth/react";

export const LOCALES = ["en", "zh", "zh-tw", "de", "ru", "ja", "fr", "ko"] as const;
export type Locale = (typeof LOCALES)[number];

interface LocaleContextType {
  locale: Locale;
  setLocale: (locale: Locale) => void;
}

const LocaleContext = createContext<LocaleContextType>({
  locale: "en",
  setLocale: () => {},
});

/**
 * Client-side locale detection.
 * Priority: NEXT_LOCALE cookie → navigator.language → "en"
 */
function detectClientLocale(): Locale {
  if (typeof window === "undefined") return "en";

  const cookie = document.cookie.match(/(?:^|;\s*)NEXT_LOCALE=([^;]+)/);
  if (cookie && (LOCALES as readonly string[]).includes(cookie[1])) {
    return cookie[1] as Locale;
  }

  const nav = (navigator.language || "en").toLowerCase();
  if (nav.startsWith("zh-tw") || nav.startsWith("zh-hk") || nav.startsWith("zh-mo")) return "zh-tw";
  if (nav.startsWith("zh")) return "zh";
  if (nav.startsWith("de")) return "de";
  if (nav.startsWith("ru")) return "ru";
  if (nav.startsWith("ja")) return "ja";
  if (nav.startsWith("fr")) return "fr";
  if (nav.startsWith("ko")) return "ko";
  return "en";
}

// useLayoutEffect fires synchronously after React's DOM mutations but BEFORE
// the browser paints.  Using it for locale sync means any English→target-language
// switch resolves before the first pixel is drawn — eliminating the flash.
// On the server useLayoutEffect doesn't run, so fall back to useEffect to avoid
// the "useLayoutEffect does nothing on the server" warning.
const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? useLayoutEffect : useEffect;

interface LocaleProviderProps {
  children: React.ReactNode;
  /**
   * Server-detected locale passed from App.getInitialProps.
   * When provided the provider uses it as the initial state so SSR and the
   * first client render agree — eliminating the English→target language flash.
   */
  initialLocale?: Locale;
}

export function LocaleProvider({ children, initialLocale }: LocaleProviderProps) {
  const [locale, setLocaleState] = useState<Locale>(initialLocale ?? "en");
  const { data: session } = useSession();
  const persistedRef = useRef<string | null>(null);

  useIsomorphicLayoutEffect(() => {
    const clientLocale = detectClientLocale();
    if (clientLocale !== locale) {
      setLocaleState(clientLocale);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // When a logged-in user's locale changes, persist it to the DB (debounced)
  useEffect(() => {
    if (!session?.user?.email) return;
    if (persistedRef.current === locale) return;
    persistedRef.current = locale;
    fetch("/api/user/update-locale", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ locale }),
    }).catch(() => {});
  }, [locale, session?.user?.email]);

  const setLocale = (newLocale: Locale) => {
    document.cookie = `NEXT_LOCALE=${newLocale};path=/;max-age=${60 * 60 * 24 * 365};samesite=lax`;
    setLocaleState(newLocale);
  };

  return (
    <LocaleContext.Provider value={{ locale, setLocale }}>
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale() {
  return useContext(LocaleContext);
}
