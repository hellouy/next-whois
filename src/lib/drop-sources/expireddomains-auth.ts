/**
 * Shared HTTP helpers for expireddomains.net.
 *
 * Extracted from `/api/admin/expired-domains-crawl` so both the admin crawler
 * and the drop-calendar adapter authenticate through the same flow.
 */

export const EXPIREDDOMAINS_BASE = "https://member.expireddomains.net";
export const EXPIREDDOMAINS_LOGIN_URL = "https://www.expireddomains.net/login/";
export const EXPIREDDOMAINS_LOGIN_CHECK_URL = "https://www.expireddomains.net/logincheck/";
export const EXPIREDDOMAINS_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

export function extractCookies(res: Response): string[] {
  if (typeof (res.headers as any).getSetCookie === "function") {
    return (res.headers as any).getSetCookie().map((c: string) => c.split(";")[0].trim());
  }
  const raw = res.headers.get("set-cookie");
  if (!raw) return [];
  return raw.split(/,(?=\s*\w+=)/).map((c) => c.split(";")[0].trim());
}

export function cookieHeader(cookies: string[]): string {
  const map = new Map<string, string>();
  for (const c of cookies) {
    const [name] = c.split("=");
    map.set(name.trim(), c);
  }
  return Array.from(map.values()).join("; ");
}

/** Log in and return the cookie header, or throw with a user-facing reason. */
export async function loginToExpiredDomains(username: string, password: string): Promise<string> {
  // The site migrated to www.expireddomains.net and its login form now posts to
  // /logincheck/ with fields `login`, `password`, `rememberme` (no CSRF token).
  const getRes = await fetch(EXPIREDDOMAINS_LOGIN_URL, {
    headers: { "User-Agent": EXPIREDDOMAINS_UA },
    redirect: "follow",
  });
  const loginCookies = extractCookies(getRes);

  const postRes = await fetch(EXPIREDDOMAINS_LOGIN_CHECK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": cookieHeader(loginCookies),
      "Referer": EXPIREDDOMAINS_LOGIN_URL,
      "User-Agent": EXPIREDDOMAINS_UA,
      "Origin": EXPIREDDOMAINS_BASE,
    },
    body: new URLSearchParams({ login: username, password, rememberme: "1" }).toString(),
    redirect: "manual",
  });

  const postCookies = extractCookies(postRes);
  const allCookies = cookieHeader([...loginCookies, ...postCookies]);

  // New flow: /logincheck/ 302s to member.expireddomains.net/auth/?token=… which
  // sets the member-subdomain sessionid cookie. Follow it before judging success.
  const authUrl = postRes.headers.get("location");
  let authCookies: string[] = [];
  if (authUrl && authUrl.includes("/auth/")) {
    try {
      const authRes = await fetch(authUrl, {
        headers: {
          "Cookie": cookieHeader([...loginCookies, ...postCookies]),
          "User-Agent": EXPIREDDOMAINS_UA,
        },
        redirect: "manual",
      });
      authCookies = extractCookies(authRes);
    } catch { /* cookie may still arrive on the logincheck response */ }
  }
  const sessionCookies = cookieHeader([...loginCookies, ...postCookies, ...authCookies]);

  // The member subdomain sets the session cookie as `ExpiredDomainssessid`.
  if (!sessionCookies.includes("ExpiredDomainssessid")) {
    const hint =
      postRes.status !== 302 && postRes.status !== 200
        ? ` (unexpected HTTP ${postRes.status} after POST)`
        : "";
    throw new Error(`Login failed — check your expireddomains.net username and password${hint}`);
  }
  void allCookies;
  return sessionCookies;
}
