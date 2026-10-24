import type { InjectOptions } from "./types.js";
import { loadProfile } from "./vault.js";

export async function injectSession(session: any, opts: InjectOptions) {
  if (!session?.Network) {
    throw new Error("active cdp session required");
  }

  const profile = await loadProfile(opts.service, opts.vaultDir);
  if (!profile) {
    throw new Error(`no session profile found for service "${opts.service}"`);
  }

  if (profile.cookies && profile.cookies.length > 0) {
    if (typeof session.Network.setCookies === "function") {
      await session.Network.setCookies({ cookies: profile.cookies });
    } else if (typeof session.Network.setCookie === "function") {
      for (const cookie of profile.cookies) {
        try {
          await session.Network.setCookie(cookie);
        } catch {
          // best-effort per cookie
        }
      }
    }
  }

  const destUrl = opts.url || profile.origin || `https://${profile.domain}`;
  const shouldNavigate = opts.navigate !== false;

  if (shouldNavigate && session.Page?.navigate) {
    await session.Page.navigate({ url: destUrl });
    if (typeof session.Page.loadEventFired === "function") {
      await session.Page.loadEventFired().catch(() => {});
    }
    await new Promise((resolve) => setTimeout(resolve, 350));
  }

  const hasStorage =
    (profile.localStorage && Object.keys(profile.localStorage).length > 0) ||
    (profile.sessionStorage && Object.keys(profile.sessionStorage).length > 0);

  if (hasStorage && session.Runtime?.evaluate) {
    try {
      await session.Runtime.evaluate({
        expression: `(function(ls, ss) {
          try {
            if (ls) {
              for (var k in ls) { localStorage.setItem(k, ls[k]); }
            }
          } catch(e) {}
          try {
            if (ss) {
              for (var sk in ss) { sessionStorage.setItem(sk, ss[sk]); }
            }
          } catch(e) {}
        })(${JSON.stringify(profile.localStorage || {})}, ${JSON.stringify(profile.sessionStorage || {})})`,
        returnByValue: false,
      });
    } catch {
      // storage restoration best effort
    }
  }

  return {
    success: true,
    service: profile.service,
    domain: profile.domain,
    authenticated: true,
    cookiesInjected: profile.cookies?.length || 0,
    storageInjected: Object.keys(profile.localStorage || {}).length,
    currentUrl: destUrl,
  };
}
