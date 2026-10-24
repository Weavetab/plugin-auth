import type { CaptureOptions, VaultCookie, VaultProfile } from "./types.js";
import { saveProfile, sanitizeService } from "./vault.js";

function getDomainRoot(hostname: string): string {
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

export async function captureSession(session: any, opts: CaptureOptions = {}) {
  if (!session?.Page?.getFrameTree) {
    throw new Error("active cdp session required");
  }

  const { frameTree } = await session.Page.getFrameTree();
  const currentUrl = opts.url || frameTree.frame.url;

  if (!currentUrl || !currentUrl.startsWith("http")) {
    throw new Error("active tab must be on an http or https page");
  }

  const parsed = new URL(currentUrl);
  const host = parsed.hostname;
  const origin = parsed.origin;
  const root = getDomainRoot(host);

  const svc = opts.service ? sanitizeService(opts.service) : root.replace(/\.[a-z]+$/, "");

  const cookieMap = new Map<string, VaultCookie>();

  try {
    const res = await session.Network.getCookies({ urls: [currentUrl] });
    for (const c of res.cookies || []) {
      const key = `${c.name}:${c.domain}:${c.path}`;
      cookieMap.set(key, {
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        expires: c.expires,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
      });
    }
  } catch {
    // getCookies call failed
  }

  try {
    if (typeof session.Network.getAllCookies === "function") {
      const all = await session.Network.getAllCookies();
      for (const c of all.cookies || []) {
        const d = (c.domain || "").replace(/^\./, "").toLowerCase();
        if (d === host || d.endsWith(`.${root}`) || d === root) {
          const key = `${c.name}:${c.domain}:${c.path}`;
          if (!cookieMap.has(key)) {
            cookieMap.set(key, {
              name: c.name,
              value: c.value,
              domain: c.domain,
              path: c.path,
              expires: c.expires,
              httpOnly: c.httpOnly,
              secure: c.secure,
              sameSite: c.sameSite,
            });
          }
        }
      }
    }
  } catch {
    // getAllCookies is optional across chrome versions
  }

  let lsData: Record<string, string> = {};
  let ssData: Record<string, string> = {};

  if (opts.includeStorage !== false && session?.Runtime?.evaluate) {
    try {
      const evalRes = await session.Runtime.evaluate({
        expression: `(function() {
          var ls = {};
          try {
            for (var i = 0; i < localStorage.length; i++) {
              var k = localStorage.key(i);
              if (k) ls[k] = localStorage.getItem(k);
            }
          } catch(e) {}
          var ss = {};
          try {
            for (var j = 0; j < sessionStorage.length; j++) {
              var sk = sessionStorage.key(j);
              if (sk) ss[sk] = sessionStorage.getItem(sk);
            }
          } catch(e) {}
          return { ls: ls, ss: ss };
        })()`,
        returnByValue: true,
      });

      if (evalRes?.result?.value) {
        lsData = evalRes.result.value.ls || {};
        ssData = evalRes.result.value.ss || {};
      }
    } catch {
      // storage evaluation is best-effort
    }
  }

  // ponytail: cookies + local/session storage cover 99% of web auth flows. ceiling: indexeddb tokens skipped. upgrade: when target service stores auth session exclusively in indexeddb.
  const profile: VaultProfile = {
    version: 1,
    service: svc,
    domain: host,
    origin,
    capturedAt: new Date().toISOString(),
    cookies: Array.from(cookieMap.values()),
    localStorage: lsData,
    sessionStorage: ssData,
  };

  const saved = await saveProfile(profile, opts.vaultDir);

  return {
    success: true,
    service: svc,
    domain: host,
    origin,
    capturedAt: profile.capturedAt,
    cookieCount: profile.cookies.length,
    storageKeyCount: Object.keys(lsData).length,
    file: saved.file,
  };
}
