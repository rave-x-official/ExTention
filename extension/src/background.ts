import {
  checkUrl,
  validateApiKey,
  type ExTentionConfig,
  type ThreatResult,
} from "./utils/api";
import {
  BLOCKLIST,
  RICKROLL_BLOCKLIST,
  type BlocklistEntry,
} from "./utils/blocklist";

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

interface CacheEntry {
  timestamp: number;
  result: ThreatResult;
}

const pendingChecks = new Map<number, string>();

const EXTENSION_URL = (() => {
  try {
    return chrome.runtime.getURL("");
  } catch {
    return "chrome-extension://null/";
  }
})();

async function getConfig(): Promise<ExTentionConfig> {
  const result = await chrome.storage.local.get([
    "vtApiKey",
    "backendUrl",
    "useBackend",
  ]);
  return {
    vtApiKey: result.vtApiKey,
    backendUrl: result.backendUrl,
    useBackend: result.useBackend,
  };
}

async function getCache(): Promise<Record<string, CacheEntry>> {
  const result = await chrome.storage.local.get("urlCache");
  return result.urlCache ?? {};
}

async function setCache(cache: Record<string, CacheEntry>): Promise<void> {
  await chrome.storage.local.set({ urlCache: cache });
}

function getDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function matchBlocklist(url: string, list: BlocklistEntry[]): string | null {
  const domain = getDomain(url);
  const fullUrl = url.toLowerCase();

  for (const entry of list) {
    switch (entry.type) {
      case "domain":
        if (domain === entry.pattern) return entry.label;
        break;
      case "url":
        if (fullUrl.includes(entry.pattern)) return entry.label;
        break;
      case "substring":
        if (fullUrl.includes(entry.pattern)) return entry.label;
        break;
      case "regex":
        try {
          const re = new RegExp(entry.pattern, "i");
          if (re.test(domain) || re.test(fullUrl)) return entry.label;
        } catch {
          // invalid regex — skip silently
        }
        break;
    }
  }

  return null;
}

function cleanCache(
  cache: Record<string, CacheEntry>,
): Record<string, CacheEntry> {
  const now = Date.now();
  return Object.fromEntries(
    Object.entries(cache).filter(([, v]) => now - v.timestamp < CACHE_TTL_MS),
  );
}

function redirectToInterstitial(
  tabId: number,
  url: string,
  threatType: string,
  label: string,
): void {
  chrome.storage.local.set(
    { blockedUrl: url, threatType, threatLabel: label },
    () => {
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL("interstitial.html"),
      });
    },
  );
}

async function isBypassed(url: string): Promise<boolean> {
  const result = await chrome.storage.local.get("bypass");
  if (result.bypass?.url === url && result.bypass?.expires > Date.now()) {
    await chrome.storage.local.remove("bypass");
    return true;
  }
  return false;
}

async function checkTabUrl(tabId: number, url: string): Promise<void> {
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  if (url.startsWith(EXTENSION_URL)) return;

  if (await isBypassed(url)) return;

  if (pendingChecks.get(tabId) === url) return;
  pendingChecks.set(tabId, url);

  try {
    const rickrollHit = matchBlocklist(url, RICKROLL_BLOCKLIST);
    if (rickrollHit) {
      chrome.action.setBadgeText({ text: "RR", tabId });
      redirectToInterstitial(tabId, url, "rickroll", rickrollHit);
      return;
    }

    const blocklistHit = matchBlocklist(url, BLOCKLIST);
    if (blocklistHit) {
      chrome.action.setBadgeText({ text: "!!", tabId });
      redirectToInterstitial(tabId, url, "malware", blocklistHit);
      return;
    }

    const config = await getConfig();
    if (!config.vtApiKey) return;

    const cache = await getCache();
    const cached = cache[url];

    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
      if (cached.result.malicious) {
        const threatType =
          cached.result.stats && cached.result.stats.suspicious > 2
            ? "phishing"
            : "malware";
        redirectToInterstitial(tabId, url, threatType, cached.result.label);
      }
      return;
    }

    try {
      const backendUrl = config.useBackend ? config.backendUrl : undefined;
      const result = await checkUrl(url, config.vtApiKey, backendUrl);

      cache[url] = { timestamp: Date.now(), result };
      await setCache(cleanCache(cache));

      if (result.malicious) {
        const threatType =
          result.stats && result.stats.suspicious > 2 ? "phishing" : "malware";
        redirectToInterstitial(tabId, url, threatType, result.label);
      }
    } catch {
      // rate limited, network error, or backend unreachable — skip silently
    }
  } finally {
    if (pendingChecks.get(tabId) === url) {
      pendingChecks.delete(tabId);
    }
  }
}

chrome.action.setBadgeText({ text: "ON" });

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    if (!details.url) return;
    checkTabUrl(details.tabId, details.url);
  },
  { urls: ["http://*/*", "https://*/*"] },
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "VALIDATE_KEY") {
    validateApiKey(message.key)
      .then(sendResponse)
      .catch((err: Error) =>
        sendResponse({ valid: false, error: err.message }),
      );
    return true;
  }

  return false;
});
