// src/utils/api.ts
var VT_BASE = "https://www.virustotal.com/api/v3";
var TEST_IP = "8.8.8.8";
async function validateApiKey(key) {
  try {
    const res = await fetch(`${VT_BASE}/ip_addresses/${TEST_IP}`, {
      headers: { "x-apikey": key }
    });
    if (res.status === 200) return { valid: true };
    if (res.status === 401) return { valid: false, error: "Invalid API key" };
    if (res.status === 403) return { valid: false, error: "API key lacks access" };
    if (res.status === 429) return { valid: false, error: "Rate limited \u2013 try again later" };
    return { valid: false, error: `Unexpected HTTP ${res.status}` };
  } catch (err) {
    return { valid: false, error: `Network error: ${err.message}` };
  }
}
function hexEncode(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(input) {
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return hexEncode(hash);
}
function parseVtStats(data) {
  const attrs = data?.data?.attributes?.last_analysis_stats;
  if (!attrs) return void 0;
  return {
    malicious: attrs.malicious ?? 0,
    suspicious: attrs.suspicious ?? 0,
    harmless: attrs.harmless ?? 0,
    undetected: attrs.undetected ?? 0
  };
}
async function callVtDirect(url, apiKey) {
  const urlId = await sha256Hex(url);
  const res = await fetch(`${VT_BASE}/urls/${urlId}`, {
    headers: { "x-apikey": apiKey }
  });
  if (res.status === 404) {
    return { malicious: false, source: "virustotal", label: "No analysis found for this URL" };
  }
  if (!res.ok) {
    throw new Error(`VirusTotal error: HTTP ${res.status}`);
  }
  const data = await res.json();
  const stats = parseVtStats(data);
  if (!stats) {
    return { malicious: false, source: "virustotal", label: "No analysis data returned" };
  }
  const isMalicious = stats.malicious > 0 || stats.suspicious > 2;
  return {
    malicious: isMalicious,
    source: "virustotal",
    label: isMalicious ? `${stats.malicious} malicious, ${stats.suspicious} suspicious` : "Clean",
    stats
  };
}
async function callBackendProxy(url, apiKey, backendUrl) {
  const res = await fetch(`${backendUrl.replace(/\/+$/, "")}/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, api_key: apiKey })
  });
  if (!res.ok) {
    throw new Error(`Backend proxy error: HTTP ${res.status}`);
  }
  const data = await res.json();
  const stats = data.vt_stats ? {
    malicious: data.vt_stats.malicious ?? 0,
    suspicious: data.vt_stats.suspicious ?? 0,
    harmless: data.vt_stats.harmless ?? 0,
    undetected: data.vt_stats.undetected ?? 0
  } : void 0;
  return {
    malicious: data.malicious ?? false,
    source: "backend",
    label: data.label ?? "No result from backend",
    stats
  };
}
async function checkUrl(url, apiKey, backendUrl) {
  try {
    return await callVtDirect(url, apiKey);
  } catch {
    if (backendUrl) {
      try {
        return await callBackendProxy(url, apiKey, backendUrl);
      } catch {
        throw new Error(
          "Connection Error: Direct API call failed and backend proxy is unreachable. Verify your backend URL or check your network connection."
        );
      }
    }
    throw new Error(
      "Connection Error: Cannot reach VirusTotal. If CORS is blocked in your environment, enable the optional Python backend."
    );
  }
}

// src/utils/blocklist.ts
var BLOCKLIST = [
  { type: "domain", pattern: "malware.testing.google.test", label: "Test malware domain" },
  { type: "domain", pattern: "testmalware.com", label: "Known malware test domain" },
  { type: "domain", pattern: "malware-sample.com", label: "Malware sample distribution" },
  { type: "domain", pattern: "phishing.army", label: "Phishing Army blocklist" },
  { type: "domain", pattern: "malwaredomainlist.com", label: "Malware domain list" },
  { type: "url", pattern: "tinyurl.com/evil", label: "Shortened malicious redirect" },
  { type: "url", pattern: "tinyurl.com/prank", label: "Shortened prank redirect" },
  { type: "substring", pattern: ".tk/phishing", label: "Suspicious TLD phishing page" },
  { type: "substring", pattern: ".ml/login", label: "Suspicious TLD login page" },
  { type: "substring", pattern: ".ga/login", label: "Suspicious TLD login page" },
  { type: "substring", pattern: ".cf/login", label: "Suspicious TLD login page" },
  { type: "substring", pattern: "secure-login.xyz", label: "Credential harvesting domain" },
  { type: "substring", pattern: "account-verify.com", label: "Phishing verification page" },
  { type: "substring", pattern: "banking-secure.com", label: "Fake banking portal" },
  { type: "substring", pattern: "paypal-security.com", label: "Fake PayPal security page" },
  { type: "substring", pattern: "apple-id-verify.com", label: "Fake Apple ID verification" }
];
var RICKROLL_BLOCKLIST = [
  { type: "url", pattern: "youtube.com/watch?v=dQw4w9WgXcQ", label: "Classic Rickroll video" },
  { type: "url", pattern: "youtu.be/dQw4w9WgXcQ", label: "Classic Rickroll video (short)" },
  { type: "domain", pattern: "rickastley.co", label: "Rick Astley prank domain" },
  { type: "regex", pattern: "rickroll\\..*", label: "Rickroll domain pattern" },
  { type: "url", pattern: "bit.ly/rickroll", label: "Shortened rickroll redirect" },
  { type: "domain", pattern: "tenor.co", label: "Rickroll GIF redirect" },
  { type: "domain", pattern: "nevergonna.give", label: "Rickroll prank site" }
];

// src/background.ts
var CACHE_TTL_MS = 24 * 60 * 60 * 1e3;
var pendingChecks = /* @__PURE__ */ new Map();
var EXTENSION_URL = (() => {
  try {
    return chrome.runtime.getURL("");
  } catch {
    return "chrome-extension://null/";
  }
})();
async function getConfig() {
  const result = await chrome.storage.local.get([
    "vtApiKey",
    "backendUrl",
    "useBackend"
  ]);
  return {
    vtApiKey: result.vtApiKey,
    backendUrl: result.backendUrl,
    useBackend: result.useBackend
  };
}
async function getCache() {
  const result = await chrome.storage.local.get("urlCache");
  return result.urlCache ?? {};
}
async function setCache(cache) {
  await chrome.storage.local.set({ urlCache: cache });
}
function getDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}
function matchBlocklist(url, list) {
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
        }
        break;
    }
  }
  return null;
}
function cleanCache(cache) {
  const now = Date.now();
  return Object.fromEntries(
    Object.entries(cache).filter(([, v]) => now - v.timestamp < CACHE_TTL_MS)
  );
}
function redirectToInterstitial(tabId, url, threatType, label) {
  chrome.storage.local.set(
    { blockedUrl: url, threatType, threatLabel: label },
    () => {
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL("interstitial.html")
      });
    }
  );
}
async function isBypassed(url) {
  const result = await chrome.storage.local.get("bypass");
  if (result.bypass?.url === url && result.bypass?.expires > Date.now()) {
    await chrome.storage.local.remove("bypass");
    return true;
  }
  return false;
}
async function checkTabUrl(tabId, url) {
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
        const threatType = cached.result.stats && cached.result.stats.suspicious > 2 ? "phishing" : "malware";
        redirectToInterstitial(tabId, url, threatType, cached.result.label);
      }
      return;
    }
    try {
      const backendUrl = config.useBackend ? config.backendUrl : void 0;
      const result = await checkUrl(url, config.vtApiKey, backendUrl);
      cache[url] = { timestamp: Date.now(), result };
      await setCache(cleanCache(cache));
      if (result.malicious) {
        const threatType = result.stats && result.stats.suspicious > 2 ? "phishing" : "malware";
        redirectToInterstitial(tabId, url, threatType, result.label);
      }
    } catch {
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
  { urls: ["http://*/*", "https://*/*"] }
);
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "VALIDATE_KEY") {
    validateApiKey(message.key).then(sendResponse).catch(
      (err) => sendResponse({ valid: false, error: err.message })
    );
    return true;
  }
  return false;
});
