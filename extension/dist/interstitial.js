/* ExTention - No More Tension.
 * Copyright (C) 2026 AG (Silver)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  function show(id) {
    const el = $(id);
    if (el) el.classList.remove("hidden");
  }

  function updateCard(threatType, blockedUrl, threatLabel) {
    const isRickroll = threatType === "rickroll";
    const isPhishing = threatType === "phishing";

    $("icon").textContent = isRickroll ? "🎸" : "⚠️";

    if (isRickroll) {
      show("threat-rickroll");
    } else if (isPhishing) {
      show("threat-phishing");
      $("threat-phishing").textContent = "Phishing Attempt Detected";
    } else {
      show("threat-malware");
    }

    if (threatLabel) {
      $("message").textContent = isRickroll
        ? "Someone is trying to Rickroll you! This site is a known prank."
        : isPhishing
          ? "This site is impersonating a trusted service to steal your credentials."
          : "This site has been flagged by security vendors as malicious.";
    }

    $("url-box").textContent = blockedUrl;
  }

  function handleGoThere(tabId, blockedUrl) {
    chrome.storage.local.set(
      { bypass: { url: blockedUrl, expires: Date.now() + 120000 } },
      function () {
        chrome.storage.local.remove(
          ["blockedUrl", "threatType", "threatLabel"],
          function () {
            chrome.tabs.update(tabId, { url: blockedUrl });
          },
        );
      },
    );
  }

  function handleBackToSafety(tabId) {
    chrome.tabs.update(tabId, { url: "https://www.google.com" });
  }

  function init() {
    chrome.storage.local.get(
      ["blockedUrl", "threatType", "threatLabel"],
      function (result) {
        const { blockedUrl, threatType, threatLabel } = result;

        if (!blockedUrl) {
          $("url-box").textContent =
            "No threat data available — this page was opened in error.";
          $("btn-go-there").classList.add("hidden");
          return;
        }

        updateCard(threatType || "malware", blockedUrl, threatLabel);

        chrome.tabs.getCurrent(function (tab) {
          if (!tab) return;
          const tabId = tab.id;

          $("btn-stay-safe").addEventListener("click", function () {
            $("btn-stay-safe").textContent = "✓ Staying Safe";
            $("btn-stay-safe").disabled = true;
          });

          $("btn-go-there").addEventListener("click", function () {
            handleGoThere(tabId, blockedUrl);
          });

          $("btn-back-to-safety").addEventListener("click", function (e) {
            e.preventDefault();
            handleBackToSafety(tabId);
          });
        });
      },
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
