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
import { StrictMode, useState, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import "./popup.css";

const VT_TEST_URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8";

type Page = "setup" | "ready" | "checking";

function Popup() {
  const [apiKey, setApiKey] = useState("");
  const [backendUrl, setBackendUrl] = useState("");
  const [useBackend, setUseBackend] = useState(false);
  const [page, setPage] = useState<Page>("checking");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    type: "ok" | "error" | "info";
    text: string;
  } | null>(null);

  useEffect(() => {
    chrome.storage.local
      .get(["vtApiKey", "backendUrl", "useBackend"])
      .then((result) => {
        if (result.backendUrl) setBackendUrl(result.backendUrl);
        if (result.useBackend) setUseBackend(result.useBackend);
        if (result.vtApiKey) {
          setPage("ready");
        } else {
          setPage("setup");
        }
      });
  }, []);

  const validateKey = useCallback(async (key: string): Promise<boolean> => {
    const res = await fetch(VT_TEST_URL, { headers: { "x-apikey": key } });
    if (res.status === 200) return true;
    if (res.status === 401)
      throw new Error("Invalid API key – check your key at virustotal.com");
    if (res.status === 429)
      throw new Error("Rate limited – try again in 1 minute");
    throw new Error(`Unexpected error (HTTP ${res.status})`);
  }, []);

  const handleSave = useCallback(async () => {
    const trimmed = apiKey.trim();
    if (!trimmed) {
      setMessage({ type: "error", text: "Please enter an API key" });
      return;
    }

    setSaving(true);
    setMessage(null);

    try {
      await validateKey(trimmed);
      await chrome.storage.local.set({
        vtApiKey: trimmed,
        backendUrl: backendUrl.trim() || undefined,
        useBackend: useBackend && !!backendUrl.trim(),
      });
      setMessage({ type: "ok", text: "API key saved successfully" });
      setPage("ready");
    } catch (err) {
      setMessage({ type: "error", text: (err as Error).message });
    } finally {
      setSaving(false);
    }
  }, [apiKey, backendUrl, useBackend, validateKey]);

  const handleRemove = useCallback(async () => {
    await chrome.storage.local.remove(["vtApiKey", "backendUrl", "useBackend"]);
    setApiKey("");
    setBackendUrl("");
    setUseBackend(false);
    setPage("setup");
    setMessage(null);
  }, []);

  const handleBackendToggle = useCallback(() => {
    setUseBackend((prev) => !prev);
  }, []);

  if (page === "checking") {
    return (
      <div className="container">
        <div className="spinner" />
        <p>Loading…</p>
      </div>
    );
  }

  if (page === "setup") {
    return (
      <div className="container">
        <div className="header">
          <div className="status-dot off" />
          <h1>ExTention</h1>
        </div>

        <p className="subtitle">
          Welcome to ExTention! Enter your VirusTotal API key to start removing
          tension from your browsing. Your key is stored locally and never sent
          to our servers.
        </p>

        <input
          className="input"
          type="password"
          placeholder="Paste your VirusTotal API key"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSave()}
          autoFocus
        />

        <label className="toggle-label">
          <input
            type="checkbox"
            checked={useBackend}
            onChange={handleBackendToggle}
          />
          <span>
            Use optional backend proxy (for CORS fallback / heuristics)
          </span>
        </label>

        {useBackend && (
          <input
            className="input"
            type="url"
            placeholder="http://localhost:8000"
            value={backendUrl}
            onChange={(e) => setBackendUrl(e.target.value)}
          />
        )}

        <button
          className="btn btn-primary"
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? "Validating…" : "Save API Key"}
        </button>

        {message && (
          <div className={`msg msg-${message.type}`}>{message.text}</div>
        )}

        <p className="footnote">
          Don't have a key?{" "}
          <a
            href="https://www.virustotal.com/gui/join-us"
            target="_blank"
            rel="noopener"
          >
            Get one free
          </a>
        </p>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="header">
        <div className="status-dot on" />
        <h1>ExTention</h1>
      </div>

      <p className="subtitle">
        No more tension — your API key is configured and active.
      </p>

      <div className="info-row">
        <span className="label">API Key</span>
        <span className="value">••••••••</span>
      </div>

      {useBackend && backendUrl && (
        <div className="info-row">
          <span className="label">Backend Proxy</span>
          <span className="value">{backendUrl}</span>
        </div>
      )}

      <div className="btn-group">
        <button className="btn btn-secondary" onClick={handleRemove}>
          Remove Key &amp; Reset
        </button>
      </div>

      <p className="footnote">
        URLs are scanned automatically on each page load — blocklist first, then
        VirusTotal.
      </p>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Popup />
  </StrictMode>,
);
