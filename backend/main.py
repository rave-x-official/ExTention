# ExTention - No More Tension.
# Copyright (C) 2026 [Your Name]
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import csv
import hashlib
import logging
from pathlib import Path
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("extention-backend")

log.info(
    "ExTention backend started. "
    "This server acts as a stateless proxy ONLY if CORS blocks direct calls from the extension. "
    "It logs NOTHING about URLs or API keys."
)

app = FastAPI(title="ExTention Backend")

DATA_DIR = Path(__file__).parent / "data"
CSV_PATH = DATA_DIR / "rickroll_domains.csv"

BLOCKLIST: dict[str, str] = {}

if CSV_PATH.exists():
    with open(CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip().lower()
            label = row.get("label", "Blocklisted").strip()
            if domain:
                BLOCKLIST[domain] = label
    log.info("Loaded %d blocklist entries from %s", len(BLOCKLIST), CSV_PATH.name)
else:
    log.warning("CSV not found at %s – running without local blocklist", CSV_PATH)


class CheckRequest(BaseModel):
    url: str
    api_key: str


class CheckResponse(BaseModel):
    source: str
    malicious: bool
    label: Optional[str] = None
    vt_stats: Optional[dict] = None
    heuristics: Optional[dict] = None


def get_domain(url: str) -> str:
    domain = url.lower().strip()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    domain = domain.split("@")[-1]
    domain = domain.split(":")[0]
    return domain.removeprefix("www.")


def is_suspicious_tld(domain: str) -> Optional[str]:
    suspicious = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".date"}
    for tld in suspicious:
        if domain.endswith(tld):
            return f"Suspicious TLD: {tld}"
    return None


def check_heuristics(domain: str) -> dict:
    result: dict = {"flags": [], "score": 0}

    tld_flag = is_suspicious_tld(domain)
    if tld_flag:
        result["flags"].append(tld_flag)
        result["score"] += 25

    if len(domain) > 50:
        result["flags"].append("Unusually long domain name")
        result["score"] += 15

    dash_count = domain.count("-")
    if dash_count > 3:
        result["flags"].append(f"Excessive hyphens ({dash_count})")
        result["score"] += 10

    digit_count = sum(c.isdigit() for c in domain.split(".")[0])
    if digit_count > 5:
        result["flags"].append(f"Many digits in subdomain ({digit_count})")
        result["score"] += 10

    result["malicious"] = result["score"] >= 30
    return result


def call_virustotal(url: str, api_key: str) -> Optional[dict]:
    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )
    except requests.RequestException as e:
        log.warning("VT API call failed (not logging details)")
        return None

    if resp.status_code == 404:
        return {"found": False}

    if resp.status_code != 200:
        log.warning("VT API returned %s (not logging details)", resp.status_code)
        if resp.status_code == 429:
            return {"error": "rate_limited"}
        return None

    data = resp.json()
    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    if not stats:
        return {"found": False}

    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


@app.post("/check", response_model=CheckResponse)
def check_url(request: CheckRequest):
    url = request.url
    api_key = request.api_key

    if not url or not api_key:
        raise HTTPException(status_code=400, detail="url and api_key are required")

    domain = get_domain(url)

    # 1. Local blocklist check (no secrets logged)
    if domain in BLOCKLIST:
        log.info("Blocklist hit for domain (not logging domain)")
        return CheckResponse(
            source="blocklist",
            malicious=True,
            label=BLOCKLIST[domain],
        )

    # 2. Heuristics check (domain scoring only — no data stored)
    heuristics = check_heuristics(domain)
    if heuristics["malicious"]:
        log.info("Heuristics flagged domain (not logging domain)")
        return CheckResponse(
            source="heuristics",
            malicious=True,
            label="; ".join(heuristics["flags"]),
            heuristics=heuristics,
        )

    # 3. VirusTotal proxy — forwards your key + URL, stores nothing
    vt_result = call_virustotal(url, api_key)

    if vt_result is None:
        return CheckResponse(
            source="error",
            malicious=False,
            label="VirusTotal check failed – try again later",
        )

    if vt_result.get("error") == "rate_limited":
        return CheckResponse(
            source="error",
            malicious=False,
            label="VirusTotal rate limit reached",
        )

    if not vt_result.get("found"):
        return CheckResponse(
            source="virustotal",
            malicious=False,
            label="No analysis found for this URL",
            heuristics=heuristics,
        )

    malicious_count = vt_result.get("malicious", 0)
    suspicious_count = vt_result.get("suspicious", 0)
    is_malicious = malicious_count > 0 or suspicious_count > 2

    return CheckResponse(
        source="virustotal",
        malicious=is_malicious,
        label=f"{malicious_count} malicious, {suspicious_count} suspicious"
        if is_malicious
        else "Clean",
        vt_stats=vt_result,
        heuristics=heuristics,
    )


@app.get("/health")
def health():
    return {"status": "ok", "blocklist_size": len(BLOCKLIST)}
