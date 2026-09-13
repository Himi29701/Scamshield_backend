"""
The 'live investigation' layer: real network calls against a candidate
domain/URL. Each function fails soft (returns an 'error' field) rather
than raising, so one dead check never kills the whole pipeline.
"""
import ssl
import socket
import datetime
import requests
import whois

REQUEST_TIMEOUT = 6
USER_AGENT = "ScamShield-Investigator/1.0 (+security-research)"


def check_domain_age(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return {"domain": domain, "found": False}
        if isinstance(created, str):
            created = datetime.datetime.fromisoformat(created)
        age_days = (datetime.datetime.now() - created).days
        return {
            "domain": domain,
            "found": True,
            "created": created.isoformat(),
            "age_days": age_days,
            "flag_new_domain": age_days < 90,
            "registrar": getattr(w, "registrar", None),
        }
    except Exception as e:
        return {"domain": domain, "found": False, "error": str(e)}


def check_ssl(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "domain": domain,
            "has_valid_cert": True,
            "issuer": issuer.get("organizationName", "unknown"),
            "expires": not_after.isoformat(),
        }
    except Exception as e:
        return {"domain": domain, "has_valid_cert": False, "error": str(e)}


import time
import os

ANAKIN_BASE = "https://api.anakin.io/v1"
ANAKIN_API_KEY = os.environ.get("ANAKIN_API_KEY")

def fetch_page(url: str) -> dict:
    try:
        headers = {"Content-Type": "application/json"}
        if ANAKIN_API_KEY:
            headers["X-API-Key"] = ANAKIN_API_KEY

        submit = requests.post(
            f"{ANAKIN_BASE}/url-scraper",
            headers=headers,
            json={"url": url, "country": "us", "formats": ["markdown", "html", "cleanedHtml"]},
            timeout=REQUEST_TIMEOUT,
        )
        job_id = submit.json().get("jobId")
        if not job_id:
            return {"url": url, "reachable": False, "error": f"Anakin did not return a jobId: {submit.text[:200]}"}

        for _ in range(30):
            status_resp = requests.get(f"{ANAKIN_BASE}/url-scraper/{job_id}", headers=headers, timeout=REQUEST_TIMEOUT)
            data = status_resp.json()
            if data.get("status") == "completed":
                result = data.get("result", {})
                content = result.get("markdown") or result.get("html") or ""
                return {
                    "url": url,
                    "reachable": True,
                    "status_code": 200,
                    "final_url": result.get("url", url),
                    "redirect_chain": [url],
                    "redirected": result.get("url", url) != url,
                    "content_snippet": content[:3000],
                    "content_length": len(content),
                    "scraped_via": "anakin.io",
                }
            if data.get("status") == "failed":
                return {"url": url, "reachable": False, "error": data.get("error", "Anakin job failed")}
            time.sleep(2)

        return {"url": url, "reachable": False, "error": "Anakin job timed out"}
    except Exception as e:
        return {"url": url, "reachable": False, "error": str(e)}

def investigate_domain(domain: str, url: str | None = None) -> dict:
    result = {
        "domain": domain,
        "whois": check_domain_age(domain),
        "ssl": check_ssl(domain),
    }
    if url:
        result["page"] = fetch_page(url)
    return result
