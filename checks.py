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


def fetch_page(url: str) -> dict:
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        redirect_chain = [r.url for r in resp.history] + [resp.url]
        return {
            "url": url,
            "reachable": True,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirect_chain": redirect_chain,
            "redirected": len(resp.history) > 0,
            "content_snippet": resp.text[:3000],
            "content_length": len(resp.text),
        }
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
