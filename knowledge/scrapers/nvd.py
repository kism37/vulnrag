"""
knowledge/scrapers/nvd.py
Pulls recent high/critical CVEs from NVD API v2.
Focuses on web application vulnerabilities.
"""

import requests
import time

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

WEB_KEYWORDS = [
    "cross-site scripting", "sql injection", "remote code execution",
    "path traversal", "server-side request forgery", "ssrf",
    "authentication bypass", "privilege escalation", "file upload",
    "open redirect", "xml external entity", "xxe", "prototype pollution",
    "deserialization", "command injection", "ldap injection",
    "insecure direct object", "broken access control",
]

CWE_WEB = {
    "CWE-79": "XSS", "CWE-89": "SQL Injection", "CWE-78": "Command Injection",
    "CWE-22": "Path Traversal", "CWE-918": "SSRF", "CWE-611": "XXE",
    "CWE-862": "Missing Auth", "CWE-863": "Incorrect Auth",
    "CWE-284": "Improper Access Control", "CWE-434": "Unrestricted Upload",
    "CWE-601": "Open Redirect", "CWE-502": "Deserialization",
    "CWE-94": "Code Injection", "CWE-1321": "Prototype Pollution",
}


def scrape(days_back: int = 30, max_results: int = 100) -> list[dict]:
    print(f"[*] Scraping NVD CVEs (last {days_back} days, high/critical)...")
    documents = []

    from datetime import datetime, timedelta
    end = datetime.utcnow()
    start = end - timedelta(days=days_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        "cvssV3Severity": "HIGH",
        "resultsPerPage": min(max_results, 100),
        "startIndex": 0,
    }

    try:
        resp = requests.get(NVD_API, params=params, headers=HEADERS, timeout=20)
        if resp.status_code == 403:
            print("    NVD rate limit hit — try again later or add API key")
            return []
        if resp.status_code != 200:
            print(f"    NVD returned {resp.status_code}")
            return []

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

            if not desc:
                continue

            desc_lower = desc.lower()
            is_web_related = any(kw in desc_lower for kw in WEB_KEYWORDS)

            weaknesses = cve.get("weaknesses", [])
            cwe_ids = []
            vuln_class = "Unknown"
            for w in weaknesses:
                for d in w.get("description", []):
                    cwe = d.get("value", "")
                    if cwe in CWE_WEB:
                        cwe_ids.append(cwe)
                        vuln_class = CWE_WEB[cwe]
                        is_web_related = True

            if not is_web_related:
                continue

            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
                metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) or {}
            )
            score = cvss_data.get("baseScore", "N/A")
            vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "HIGH")

            refs = cve.get("references", [])
            ref_urls = [r["url"] for r in refs[:3] if r.get("url")]

            published = cve.get("published", "")[:10]

            content = f"""CVE ID: {cve_id}
Vuln class: {vuln_class}
CWE: {', '.join(cwe_ids) if cwe_ids else 'N/A'}
CVSS Score: {score} ({severity})
CVSS Vector: {vector}
Published: {published}
Description: {desc[:500]}
References: {', '.join(ref_urls)}
Source: NVD"""

            tags = ["nvd", "cve", severity.lower()] + [CWE_WEB.get(c, c).lower() for c in cwe_ids]

            documents.append({
                "title": f"{cve_id}: {desc[:80]}",
                "content": content,
                "tags": tags,
            })

        # Also grab critical
        time.sleep(1)
        params["cvssV3Severity"] = "CRITICAL"
        resp2 = requests.get(NVD_API, params=params, headers=HEADERS, timeout=20)
        if resp2.status_code == 200:
            for item in resp2.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                if not desc:
                    continue
                desc_lower = desc.lower()
                if not any(kw in desc_lower for kw in WEB_KEYWORDS):
                    continue
                content = f"""CVE ID: {cve_id}
Severity: CRITICAL
Description: {desc[:500]}
Source: NVD"""
                documents.append({
                    "title": f"{cve_id}: {desc[:80]}",
                    "content": content,
                    "tags": ["nvd", "cve", "critical"],
                })

    except Exception as e:
        print(f"    NVD scraper error: {e}")

    print(f"[+] NVD: {len(documents)} CVEs scraped")
    return documents
