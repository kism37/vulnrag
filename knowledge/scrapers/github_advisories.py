"""
knowledge/scrapers/github_advisories.py
Pulls web-related security advisories from GitHub Advisory Database.
Uses the public GraphQL API — no auth needed for public advisories.
"""

import requests
import time

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0",
    "Content-Type": "application/json",
}

GRAPHQL_URL = "https://api.github.com/graphql"

QUERY = """
query($cursor: String) {
  securityAdvisories(
    first: 25
    after: $cursor
    orderBy: {field: PUBLISHED_AT, direction: DESC}
    classifications: [GENERAL]
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      cwes(first: 5) { nodes { cweId name } }
      vulnerabilities(first: 3) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
      references { url }
    }
  }
}
"""

WEB_ECOSYSTEMS = {"NPM", "RUBYGEMS", "PIP", "MAVEN", "COMPOSER", "GO", "RUST"}
WEB_KEYWORDS = [
    "xss", "cross-site", "sql injection", "ssrf", "rce", "remote code",
    "path traversal", "authentication", "authorization", "injection",
    "prototype pollution", "deserialization", "open redirect",
]


def scrape(max_pages: int = 4) -> list[dict]:
    print("[*] Scraping GitHub Security Advisories...")
    documents = []
    cursor = None

    for page in range(max_pages):
        try:
            resp = requests.post(
                GRAPHQL_URL,
                json={"query": QUERY, "variables": {"cursor": cursor}},
                headers=HEADERS,
                timeout=20,
            )

            if resp.status_code == 401:
                print("    GitHub token needed for GraphQL — falling back to REST API")
                return _fallback_rest()

            if resp.status_code != 200:
                print(f"    GitHub API returned {resp.status_code}")
                break

            data = resp.json()
            advisories = data.get("data", {}).get("securityAdvisories", {})
            nodes = advisories.get("nodes", [])

            for node in nodes:
                severity = node.get("severity", "").upper()
                if severity not in ("HIGH", "CRITICAL"):
                    continue

                summary = node.get("summary", "").strip()
                desc = node.get("description", "").strip()
                ghsa_id = node.get("ghsaId", "")
                published = node.get("publishedAt", "")[:10]

                desc_lower = (summary + " " + desc).lower()
                is_web = any(kw in desc_lower for kw in WEB_KEYWORDS)

                vulns = node.get("vulnerabilities", {}).get("nodes", [])
                ecosystems = [
                    v.get("package", {}).get("ecosystem", "")
                    for v in vulns if v.get("package")
                ]
                is_web_ecosystem = any(e in WEB_ECOSYSTEMS for e in ecosystems)

                if not (is_web or is_web_ecosystem):
                    continue

                cwes = node.get("cwes", {}).get("nodes", [])
                cwe_text = ", ".join(f"{c['cweId']} ({c['name']})" for c in cwes) or "N/A"

                packages = []
                for v in vulns:
                    pkg = v.get("package", {})
                    name = pkg.get("name", "")
                    eco = pkg.get("ecosystem", "")
                    vrange = v.get("vulnerableVersionRange", "")
                    patch = (v.get("firstPatchedVersion") or {}).get("identifier", "no patch")
                    if name:
                        packages.append(f"{eco}/{name} {vrange} (fix: {patch})")

                refs = [r["url"] for r in node.get("references", [])[:3]]

                tags = ["github", "advisory", severity.lower()] + [
                    kw for kw in WEB_KEYWORDS if kw in desc_lower
                ]

                content = f"""GHSA ID: {ghsa_id}
Severity: {severity}
CWE: {cwe_text}
Published: {published}
Affected packages: {'; '.join(packages) or 'N/A'}
Description: {desc[:500]}
References: {', '.join(refs)}
Source: GitHub Security Advisories"""

                documents.append({
                    "title": f"{ghsa_id}: {summary[:80]}",
                    "content": content,
                    "tags": tags,
                })

            page_info = advisories.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            time.sleep(1)

        except Exception as e:
            print(f"    GitHub advisory scraper error on page {page}: {e}")
            break

    print(f"[+] GitHub advisories: {len(documents)} scraped")
    return documents


def _fallback_rest() -> list[dict]:
    """Fallback using GitHub REST API for advisories — no auth needed."""
    print("    Falling back to GitHub REST API...")
    documents = []
    try:
        resp = requests.get(
            "https://api.github.com/advisories?type=reviewed&severity=high&per_page=50",
            headers=HEADERS,
            timeout=20,
        )
        if resp.status_code != 200:
            return []

        for adv in resp.json():
            summary = adv.get("summary", "").strip()
            desc = (adv.get("description") or "")[:500]
            ghsa_id = adv.get("ghsa_id", "")
            severity = adv.get("severity", "high").upper()

            if not summary:
                continue

            desc_lower = (summary + " " + desc).lower()
            if not any(kw in desc_lower for kw in WEB_KEYWORDS):
                continue

            documents.append({
                "title": f"{ghsa_id}: {summary[:80]}",
                "content": f"Severity: {severity}\nDescription: {desc}\nSource: GitHub REST API",
                "tags": ["github", "advisory", severity.lower()],
            })

    except Exception as e:
        print(f"    REST fallback failed: {e}")

    print(f"    REST API got {len(documents)} advisories")
    return documents
