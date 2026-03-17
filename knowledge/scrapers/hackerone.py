"""
knowledge/scrapers/hackerone.py
Scrapes HackerOne public disclosed reports via their GraphQL API.
"""

import requests
import time

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0",
    "Content-Type": "application/json",
}

API_URL = "https://hackerone.com/graphql"

QUERY = """
query HacktivityPageQuery($cursor: String) {
  hacktivity_items(
    first: 25
    after: $cursor
    order_by: {field: popular, direction: DESC}
    where: {
      report: {
        disclosed_at: {_is_null: false}
        severity_rating: {_in: [high, critical]}
      }
    }
  ) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        ... on HacktivityItemUnion {
          report {
            title
            vulnerability_information
            severity_rating
            disclosed_at
            weakness { name }
            structured_scope { asset_identifier }
          }
        }
      }
    }
  }
}
"""


def scrape(max_pages: int = 5) -> list[dict]:
    print("[*] Scraping HackerOne public reports...")
    documents = []
    cursor = None

    for page in range(max_pages):
        try:
            resp = requests.post(
                API_URL,
                json={"query": QUERY, "variables": {"cursor": cursor}},
                headers=HEADERS,
                timeout=20,
            )
            if resp.status_code != 200:
                print(f"    H1 API returned {resp.status_code}, stopping")
                break

            data = resp.json()
            items = data.get("data", {}).get("hacktivity_items", {})
            edges = items.get("edges", [])

            for edge in edges:
                report = edge.get("node", {}).get("report")
                if not report or not report.get("title"):
                    continue

                title = report["title"]
                weakness = report.get("weakness", {}) or {}
                vuln_class = weakness.get("name", "Unknown")
                severity = report.get("severity_rating", "unknown")
                info = (report.get("vulnerability_information") or "")[:600]
                scope = report.get("structured_scope", {}) or {}
                asset = scope.get("asset_identifier", "")

                content = f"""Vuln class: {vuln_class}
Severity: {severity}
Asset: {asset}
Description: {info}
Source: HackerOne public disclosure"""

                documents.append({
                    "title": title,
                    "content": content,
                    "tags": [vuln_class.lower(), severity, "hackerone"],
                })

            page_info = items.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            time.sleep(1)

        except Exception as e:
            print(f"    H1 scraper error on page {page}: {e}")
            break

    print(f"[+] HackerOne: {len(documents)} reports scraped")
    return documents
