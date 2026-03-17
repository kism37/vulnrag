"""
knowledge/scrapers/blogs.py
Scrapes security research blogs: PortSwigger, ProjectDiscovery, and others.
"""

import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import time

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"}

SOURCES = [
    {
        "name": "portswigger",
        "rss": "https://portswigger.net/research/rss",
        "type": "rss",
    },
    {
        "name": "projectdiscovery",
        "rss": "https://blog.projectdiscovery.io/rss/",
        "type": "rss",
    },
    {
        "name": "assetnote",
        "rss": "https://blog.assetnote.io/feed.xml",
        "type": "rss",
    },
    {
        "name": "hacktricks",
        "url": "https://book.hacktricks.xyz/",
        "type": "static",
        "sections": [
            "https://book.hacktricks.xyz/pentesting-web/sql-injection",
            "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
            "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
            "https://book.hacktricks.xyz/pentesting-web/file-upload",
        ]
    },
]

SECURITY_KEYWORDS = [
    "vulnerability", "exploit", "bypass", "injection", "xss", "ssrf",
    "rce", "idor", "authentication", "authorization", "traversal",
    "disclosure", "misconfiguration", "pentest", "bug bounty", "cve",
]


def _scrape_rss(source: dict) -> list[dict]:
    documents = []
    try:
        resp = requests.get(source["rss"], headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return []

        root = ET.fromstring(resp.content)
        ns = {"atom": "http://www.w3.org/2005/Atom"}

        items = root.findall(".//item") or root.findall(".//atom:entry", ns)

        for item in items[:20]:
            title = (
                item.findtext("title") or
                item.findtext("atom:title", namespaces=ns) or ""
            ).strip()

            desc = (
                item.findtext("description") or
                item.findtext("summary") or
                item.findtext("atom:summary", namespaces=ns) or ""
            ).strip()

            link = (
                item.findtext("link") or
                item.findtext("atom:link", namespaces=ns) or
                (item.find("atom:link", ns).get("href") if item.find("atom:link", ns) is not None else "") or ""
            ).strip()

            pub_date = (
                item.findtext("pubDate") or
                item.findtext("published") or
                item.findtext("atom:published", namespaces=ns) or ""
            ).strip()

            if not title:
                continue

            desc_clean = BeautifulSoup(desc, "html.parser").get_text()[:500]

            title_lower = title.lower()
            is_security = any(kw in title_lower or kw in desc_clean.lower() for kw in SECURITY_KEYWORDS)
            if not is_security:
                continue

            tags = [source["name"]] + [kw for kw in SECURITY_KEYWORDS if kw in title_lower]

            content = f"""Published: {pub_date}
Summary: {desc_clean}
Link: {link}
Source: {source['name']}"""

            documents.append({
                "title": title,
                "content": content,
                "tags": tags,
            })

        time.sleep(0.5)

    except Exception as e:
        print(f"    {source['name']} RSS failed: {e}")

    return documents


def _scrape_static(source: dict) -> list[dict]:
    documents = []
    sections = source.get("sections", [])
    for url in sections:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.find("h1")
            title_text = title.get_text(strip=True) if title else url.split("/")[-1]

            # Get main content paragraphs
            content_div = soup.find("main") or soup.find("article") or soup.find("body")
            if not content_div:
                continue

            paragraphs = content_div.find_all(["p", "li", "code"])
            text = " ".join(p.get_text(strip=True) for p in paragraphs)[:800]

            documents.append({
                "title": title_text,
                "content": f"{text}\nSource: {source['name']}\nLink: {url}",
                "tags": [source["name"], "technique"] + [
                    kw for kw in SECURITY_KEYWORDS if kw in title_text.lower()
                ],
            })
            time.sleep(1)

        except Exception as e:
            print(f"    Static scrape failed for {url}: {e}")

    return documents


def scrape() -> list[dict]:
    print("[*] Scraping security blogs...")
    all_docs = []

    for source in SOURCES:
        print(f"    Scraping {source['name']}...")
        if source["type"] == "rss":
            docs = _scrape_rss(source)
        elif source["type"] == "static":
            docs = _scrape_static(source)
        else:
            docs = []

        print(f"    {source['name']}: {len(docs)} articles")
        all_docs.extend(docs)

    print(f"[+] Blogs: {len(all_docs)} articles scraped total")
    return all_docs
