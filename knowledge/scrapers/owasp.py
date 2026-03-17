"""
knowledge/scrapers/owasp.py
Pulls OWASP Top 10 descriptions, testing guide content, and cheat sheets.
These are stable references that don't change often — scraped once and cached.
"""

import requests
from bs4 import BeautifulSoup
import time

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"}

OWASP_TOP10 = [
    {
        "id": "A01",
        "title": "Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "tags": ["access control", "idor", "privilege escalation", "owasp"],
    },
    {
        "id": "A02",
        "title": "Cryptographic Failures",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "tags": ["cryptography", "tls", "sensitive data", "owasp"],
    },
    {
        "id": "A03",
        "title": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
        "tags": ["injection", "sql injection", "xss", "command injection", "owasp"],
    },
    {
        "id": "A04",
        "title": "Insecure Design",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "tags": ["design", "threat modeling", "owasp"],
    },
    {
        "id": "A05",
        "title": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "tags": ["misconfiguration", "headers", "default credentials", "owasp"],
    },
    {
        "id": "A06",
        "title": "Vulnerable and Outdated Components",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "tags": ["cve", "outdated", "dependencies", "owasp"],
    },
    {
        "id": "A07",
        "title": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "tags": ["authentication", "session", "jwt", "oauth", "owasp"],
    },
    {
        "id": "A08",
        "title": "Software and Data Integrity Failures",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "tags": ["deserialization", "supply chain", "integrity", "owasp"],
    },
    {
        "id": "A09",
        "title": "Security Logging and Monitoring Failures",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "tags": ["logging", "monitoring", "detection", "owasp"],
    },
    {
        "id": "A10",
        "title": "Server-Side Request Forgery",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "tags": ["ssrf", "server-side request forgery", "owasp"],
    },
]

CHEAT_SHEETS = [
    {
        "title": "SQL Injection Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "tags": ["sql injection", "owasp", "cheatsheet"],
    },
    {
        "title": "XSS Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "tags": ["xss", "owasp", "cheatsheet"],
    },
    {
        "title": "Authentication Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "tags": ["authentication", "owasp", "cheatsheet"],
    },
    {
        "title": "JWT Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        "tags": ["jwt", "authentication", "owasp", "cheatsheet"],
    },
    {
        "title": "SSRF Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "tags": ["ssrf", "owasp", "cheatsheet"],
    },
    {
        "title": "File Upload Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "tags": ["file upload", "owasp", "cheatsheet"],
    },
]


def _extract_text(url: str, max_chars: int = 800) -> str:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return ""
        soup = BeautifulSoup(resp.text, "html.parser")
        main = soup.find("main") or soup.find("article") or soup.find("div", class_="col-md-9")
        if not main:
            main = soup.find("body")
        if not main:
            return ""
        paras = main.find_all(["p", "li"])
        return " ".join(p.get_text(strip=True) for p in paras)[:max_chars]
    except Exception:
        return ""


def scrape() -> list[dict]:
    print("[*] Scraping OWASP resources...")
    documents = []

    print("    Scraping OWASP Top 10...")
    for item in OWASP_TOP10:
        text = _extract_text(item["url"])
        if not text:
            text = f"OWASP Top 10 {item['id']}: {item['title']} — see {item['url']}"

        documents.append({
            "title": f"OWASP {item['id']}: {item['title']}",
            "content": f"""{text}
Reference: {item['url']}
Source: OWASP Top 10 2021""",
            "tags": item["tags"],
        })
        time.sleep(0.5)

    print("    Scraping OWASP Cheat Sheets...")
    for sheet in CHEAT_SHEETS:
        text = _extract_text(sheet["url"])
        if not text:
            text = f"See full cheat sheet at {sheet['url']}"

        documents.append({
            "title": sheet["title"],
            "content": f"""{text}
Reference: {sheet['url']}
Source: OWASP Cheat Sheet Series""",
            "tags": sheet["tags"],
        })
        time.sleep(0.5)

    print(f"[+] OWASP: {len(documents)} resources scraped")
    return documents
