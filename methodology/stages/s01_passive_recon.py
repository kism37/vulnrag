"""
methodology/stages/s01_passive_recon.py
Stage 1: Passive recon and OSINT — no active traffic to target.
"""

import subprocess
import requests
from methodology.context import TargetContext, Finding
from methodology.human_gate import ActionType, Action, request
from engine.llm import ask_with_rag

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"}


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 1 — Passive Recon & OSINT")
    print("="*60)

    # WHOIS — passive
    print("\n[*] WHOIS lookup...")
    try:
        r = subprocess.run(["whois", ctx.domain], capture_output=True, text=True, timeout=15)
        for line in r.stdout.splitlines():
            if any(k in line.lower() for k in ["registrar:", "creation date:", "name server:"]):
                print(f"  {line.strip()}")
    except Exception as e:
        print(f"  WHOIS failed: {e}")

    # DNS records — passive
    print("\n[*] DNS records...")
    dns = {}
    for rtype in ["A", "MX", "TXT", "NS", "CNAME"]:
        try:
            r = subprocess.run(
                ["dig", "+short", rtype, ctx.domain],
                capture_output=True, text=True, timeout=10
            )
            if r.stdout.strip() and "[" not in r.stdout:
                dns[rtype] = r.stdout.strip()
                print(f"  {rtype}: {r.stdout.strip()[:100]}")
                if rtype == "TXT" and "v=spf1" in r.stdout:
                    ctx.add_finding(Finding(
                        stage="passive_recon", category="OSINT", severity="info",
                        title="SPF record found",
                        detail=r.stdout.strip()[:200],
                        recommendation="Enumerate third-party services referenced in SPF record"
                    ))
        except Exception:
            pass
    ctx.dns_records = dns

    # crt.sh — passive
    print("\n[*] Certificate transparency (crt.sh)...")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{ctx.domain}&output=json",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200:
            certs = r.json()
            found = set()
            for cert in certs[:100]:
                for d in cert.get("name_value", "").split("\n"):
                    d = d.strip().lstrip("*.")
                    if ctx.domain in d:
                        found.add(d)
            ctx.subdomains = list(set(ctx.subdomains) | found)
            print(f"  Found {len(found)} domains via cert transparency")
            for d in sorted(found)[:10]:
                print(f"  🔹 {d}")
    except Exception as e:
        print(f"  crt.sh failed: {e}")

    # Wayback Machine — passive
    print("\n[*] Wayback Machine historical URLs...")
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{ctx.domain}/*&output=json&fl=original&collapse=urlkey&limit=100",
            timeout=15
        )
        if r.status_code == 200:
            urls_raw = r.json()[1:]
            interesting = [
                u[0] for u in urls_raw
                if any(k in u[0].lower() for k in [
                    "api", "admin", "login", "auth", "token", "key",
                    "upload", "backup", "config", ".env", ".sql", "graphql"
                ])
            ]
            ctx.wayback_urls = interesting[:30]
            print(f"  {len(urls_raw)} archived URLs, {len(interesting)} interesting")
            for u in interesting[:8]:
                print(f"  📌 {u}")
    except Exception as e:
        print(f"  Wayback failed: {e}")

    # Google dorks — manual (no active request)
    print("\n[*] Google dorks to run manually:")
    dorks = [
        f'site:{ctx.domain} ext:php OR ext:asp OR ext:env OR ext:log',
        f'site:{ctx.domain} inurl:admin OR inurl:dashboard OR inurl:api',
        f'site:{ctx.domain} intitle:"index of"',
        f'"{ctx.domain}" password OR secret OR token site:pastebin.com OR site:github.com',
    ]
    for d in dorks:
        print(f"  🔎 {d}")

    # LLM analysis
    print("\n[*] AI analysis of passive recon findings...")
    analysis = ask_with_rag(
        query=f"Based on passive recon of {ctx.domain}, what are the most promising attack leads?",
        context={
            "domain": ctx.domain,
            "subdomains_found": len(ctx.subdomains),
            "wayback_interesting_urls": ctx.wayback_urls[:5],
            "dns_records": list(ctx.dns_records.keys()),
        }
    )
    print(f"\n{analysis}")
    ctx.stage_notes["passive_recon"] = analysis

    return ctx
