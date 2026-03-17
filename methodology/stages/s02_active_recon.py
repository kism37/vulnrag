"""
methodology/stages/s02_active_recon.py
Stage 2: Active recon — fingerprinting, subdomain enum, port scanning.
Subdomains are followed through — each interesting one gets its own recon pass.
"""

import requests
import subprocess
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from methodology.context import TargetContext, Finding
from methodology.human_gate import request, subdomain_enum, port_scan, js_fetch, ActionType, Action
from engine import recon as R
from engine.llm import ask_with_rag

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ragent/1.0"}

INTERESTING_SUBDOMAIN_KEYWORDS = [
    "api", "admin", "portal", "dev", "staging", "test", "beta",
    "app", "dashboard", "internal", "staff", "login", "auth",
    "registry", "pay", "billing", "mail", "vpn", "remote",
]


def _is_interesting_subdomain(sub: str) -> bool:
    return any(k in sub.lower() for k in INTERESTING_SUBDOMAIN_KEYWORDS)


def _quick_recon_subdomain(sub: str, ctx: TargetContext):
    """Run quick recon on a single subdomain."""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, verify=False)
            print(f"\n  🔹 {sub} — {r.status_code}")

            headers = {k.lower(): v for k, v in r.headers.items()}

            for h in ["server", "x-powered-by", "x-generator"]:
                if h in headers:
                    print(f"     🖥️  {h}: {headers[h]}")
                    if headers[h] not in ctx.tech_stack:
                        ctx.tech_stack.append(f"{sub} — {h}: {headers[h]}")

            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                print(f"     🚨 CORS wildcard on {sub}")
                ctx.add_finding(Finding(
                    stage="active_recon", category="Misconfiguration", severity="high",
                    title=f"CORS wildcard on subdomain: {sub}",
                    detail=f"Access-Control-Allow-Origin: * on {url}",
                    recommendation="Restrict CORS to specific trusted origins"
                ))

            soup = BeautifulSoup(r.text, "html.parser")
            js_files = R.find_js_files(url, soup)
            if js_files:
                js_data = R.analyze_js(js_files[:5])
                for secret in js_data.get("secrets", []):
                    print(f"     🚨 Secret in JS: {secret['type']} = {secret['value'][:50]}")
                    ctx.add_finding(Finding(
                        stage="active_recon", category="Secret Exposure", severity="high",
                        title=f"Secret in JS on {sub}: {secret['type']}",
                        detail=f"{secret['value'][:80]}",
                        recommendation="Rotate credential immediately"
                    ))
                for lib in js_data.get("vuln_libs", []):
                    print(f"     ⚠️  Vulnerable lib: {lib['lib']} {lib['version']} — {lib['cve']}")

            if r.status_code == 403:
                print(f"     ⚠️  403 — try auth bypass headers")
            elif r.status_code == 401:
                print(f"     ⚠️  401 — test default creds")

            break
        except Exception:
            continue


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 2 — Active Recon & Fingerprinting")
    print("="*60)

    action = Action(
        name="fetch_target",
        description=f"Fetch {ctx.url} to analyze headers and page content",
        command=f"curl -I {ctx.url}",
        action_type=ActionType.ACTIVE,
        risk="One HTTP request to target",
    )
    if request(action):
        print(f"\n[*] Fetching {ctx.url}...")
        resp = R.fetch(ctx.url)
        if resp:
            print(f"  Status: {resp.status_code}")
            header_data = R.analyze_headers(resp)

            ctx.tech_stack = header_data["tech_fingerprints"]
            ctx.missing_headers = header_data["missing_security_headers"]
            ctx.cors_issues = header_data["cors_issues"]
            ctx.response_headers = header_data["raw"]

            for tech in ctx.tech_stack:
                print(f"  🖥️  {tech}")

            if ctx.missing_headers:
                print(f"  ⚠️  Missing headers: {', '.join(ctx.missing_headers)}")
                ctx.add_finding(Finding(
                    stage="active_recon", category="Misconfiguration", severity="medium",
                    title="Missing security headers",
                    detail=f"Absent: {', '.join(ctx.missing_headers)}",
                    recommendation="Add missing security headers to all responses"
                ))

            for issue in ctx.cors_issues:
                print(f"  🚨 {issue}")
                if "wildcard" in issue.lower():
                    ctx.add_finding(Finding(
                        stage="active_recon", category="Misconfiguration", severity="high",
                        title="CORS wildcard misconfiguration",
                        detail=issue,
                        recommendation="Restrict Access-Control-Allow-Origin to specific origins"
                    ))

            soup = BeautifulSoup(resp.text, "html.parser")
            js_files = R.find_js_files(ctx.url, soup)
            print(f"\n[*] Found {len(js_files)} JS files")

            if js_files:
                js_action = js_fetch(ctx.url, fn=None)
                if request(js_action):
                    print("[*] Analyzing JS files...")
                    js_data = R.analyze_js(js_files)
                    ctx.js_secrets = js_data["secrets"]
                    ctx.vuln_libs = js_data["vuln_libs"]

                    for secret in ctx.js_secrets:
                        print(f"  🚨 {secret['type']} in {secret['file']}: {secret['value'][:60]}")
                        ctx.add_finding(Finding(
                            stage="active_recon", category="Secret Exposure", severity="high",
                            title=f"Potential secret in JS: {secret['type']}",
                            detail=f"Found in {secret['file']}: {secret['value'][:80]}",
                            recommendation="Rotate the exposed credential immediately"
                        ))
                    for lib in ctx.vuln_libs:
                        print(f"  🚨 {lib['lib']} {lib['version']} — {lib['cve']}: {lib['desc']}")
                        ctx.add_finding(Finding(
                            stage="active_recon", category="Vulnerable Component", severity="high",
                            title=f"Vulnerable library: {lib['lib']} {lib['version']}",
                            detail=f"{lib['cve']}: {lib['desc']}",
                            recommendation=f"Upgrade {lib['lib']} to latest version"
                        ))

    # Subdomain enum + follow-through
    sub_action = subdomain_enum(ctx.domain)
    if request(sub_action):
        print(f"\n[*] Running subfinder on {ctx.domain}...")
        subs = R.enumerate_subdomains(ctx.domain)
        ctx.subdomains = list(set(ctx.subdomains + subs))
        print(f"  Found {len(subs)} subdomains")

        interesting = [s for s in subs if _is_interesting_subdomain(s)]
        boring = [s for s in subs if not _is_interesting_subdomain(s)]
        print(f"  Interesting: {len(interesting)} | Other: {len(boring)}")

        if interesting:
            print(f"\n[*] Following through on {min(len(interesting), 10)} interesting subdomains...")
            for sub in interesting[:10]:
                _quick_recon_subdomain(sub, ctx)

    # Port scan
    scan_action = port_scan(ctx.domain, fn=lambda: R.scan_ports(ctx.domain))
    if request(scan_action):
        print(f"\n[*] Port scanning {ctx.domain}...")
        ports = R.scan_ports(ctx.domain)
        ctx.open_ports = ports
        for p in ports:
            print(f"  🟢 {p['port']}/{p['proto']} {p['service']} {p['version']}")
            if p["service"] in ["mysql", "postgresql", "mongodb", "redis", "elasticsearch"]:
                ctx.add_finding(Finding(
                    stage="active_recon", category="Network", severity="high",
                    title=f"Database exposed: {p['service']} on port {p['port']}",
                    detail=f"{p['service']} {p['version']} directly accessible",
                    recommendation="Restrict database access to internal network only"
                ))
            if p["port"] == "21":
                print(f"  [*] Testing FTP anonymous login...")
                try:
                    import ftplib
                    ftp = ftplib.FTP()
                    ftp.connect(ctx.domain, 21, timeout=5)
                    ftp.login("anonymous", "anonymous@test.com")
                    files = ftp.nlst()
                    ftp.quit()
                    ctx.add_finding(Finding(
                        stage="active_recon", category="Network", severity="critical",
                        title="FTP anonymous login enabled",
                        detail=f"Files visible: {', '.join(files[:5])}",
                        recommendation="Disable anonymous FTP login immediately"
                    ))
                    print(f"  🚨 FTP anonymous login works! Files: {files[:5]}")
                except Exception as e:
                    print(f"  FTP anonymous login: {e}")

    # AI analysis
    print("\n[*] AI analysis of active recon...")
    analysis = ask_with_rag(
        query="What attack paths does this recon reveal? What should I prioritize?",
        context={
            "url": ctx.url,
            "tech_stack": ctx.tech_stack,
            "open_ports": [f"{p['port']}/{p['service']}" for p in ctx.open_ports],
            "missing_headers": ctx.missing_headers,
            "cors_issues": ctx.cors_issues,
            "js_secrets_found": len(ctx.js_secrets),
            "vuln_libs": [f"{l['lib']} {l['version']}" for l in ctx.vuln_libs],
            "interesting_subdomains": [s for s in ctx.subdomains if _is_interesting_subdomain(s)][:5],
        }
    )
    print(f"\n{analysis}")
    ctx.stage_notes["active_recon"] = analysis

    return ctx
