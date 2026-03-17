"""
methodology/stages/s02_active_recon.py
Stage 2: Active recon — fingerprinting, subdomain enum, port scanning.
All active actions go through the human gate.
"""

import requests
from urllib.parse import urlparse
from methodology.context import TargetContext, Finding
from methodology.human_gate import request, subdomain_enum, port_scan, js_fetch, ActionType, Action
from engine import recon as R
from engine.llm import ask_with_rag

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"}


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 2 — Active Recon & Fingerprinting")
    print("="*60)

    # Header analysis — single request, ask permission
    action = Action(
        name="fetch_target",
        description=f"Fetch {ctx.url} to analyze headers and page content",
        command=f"curl -I {ctx.url}",
        action_type=ActionType.ACTIVE,
        risk="One HTTP request to target — will appear in access logs",
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
                    title=f"Missing security headers: {', '.join(ctx.missing_headers[:3])}",
                    detail=f"Headers absent: {', '.join(ctx.missing_headers)}",
                    recommendation="Add missing security headers to all responses"
                ))

            for issue in ctx.cors_issues:
                print(f"  🚨 {issue}")
                if "wildcard" in issue.lower():
                    ctx.add_finding(Finding(
                        stage="active_recon", category="Misconfiguration", severity="high",
                        title="CORS wildcard misconfiguration",
                        detail=issue,
                        recommendation="Restrict Access-Control-Allow-Origin to specific trusted origins"
                    ))

            # JS analysis
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            js_files = R.find_js_files(ctx.url, soup)
            print(f"\n[*] Found {len(js_files)} JS files")

            if js_files:
                js_action = js_fetch(ctx.url, fn=None)
                if request(js_action):
                    print("[*] Analyzing JS files for secrets and vulnerable libraries...")
                    js_data = R.analyze_js(js_files)
                    ctx.js_secrets = js_data["secrets"]
                    ctx.vuln_libs = js_data["vuln_libs"]

                    for secret in ctx.js_secrets:
                        print(f"  🚨 {secret['type']} in {secret['file']}: {secret['value'][:60]}")
                        ctx.add_finding(Finding(
                            stage="active_recon", category="Secret Exposure", severity="high",
                            title=f"Potential secret in JS: {secret['type']}",
                            detail=f"Found in {secret['file']}: {secret['value'][:80]}",
                            recommendation="Rotate the exposed credential immediately, move secrets server-side"
                        ))

                    for lib in ctx.vuln_libs:
                        print(f"  🚨 {lib['lib']} {lib['version']} — {lib['cve']}: {lib['desc']}")
                        ctx.add_finding(Finding(
                            stage="active_recon", category="Vulnerable Component", severity="high",
                            title=f"Vulnerable library: {lib['lib']} {lib['version']}",
                            detail=f"{lib['cve']}: {lib['desc']}",
                            recommendation=f"Upgrade {lib['lib']} to latest version"
                        ))

    # Subdomain enumeration
    sub_action = subdomain_enum(ctx.domain, fn=lambda: R.enumerate_subdomains(ctx.domain))
    approved, result = False, None
    approved = request(sub_action)
    if approved:
        print(f"\n[*] Running subfinder on {ctx.domain}...")
        subs = R.enumerate_subdomains(ctx.domain)
        ctx.subdomains = list(set(ctx.subdomains + subs))
        print(f"  Found {len(subs)} subdomains via subfinder")
        for s in subs[:15]:
            print(f"  🔹 {s}")

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
                ctx.add_finding(Finding(
                    stage="active_recon", category="Network", severity="medium",
                    title="FTP exposed on port 21",
                    detail="FTP is unencrypted — check for anonymous login",
                    recommendation="Disable FTP, use SFTP instead. Test: ftp anonymous@target"
                ))

    # LLM analysis with full recon context
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
            "subdomains": ctx.subdomains[:5],
        }
    )
    print(f"\n{analysis}")
    ctx.stage_notes["active_recon"] = analysis

    return ctx
