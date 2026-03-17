"""
methodology/stages/s05_injection.py — Injection testing
"""
import requests
from urllib.parse import urljoin
from methodology.context import TargetContext, Finding
from methodology.human_gate import request, injection_probe, ActionType, Action
from engine import recon as R
from engine.llm import ask_with_rag, decide


SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "*{7*7}", "<%=7*7%>"]
SQLI_PAYLOADS = ["'", "\"", "1' OR '1'='1", "1 AND SLEEP(3)--"]


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 5 — Injection Testing")
    print("="*60)

    # LLM decides which injection types to prioritize
    decision = decide(
        situation=f"About to test injections on {ctx.url}",
        options=["SQLi (database backend likely)", "XSS (input fields found)", "SSTI (template engine detected)", "SSRF (webhook/URL params found)", "XXE (XML endpoints found)"],
        context={"tech_stack": ctx.tech_stack, "endpoints": ctx.endpoints[:5], "open_ports": [p["port"] for p in ctx.open_ports]}
    )
    print(f"\n[*] AI injection priority decision:\n{decision}")

    # Auto-probe common paths for SSTI
    probe_action = injection_probe(ctx.url, "q", "{{7*7}}")
    if request(probe_action):
        print("\n[*] Probing for SSTI...")
        test_paths = ["/search", "/api/search", "/?q=", "/render"]
        for path in test_paths:
            try:
                for payload in SSTI_PAYLOADS:
                    r = requests.get(
                        urljoin(ctx.url, path),
                        params={"q": payload, "search": payload, "name": payload},
                        timeout=5, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}
                    )
                    if "49" in r.text:
                        ctx.add_finding(Finding(
                            stage="injection", category="SSTI", severity="critical",
                            title=f"SSTI confirmed at {path}",
                            detail=f"Payload {payload} returned 49 in response",
                            recommendation="Test for RCE: tplmap -u '" + urljoin(ctx.url, path) + "'"
                        ))
                        print(f"  🚨 SSTI at {path} with {payload}")
                    if any(e in r.text.lower() for e in ["sql syntax", "mysql_fetch", "pg_query", "sqlite"]):
                        ctx.add_finding(Finding(
                            stage="injection", category="SQLi", severity="high",
                            title=f"SQL error at {path}",
                            detail=f"SQL error message in response",
                            recommendation=f"sqlmap -u '{urljoin(ctx.url, path)}?q=1' --dbs --batch"
                        ))
                        print(f"  🚨 SQL error at {path}")
            except Exception:
                pass

    # Manual guidance
    print("\n[*] Manual injection test commands:")
    print(f"  SQLi:  sqlmap -u '{ctx.url}/search?q=1' --dbs --batch --risk=2")
    print(f"  XSS:   dalfox url '{ctx.url}/search?q=FUZZ'")
    print(f"  SSRF:  look for url=, webhook=, callback=, redirect= params")
    print(f"  SSTI:  tplmap -u '{ctx.url}' --os-shell")
    print(f"  XXE:   check file uploads (SVG, DOCX, XLSX), SOAP endpoints")

    guidance = ask_with_rag(
        query="What injection attacks should I prioritize and what are the exact payloads for this target?",
        context={"tech_stack": ctx.tech_stack, "url": ctx.url, "endpoints": ctx.endpoints[:8]}
    )
    print(f"\n{guidance}")
    ctx.stage_notes["injection"] = guidance
    return ctx
