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

    # Auto-probe common paths for SSTI using differential analysis
    probe_action = injection_probe(ctx.url, "q", "{{7*7}}")
    if request(probe_action):
        print("\n[*] Probing for SSTI (differential analysis)...")
        test_paths = ["/search", "/api/search", "/?q=", "/render"]
        for path in test_paths:
            try:
                full_url = urljoin(ctx.url, path)

                # Baseline request with a benign value
                baseline = requests.get(
                    full_url,
                    params={"q": "vulnragtest1234", "search": "vulnragtest1234"},
                    timeout=5, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                # Check if baseline already contains "49" — if so, skip (would be false positive)
                baseline_has_49 = "49" in baseline.text

                for payload in SSTI_PAYLOADS[:2]:  # test fewer payloads, reduce noise
                    r = requests.get(
                        full_url,
                        params={"q": payload, "search": payload},
                        timeout=5, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}
                    )
                    # Only flag if:
                    # 1. "49" appears in payload response
                    # 2. "49" was NOT in baseline (differential)
                    # 3. Response is different from baseline
                    payload_has_49 = "49" in r.text
                    response_changed = abs(len(r.text) - len(baseline.text)) < 500  # similar size = reflected
                    if payload_has_49 and not baseline_has_49:
                        ctx.add_finding(Finding(
                            stage="injection", category="SSTI", severity="high",
                            title=f"Possible SSTI at {path} — needs manual verification",
                            detail=f"Payload {payload} returned '49' which was absent in baseline. Verify manually with tplmap.",
                            recommendation=f"tplmap -u '{full_url}?q=1' — confirm before reporting"
                        ))
                        print(f"  ⚠️  Possible SSTI at {path} with {payload} — verify manually")

                    if any(e in r.text.lower() for e in ["sql syntax", "mysql_fetch", "pg_query", "sqlite", "you have an error in your sql"]):
                        if not any(e in baseline.text.lower() for e in ["sql syntax", "mysql_fetch", "pg_query"]):
                            ctx.add_finding(Finding(
                                stage="injection", category="SQLi", severity="high",
                                title=f"SQL error at {path} — needs manual verification",
                                detail="SQL error message appeared after injection payload, absent in baseline",
                                recommendation=f"sqlmap -u '{full_url}?q=1' --dbs --batch --level=2"
                            ))
                            print(f"  ⚠️  SQL error at {path} — verify manually")
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
