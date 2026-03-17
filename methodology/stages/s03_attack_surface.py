"""
methodology/stages/s03_attack_surface.py
Stage 3: Attack surface mapping.
Runs ffuf, checks API schemas, exposed files, S3 buckets.
"""
import subprocess
import requests
import os
from urllib.parse import urljoin
from methodology.context import TargetContext, Finding
from methodology.human_gate import request, api_probe, s3_check, ActionType, Action
from engine import recon as R
from engine.llm import ask_with_rag


def _run_ffuf(url: str, wordlist: str = None) -> list[dict]:
    """Run ffuf and return found paths."""
    # Try common wordlist locations
    candidates = [
        wordlist,
        os.path.expanduser("~/wordlists/raft-large-words.txt"),
        "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    wl = next((w for w in candidates if w and os.path.exists(w)), None)

    if not wl:
        print("  ⚠️  No wordlist found. Install seclists: sudo apt install seclists")
        return []

    print(f"  Using wordlist: {wl}")
    out_file = "/tmp/ragent_ffuf.json"
    try:
        result = subprocess.run(
            ["ffuf", "-u", f"{url}/FUZZ", "-w", wl,
             "-mc", "200,201,301,302,403,405",
             "-t", "50", "-timeout", "5",
             "-of", "json", "-o", out_file, "-s"],
            capture_output=True, text=True, timeout=90
        )
        if os.path.exists(out_file):
            import json
            with open(out_file) as f:
                data = json.load(f)
            found = data.get("results", [])
            return [{"path": r["input"]["FUZZ"], "status": r["status"], "size": r["length"]} for r in found]
    except FileNotFoundError:
        print("  ⚠️  ffuf not found. Install: sudo apt install ffuf")
    except subprocess.TimeoutExpired:
        print("  ⚠️  ffuf timed out")
    except Exception as e:
        print(f"  ffuf error: {e}")
    return []


def _run_gau(domain: str) -> list[str]:
    """Run gau to get all known URLs."""
    try:
        result = subprocess.run(
            ["gau", "--subs", domain],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return [u.strip() for u in result.stdout.strip().splitlines() if u.strip()]
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return []


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 3 — Attack Surface Mapping")
    print("="*60)

    # API schema checks
    action = api_probe(ctx.url, "/swagger.json")
    if request(action):
        print("\n[*] Checking for exposed API schemas...")
        schemas = R.check_api_schemas(ctx.url)
        ctx.api_schemas = schemas
        for s in schemas:
            print(f"  🚨 FOUND: {s['path']} ({s['status']}, {s['size']} bytes)")
            ctx.add_finding(Finding(
                stage="attack_surface", category="API", severity="high",
                title=f"API schema exposed: {s['path']}",
                detail=f"Full API schema at {ctx.url}{s['path']}",
                recommendation="Disable schema exposure in production or require authentication"
            ))
        if not schemas:
            print("  No exposed API schemas found")

    # GraphQL introspection
    gql_action = Action(
        name="graphql_introspection",
        description=f"Test GraphQL introspection at {ctx.url}/graphql",
        command=f'curl -s -X POST {ctx.url}/graphql -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name}}}}}}"}}\'',
        action_type=ActionType.ACTIVE,
        risk="One POST to /graphql",
    )
    if request(gql_action):
        if R.check_graphql_introspection(ctx.url):
            ctx.graphql_introspection = True
            print("  🚨 GraphQL introspection enabled")
            ctx.add_finding(Finding(
                stage="attack_surface", category="API", severity="high",
                title="GraphQL introspection enabled",
                detail="Full schema exposed — enumerate with graphql-voyager",
                recommendation="Disable introspection in production"
            ))

    # Directory fuzzing with ffuf
    ffuf_action = Action(
        name="ffuf_dirscan",
        description=f"Directory fuzzing on {ctx.url} with ffuf",
        command=f"ffuf -u {ctx.url}/FUZZ -w <wordlist> -mc 200,301,302,403",
        action_type=ActionType.ACTIVE,
        risk="Many HTTP requests — will appear in access logs, may trigger WAF",
    )
    if request(ffuf_action):
        print(f"\n[*] Running ffuf on {ctx.url}...")
        found = _run_ffuf(ctx.url)
        if found:
            print(f"  Found {len(found)} paths:")
            for item in found[:20]:
                icon = "🚨" if item["status"] in [200, 201] else "⚠️"
                print(f"  {icon} /{item['path']} — {item['status']} ({item['size']} bytes)")
                if item["status"] in [200, 201]:
                    ctx.endpoints.append(f"{ctx.url}/{item['path']}")
        else:
            print("  No paths found via ffuf")

    # gau URL discovery
    gau_action = Action(
        name="gau_urls",
        description=f"Fetch all known URLs for {ctx.domain} via gau",
        command=f"gau --subs {ctx.domain}",
        action_type=ActionType.ACTIVE,
        risk="Passive — queries public archives only",
    )
    if request(gau_action):
        print(f"\n[*] Running gau on {ctx.domain}...")
        urls = _run_gau(ctx.domain)
        if urls:
            print(f"  Found {len(urls)} URLs via gau")
            interesting = [u for u in urls if any(
                k in u.lower() for k in ["api", "admin", "token", "key", "secret", "upload", "graphql"]
            )]
            print(f"  Interesting: {len(interesting)}")
            for u in interesting[:10]:
                print(f"  📌 {u}")
                ctx.endpoints.append(u)
        else:
            print("  gau not found or returned no results. Install: go install github.com/lc/gau/v2/cmd/gau@latest")

    # Exposed files
    file_action = Action(
        name="exposed_files",
        description=f"Check for exposed config/credential files",
        command=f"curl -s {ctx.url}/.env",
        action_type=ActionType.ACTIVE,
        risk="Multiple HTTP requests — logged",
    )
    if request(file_action):
        print("\n[*] Checking for exposed sensitive files...")
        exposed = R.check_exposed_files(ctx.url)
        ctx.exposed_files = exposed
        for f in exposed:
            print(f"  🚨 {f['path']}: {f['snippet'][:60]}")
            ctx.add_finding(Finding(
                stage="attack_surface", category="Secret Exposure", severity="critical",
                title=f"Exposed file: {f['path']}",
                detail=f"Content: {f['snippet'][:100]}",
                recommendation="Remove file, rotate any exposed credentials"
            ))
        if not exposed:
            print("  No exposed sensitive files found")

    # S3 buckets
    s3_action = s3_check(ctx.domain)
    if request(s3_action):
        print("\n[*] Checking S3 buckets...")
        buckets = R.check_s3_buckets(ctx.domain)
        ctx.s3_buckets = buckets
        for b in buckets:
            icon = "🚨" if b["status"] == "public" else "🟡"
            print(f"  {icon} {b['bucket']}.s3.amazonaws.com — {b['status']}")
            if b["status"] == "public":
                # Actually try to list contents
                try:
                    r = requests.get(f"https://{b['bucket']}.s3.amazonaws.com", timeout=5)
                    preview = r.text[:300]
                    ctx.add_finding(Finding(
                        stage="attack_surface", category="Cloud", severity="critical",
                        title=f"Public S3 bucket: {b['bucket']}",
                        detail=f"Contents preview: {preview}",
                        recommendation="Set bucket ACL to private, audit contents for sensitive data"
                    ))
                    print(f"  Contents: {preview[:100]}")
                except Exception:
                    pass

    # AI analysis
    print("\n[*] AI attack surface analysis...")
    analysis = ask_with_rag(
        query="What does this attack surface tell us? What are the highest value targets?",
        context={
            "url": ctx.url,
            "tech_stack": ctx.tech_stack,
            "api_schemas": [s["path"] for s in ctx.api_schemas],
            "graphql_introspection": ctx.graphql_introspection,
            "exposed_files": [f["path"] for f in ctx.exposed_files],
            "s3_buckets": ctx.s3_buckets,
            "endpoints_found": len(ctx.endpoints),
            "wayback_interesting": ctx.wayback_urls[:5],
        }
    )
    print(f"\n{analysis}")
    ctx.stage_notes["attack_surface"] = analysis

    return ctx
