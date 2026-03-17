"""
methodology/stages/s03_attack_surface.py
Stage 3: Attack surface mapping — API schemas, exposed files, S3 buckets.
"""
import requests
from urllib.parse import urljoin
from methodology.context import TargetContext, Finding
from methodology.human_gate import request, api_probe, s3_check, ActionType, Action
from engine import recon as R
from engine.llm import ask_with_rag


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
                recommendation="Disable API schema exposure in production or add authentication"
            ))
        if not schemas:
            print("  No exposed API schemas found")

    # GraphQL introspection
    gql_action = Action(
        name="graphql_introspection",
        description=f"Test GraphQL introspection at {ctx.url}/graphql",
        command=f'curl -s -X POST {ctx.url}/graphql -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name}}}}}}"}}\' ',
        action_type=ActionType.ACTIVE,
        risk="One POST request to /graphql — may be logged",
    )
    if request(gql_action):
        if R.check_graphql_introspection(ctx.url):
            ctx.graphql_introspection = True
            print("  🚨 GraphQL introspection enabled")
            ctx.add_finding(Finding(
                stage="attack_surface", category="API", severity="high",
                title="GraphQL introspection enabled",
                detail="Full schema exposed — all types, queries and mutations enumerable",
                recommendation="Disable introspection in production. Use graphql-voyager to map schema first."
            ))

    # Exposed files
    file_action = Action(
        name="exposed_files",
        description=f"Check for exposed config/credential files on {ctx.url}",
        command=f"curl -s {ctx.url}/.env",
        action_type=ActionType.ACTIVE,
        risk="Multiple HTTP requests — will appear in access logs",
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
                detail=f"Content preview: {f['snippet'][:100]}",
                recommendation="Remove file from public access immediately, rotate any exposed credentials"
            ))

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
                ctx.add_finding(Finding(
                    stage="attack_surface", category="Cloud", severity="critical",
                    title=f"Public S3 bucket: {b['bucket']}",
                    detail=f"https://{b['bucket']}.s3.amazonaws.com is publicly readable",
                    recommendation="Set bucket ACL to private, audit contents for sensitive data"
                ))

    # Manual guidance
    print("\n[*] Manual steps for attack surface mapping:")
    print(f"  ffuf -w ~/wordlists/raft-large-words.txt -u {ctx.url}/FUZZ -mc 200,301,302,403")
    print(f"  gau {ctx.domain} | grep '\\.js' | sort -u | xargs -I% python3 linkfinder.py -i %")
    print(f"  arjun -u {ctx.url}/api/endpoint --stable")

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
            "wayback_interesting": ctx.wayback_urls[:5],
        }
    )
    print(f"\n{analysis}")
    ctx.stage_notes["attack_surface"] = analysis

    return ctx
