"""
methodology/stages/s07_api_abuse.py — API abuse testing
"""
from methodology.context import TargetContext
from engine.llm import ask_with_rag


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 7 — API Abuse")
    print("="*60)

    guidance = ask_with_rag(
        query="What API vulnerabilities should I test? Give specific requests and tools.",
        context={
            "url": ctx.url,
            "tech_stack": ctx.tech_stack,
            "api_schemas": [s["path"] for s in ctx.api_schemas],
            "graphql": ctx.graphql_introspection,
            "endpoints": ctx.endpoints[:10],
        }
    )
    print(f"\n{guidance}")

    print("\n[*] API abuse checklist:")
    tips = [
        "Test all HTTP methods on every endpoint — DELETE/PUT may be less protected",
        "Mass assignment: send extra fields like role, isAdmin, price in request body",
        "Test API versioning: /api/v1/ may have weaker auth than /api/v2/",
        "GraphQL: test query depth, batching, mutation abuse",
        f"Rate limiting: ffuf -u {ctx.url}/api/login -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt",
        "Check for BOPLA: can you read/write fields you shouldn't own?",
    ]
    for tip in tips:
        print(f"  → {tip}")

    ctx.stage_notes["api_abuse"] = guidance
    return ctx
