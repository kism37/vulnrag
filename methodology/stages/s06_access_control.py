"""
methodology/stages/s06_access_control.py — IDOR & privilege escalation
"""
from methodology.context import TargetContext
from methodology.human_gate import request, ActionType, Action
from engine.llm import ask_with_rag


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 6 — Access Control (IDOR, Privilege Escalation)")
    print("="*60)

    guidance = ask_with_rag(
        query="What IDOR and access control vulnerabilities are most likely? Give me specific test cases.",
        context={"url": ctx.url, "tech_stack": ctx.tech_stack, "api_schemas": [s["path"] for s in ctx.api_schemas], "endpoints": ctx.endpoints[:10]}
    )
    print(f"\n{guidance}")

    print("\n[*] Manual access control steps:")
    steps = [
        ("IDOR test setup",        "Create two accounts A and B. With A's session, access B's resources by changing IDs"),
        ("Autorize scan",          "Install Burp Autorize, add B's cookie, browse app as A — Autorize flags bypasses"),
        ("Mass assignment",        'Try adding "role":"admin" or "isAdmin":true to POST/PUT request bodies'),
        ("Method switching",       "Try GET→POST→PUT→DELETE→PATCH on every endpoint"),
        ("Admin endpoint enum",    f"ffuf -u {ctx.url}/api/FUZZ -w ~/wordlists/api-endpoints.txt"),
        ("Header bypass",          'Add X-Original-URL: /admin or X-Forwarded-For: 127.0.0.1'),
    ]
    for name, tip in steps:
        print(f"\n  📋 {name}")
        print(f"     {tip}")

    ctx.stage_notes["access_control"] = guidance
    return ctx
