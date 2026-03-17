"""
methodology/stages/s04_auth.py — Authentication & session testing
"""
from methodology.context import TargetContext
from methodology.human_gate import request, ActionType, Action
from engine.llm import ask_with_rag


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 4 — Authentication & Session Testing")
    print("="*60)

    print("\n[*] AI-guided auth attack recommendations for this target...")
    guidance = ask_with_rag(
        query="What authentication vulnerabilities are most likely? Give specific test steps.",
        context={
            "url": ctx.url,
            "tech_stack": ctx.tech_stack,
            "missing_headers": ctx.missing_headers,
            "endpoints": ctx.endpoints[:10],
            "wayback_urls": [u for u in ctx.wayback_urls if any(k in u for k in ["login", "auth", "token", "oauth"])],
        }
    )
    print(f"\n{guidance}")

    print("\n[*] Manual auth test checklist:")
    checks = [
        ("JWT testing",        f"jwt_tool {ctx.url} -t header — test alg:none, confusion, weak secrets"),
        ("OAuth flow",         f"Intercept OAuth redirect in Burp, test redirect_uri manipulation"),
        ("Password reset",     f"Request reset, check token entropy, test host header injection"),
        ("Session fixation",   f"Set session cookie before login, check if it changes after auth"),
        ("Brute force",        f"ffuf -w passwords.txt -u {ctx.url}/login -d 'user=admin&pass=FUZZ'"),
        ("Default creds",      f"Try admin/admin, admin/password, root/root on login forms"),
    ]
    for name, tip in checks:
        action = Action(
            name=f"auth_{name.lower().replace(' ', '_')}",
            description=f"Test: {name}",
            command=tip,
            action_type=ActionType.INTRUSIVE,
        )
        approved = request(action)
        if approved:
            print(f"  ✅ Proceed with: {tip}")

    ctx.stage_notes["auth"] = guidance
    return ctx
