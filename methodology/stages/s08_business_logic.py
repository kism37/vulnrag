"""
methodology/stages/s08_business_logic.py — Business logic flaws
"""
from methodology.context import TargetContext
from engine.llm import ask_with_rag


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 8 — Business Logic Flaws")
    print("="*60)

    guidance = ask_with_rag(
        query="What business logic vulnerabilities are most likely on this target? Give 3 specific scenarios.",
        context={"url": ctx.url, "tech_stack": ctx.tech_stack, "endpoints": ctx.endpoints[:10]}
    )
    print(f"\n{guidance}")

    print("\n[*] Business logic test areas:")
    tips = [
        ("Workflow abuse",    "Map multi-step flows (checkout, signup, KYC). Skip steps, repeat steps, go backwards."),
        ("Price tampering",   "Intercept checkout POST, change price/quantity to 0 or negative."),
        ("Race conditions",   "Use Burp Turbo Intruder single-packet attack on coupon codes, credits, votes."),
        ("File upload",       "Upload .php disguised as .jpg, double extension shell.php.jpg, SVG XSS, ZIP slip."),
        ("Coupon abuse",      "Apply same coupon twice via race condition or account manipulation."),
        ("Logic bypass",      "Complete verification step without actually verifying (e.g. email confirmation)."),
    ]
    for name, tip in tips:
        print(f"\n  📋 {name}")
        print(f"     {tip}")

    ctx.stage_notes["business_logic"] = guidance
    return ctx
