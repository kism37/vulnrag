"""
methodology/stages/s09_cloud.py — Cloud misconfiguration
"""
from methodology.context import TargetContext
from engine.llm import ask_with_rag


def run(ctx: TargetContext) -> TargetContext:
    print("\n" + "="*60)
    print("  STAGE 9 — Cloud Misconfiguration")
    print("="*60)

    guidance = ask_with_rag(
        query="What cloud misconfigurations are likely on this target? What should I check?",
        context={
            "url": ctx.url,
            "tech_stack": ctx.tech_stack,
            "js_secrets": [s["type"] for s in ctx.js_secrets],
            "exposed_files": [f["path"] for f in ctx.exposed_files],
            "s3_buckets": ctx.s3_buckets,
        }
    )
    print(f"\n{guidance}")

    if ctx.s3_buckets:
        public = [b for b in ctx.s3_buckets if b["status"] == "public"]
        if public:
            print(f"\n  🚨 Public S3 buckets found in stage 3:")
            for b in public:
                print(f"     aws s3 ls s3://{b['bucket']} --no-sign-request")

    print("\n[*] Cloud attack checklist:")
    tips = [
        ("AWS metadata via SSRF",  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("GCP metadata via SSRF",  "http://metadata.google.internal/computeMetadata/v1/ (need Metadata-Flavor: Google)"),
        ("Azure metadata via SSRF","http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01"),
        ("Spring Boot actuator",   f"curl {ctx.url}/actuator/env — dumps env vars with secrets"),
        ("Docker API exposed",     "curl http://target:2375/v1.41/containers/json"),
        ("Kubernetes dashboard",   f"Try {ctx.url}:8001, {ctx.url}:10250/pods"),
    ]
    for name, tip in tips:
        print(f"\n  📋 {name}")
        print(f"     {tip}")

    ctx.stage_notes["cloud"] = guidance
    return ctx
