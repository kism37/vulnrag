"""
methodology/orchestrator.py
Runs all 10 stages in sequence, passing TargetContext between them.
Each stage reads what previous stages found and adds its own.
"""

import time
from urllib.parse import urlparse
from methodology.context import TargetContext
from methodology.stages import (
    s01_passive_recon,
    s02_active_recon,
    s03_attack_surface,
    s04_auth,
    s05_injection,
    s06_access_control,
    s07_api_abuse,
    s08_business_logic,
    s09_cloud,
    s10_report,
)

STAGES = [
    ("1",  "Passive Recon",     s01_passive_recon),
    ("2",  "Active Recon",      s02_active_recon),
    ("3",  "Attack Surface",    s03_attack_surface),
    ("4",  "Auth Testing",      s04_auth),
    ("5",  "Injection",         s05_injection),
    ("6",  "Access Control",    s06_access_control),
    ("7",  "API Abuse",         s07_api_abuse),
    ("8",  "Business Logic",    s08_business_logic),
    ("9",  "Cloud",             s09_cloud),
]


def run(url: str, skip: list[str] = None) -> str:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    ctx = TargetContext(url=url, domain=domain)
    skip = skip or []

    print("\n" + "=" * 60)
    print("  vulnrag — Full Attack Methodology Engine")
    print("=" * 60)
    print(f"\n  Target: {url}")
    print(f"  Domain: {domain}")
    print(f"\n  Stages to run:")
    for num, name, _ in STAGES:
        status = "  [skip]" if num in skip else ""
        print(f"    {num}. {name}{status}")

    print(f"\n  Knowledge base will inform all recommendations.")
    print(f"  Active actions require your approval before executing.")
    print(f"\n  Starting in 3 seconds... (Ctrl+C to abort a stage)\n")
    time.sleep(3)

    for num, name, module in STAGES:
        if num in skip:
            print(f"\n  [skip] Stage {num}: {name}")
            continue
        try:
            ctx = module.run(ctx)
        except KeyboardInterrupt:
            print(f"\n  Ctrl+C — skipping stage {num}: {name}")
            continue
        except Exception as e:
            print(f"\n  Stage {num} error: {e}")
            import traceback
            traceback.print_exc()
            continue

    # Final report
    report_path = s10_report.run(ctx)

    print("\n" + "=" * 60)
    print(f"  Complete. Report: {report_path}")
    print("=" * 60)

    return report_path
