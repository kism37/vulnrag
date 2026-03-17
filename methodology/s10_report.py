"""
methodology/stages/s10_report.py — Final report generation
"""
import os
from datetime import datetime
from methodology.context import TargetContext
from engine.llm import ask_with_rag


def run(ctx: TargetContext) -> str:
    print("\n" + "="*60)
    print("  STAGE 10 — Impact Assessment & Report")
    print("="*60)

    counts = ctx.severity_counts()
    print(f"\n  Total findings: {len(ctx.findings)}")
    print(f"  🔴 Critical: {counts['critical']}")
    print(f"  🟠 High:     {counts['high']}")
    print(f"  🟡 Medium:   {counts['medium']}")
    print(f"  🔵 Low:      {counts['low']}")
    print(f"  ⚪ Info:     {counts['info']}")

    findings_text = "\n".join(
        f"[{f.severity.upper()}] {f.stage} — {f.title}: {f.detail}"
        for f in ctx.findings
    ) or "No automated findings — manual testing required."

    exec_summary = ask_with_rag(
        query="Write a professional penetration test executive summary for this target.",
        context={
            "target": ctx.url,
            "tech_stack": ctx.tech_stack,
            "findings_count": len(ctx.findings),
            "severity_breakdown": str(counts),
            "critical_findings": [f.title for f in ctx.findings if f.severity == "critical"],
            "high_findings": [f.title for f in ctx.findings if f.severity == "high"],
        }
    )

    print(f"\n[*] Executive summary:\n")
    print(exec_summary)

    # Save report
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/{ctx.domain}_{timestamp}.md"

    sev_order = ["critical", "high", "medium", "low", "info"]

    with open(report_path, "w") as f:
        f.write(f"# vulnrag Report — {ctx.domain}\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Target:** {ctx.url}\n")
        f.write(f"**Duration:** {ctx.start_time} → {datetime.now().isoformat()}\n\n")

        f.write("## Executive Summary\n\n")
        f.write(exec_summary + "\n\n")

        f.write("## Severity Breakdown\n\n")
        for sev in sev_order:
            f.write(f"- {sev.capitalize()}: {counts.get(sev, 0)}\n")
        f.write("\n")

        f.write("## Findings\n\n")
        for sev in sev_order:
            sev_findings = [fi for fi in ctx.findings if fi.severity == sev]
            if not sev_findings:
                continue
            f.write(f"### {sev.upper()}\n\n")
            for fi in sev_findings:
                f.write(f"#### {fi.title}\n")
                f.write(f"**Stage:** {fi.stage}  \n")
                f.write(f"**Category:** {fi.category}  \n")
                f.write(f"**Detail:** {fi.detail}  \n")
                f.write(f"**Recommendation:** {fi.recommendation}  \n\n")

        f.write("## Recon Summary\n\n")
        f.write(ctx.summary() + "\n\n")

        f.write("## Stage Notes\n\n")
        for stage, note in ctx.stage_notes.items():
            f.write(f"### {stage.replace('_', ' ').title()}\n\n")
            f.write(note + "\n\n")

    print(f"\n  📄 Report saved: {report_path}")
    return report_path
