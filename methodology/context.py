"""
methodology/context.py
TargetContext is the shared state passed through all 10 stages.
Each stage reads what previous stages found and adds its own findings.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Finding:
    stage: str
    category: str
    severity: str        # critical / high / medium / low / info
    title: str
    detail: str
    recommendation: str = ""
    evidence: str = ""


@dataclass
class TargetContext:
    # Target info
    url: str
    domain: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())

    # Recon results (populated by stages 1-3)
    tech_stack: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    response_headers: dict = field(default_factory=dict)
    missing_headers: list = field(default_factory=list)
    cors_issues: list = field(default_factory=list)
    js_secrets: list = field(default_factory=list)
    vuln_libs: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    api_schemas: list = field(default_factory=list)
    graphql_introspection: bool = False
    exposed_files: list = field(default_factory=list)
    s3_buckets: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    wayback_urls: list = field(default_factory=list)

    # Findings accumulated across all stages
    findings: list = field(default_factory=list)

    # Stage notes (free-form text per stage for LLM context)
    stage_notes: dict = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def summary(self) -> str:
        """Build a concise summary of everything found so far for LLM context."""
        parts = []

        if self.tech_stack:
            parts.append(f"Tech stack: {', '.join(self.tech_stack)}")

        if self.open_ports:
            port_list = [f"{p['port']}/{p['service']}" for p in self.open_ports]
            parts.append(f"Open ports: {', '.join(port_list)}")

        if self.missing_headers:
            parts.append(f"Missing security headers: {', '.join(self.missing_headers)}")

        if self.cors_issues:
            parts.append(f"CORS issues: {', '.join(self.cors_issues)}")

        if self.js_secrets:
            types = list({s['type'] for s in self.js_secrets})
            parts.append(f"JS secrets found: {', '.join(types)}")

        if self.vuln_libs:
            libs = [f"{l['lib']} {l['version']} ({l['cve']})" for l in self.vuln_libs]
            parts.append(f"Vulnerable libraries: {', '.join(libs)}")

        if self.subdomains:
            parts.append(f"Subdomains: {len(self.subdomains)} found")

        if self.api_schemas:
            paths = [s['path'] for s in self.api_schemas]
            parts.append(f"Exposed API schemas: {', '.join(paths)}")

        if self.graphql_introspection:
            parts.append("GraphQL introspection enabled")

        if self.exposed_files:
            paths = [f['path'] for f in self.exposed_files]
            parts.append(f"Exposed files: {', '.join(paths)}")

        if self.s3_buckets:
            public = [b['bucket'] for b in self.s3_buckets if b['status'] == 'public']
            if public:
                parts.append(f"Public S3 buckets: {', '.join(public)}")

        if self.findings:
            by_sev = {}
            for f in self.findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            sev_str = ", ".join(f"{v} {k}" for k, v in by_sev.items())
            parts.append(f"Findings so far: {sev_str}")

        return "\n".join(parts) if parts else "No significant findings yet."

    def severity_counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
        return counts
