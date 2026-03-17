"""
agent/memory.py
Structured memory for the agent. Replaces flat TargetContext.
Everything the agent knows lives here, organized for fast retrieval.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


@dataclass
class Asset:
    value: str          # domain, IP, subdomain, URL
    asset_type: str     # domain, subdomain, ip, url
    source: str         # how we found it
    interesting: bool = False
    notes: str = ""


@dataclass
class Endpoint:
    url: str
    path: str
    method: str = "GET"
    params: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    status_code: int = 0
    response_size: int = 0
    tech_hints: list = field(default_factory=list)
    interest_score: float = 0.0   # 0-1, higher = test deeper
    notes: str = ""
    source: str = ""


@dataclass
class Hypothesis:
    belief: str              # "This param fetches URLs → SSRF candidate"
    confidence: float        # 0-1
    target: str              # what to test (url + param)
    attack_type: str         # ssrf, sqli, xss, idor, etc.
    status: str = "pending"  # pending, testing, confirmed, rejected
    evidence: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Finding:
    title: str
    attack_type: str
    severity: str           # critical, high, medium, low
    url: str
    parameter: str = ""
    proof: str = ""         # actual evidence — response snippet, PoC
    cvss_score: float = 0.0
    impact: str = ""
    reproduction: str = ""  # step by step to reproduce
    recommendation: str = ""
    confirmed: bool = False
    chain_ids: list = field(default_factory=list)  # related finding IDs
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TestRecord:
    action: str         # what we did
    target: str         # what we tested
    tool: str           # tool used
    result: str         # what came back (summary)
    found_something: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AgentMemory:
    # Target info
    url: str
    domain: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())

    # Structured memory buckets
    assets:       list[Asset]      = field(default_factory=list)
    endpoints:    list[Endpoint]   = field(default_factory=list)
    hypotheses:   list[Hypothesis] = field(default_factory=list)
    findings:     list[Finding]    = field(default_factory=list)
    test_history: list[TestRecord] = field(default_factory=list)
    chains:       list[dict]       = field(default_factory=list)

    # Agent state
    step_count:   int  = 0
    done:         bool = False
    stop_reason:  str  = ""

    # Raw recon data
    tech_stack:       list = field(default_factory=list)
    response_headers: dict = field(default_factory=dict)
    js_secrets:       list = field(default_factory=list)
    vuln_libs:        list = field(default_factory=list)
    open_ports:       list = field(default_factory=list)


    # ── Adders ───────────────────────────────────────────────────────────────

    def add_asset(self, value: str, asset_type: str, source: str, interesting: bool = False):
        # Deduplicate
        if not any(a.value == value for a in self.assets):
            self.assets.append(Asset(value=value, asset_type=asset_type, source=source, interesting=interesting))

    def add_endpoint(self, url: str, path: str, **kwargs) -> Endpoint:
        existing = next((e for e in self.endpoints if e.url == url), None)
        if existing:
            return existing
        ep = Endpoint(url=url, path=path, **kwargs)
        ep.interest_score = self._score_endpoint(ep)
        self.endpoints.append(ep)
        return ep

    def add_hypothesis(self, belief: str, confidence: float, target: str, attack_type: str, evidence: str = "") -> Hypothesis:
        h = Hypothesis(belief=belief, confidence=confidence, target=target,
                       attack_type=attack_type, evidence=evidence)
        self.hypotheses.append(h)
        return h

    def add_finding(self, title: str, attack_type: str, severity: str, url: str, **kwargs) -> Finding:
        f = Finding(title=title, attack_type=attack_type, severity=severity, url=url, **kwargs)
        self.findings.append(f)
        return f

    def add_test_record(self, action: str, target: str, tool: str, result: str, found_something: bool = False):
        self.test_history.append(TestRecord(
            action=action, target=target, tool=tool,
            result=result, found_something=found_something
        ))

    def already_tested(self, target: str, action: str) -> bool:
        return any(t.target == target and t.action == action for t in self.test_history)


    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score_endpoint(self, ep: Endpoint) -> float:
        score = 0.0
        interesting_paths = [
            "api", "admin", "auth", "login", "upload", "file", "user",
            "account", "token", "oauth", "graphql", "webhook", "callback",
            "redirect", "fetch", "proxy", "export", "import", "download",
        ]
        interesting_params = [
            "url", "redirect", "next", "file", "path", "callback", "id",
            "user_id", "token", "key", "secret", "cmd", "exec", "query",
        ]
        path_lower = ep.path.lower()
        for p in interesting_paths:
            if p in path_lower:
                score += 0.15
        for p in interesting_params:
            if any(p in param.lower() for param in ep.params):
                score += 0.2
        if ep.status_code in [200, 302, 401, 403]:
            score += 0.1
        return min(score, 1.0)


    # ── Queries ───────────────────────────────────────────────────────────────

    def top_endpoints(self, n: int = 5) -> list[Endpoint]:
        return sorted(self.endpoints, key=lambda e: e.interest_score, reverse=True)[:n]

    def pending_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses if h.status == "pending"]

    def high_confidence_hypotheses(self, threshold: float = 0.5) -> list[Hypothesis]:
        return sorted(
            [h for h in self.pending_hypotheses() if h.confidence >= threshold],
            key=lambda h: h.confidence, reverse=True
        )

    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.confirmed]

    def severity_counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.confirmed_findings():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


    # ── Context snapshot for LLM ─────────────────────────────────────────────

    def snapshot(self) -> str:
        """Concise summary of current state for LLM context."""
        lines = [
            f"Target: {self.url}",
            f"Step: {self.step_count}",
            f"Tech stack: {', '.join(self.tech_stack) or 'unknown'}",
            f"Assets found: {len(self.assets)} ({len([a for a in self.assets if a.asset_type == 'subdomain'])} subdomains)",
            f"Endpoints mapped: {len(self.endpoints)}",
            f"Open ports: {', '.join(p['port'] + '/' + p['service'] for p in self.open_ports) or 'none'}",
            f"Hypotheses: {len(self.pending_hypotheses())} pending, {len([h for h in self.hypotheses if h.status == 'confirmed'])} confirmed",
            f"Findings: {len(self.confirmed_findings())} confirmed",
            f"Tests run: {len(self.test_history)}",
        ]

        if self.js_secrets:
            lines.append(f"JS secrets found: {', '.join(s['type'] for s in self.js_secrets[:3])}")

        if self.vuln_libs:
            lines.append(f"Vulnerable libs: {', '.join(l['lib'] + ' ' + l['version'] for l in self.vuln_libs[:3])}")

        if self.high_confidence_hypotheses():
            top = self.high_confidence_hypotheses()[0]
            lines.append(f"Top hypothesis ({top.confidence:.0%}): {top.belief}")

        if self.confirmed_findings():
            lines.append(f"Confirmed findings: {', '.join(f.title for f in self.confirmed_findings()[:3])}")

        return "\n".join(lines)


    def recent_history(self, n: int = 5) -> str:
        """Last N test records as text."""
        recent = self.test_history[-n:]
        return "\n".join(
            f"  [{t.tool}] {t.action} on {t.target}: {t.result[:80]}"
            for t in recent
        ) or "  No tests run yet."


    def to_json(self) -> str:
        """Serialize for checkpoint/resume."""
        def default(o):
            if hasattr(o, '__dict__'):
                return o.__dict__
            return str(o)
        return json.dumps(self.__dict__, default=default, indent=2)
