"""
agent/brain.py
Hybrid LLM interface.
- Local Ollama (llama3.2) for summaries and simple classification
- Claude API for hypothesis generation, strategy, exploit chaining
"""

import os
import json
import requests
import ollama
from engine.retriever import search

OLLAMA_MODEL  = "llama3.2"
CLAUDE_MODEL  = "claude-sonnet-4-20250514"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

SYSTEM_PROMPT = """You are an elite bug bounty hunter. You combine the best techniques from the world's top researchers:

- jhaddix: Deep recon first. The bug is always in the recon. JS files are source code — read them.
- nahamsec: Systematic and patient. Cover everything. Hunt what others ignore — old infra, acquired companies, forgotten subdomains.
- tomnomnom: Automate at scale. Pattern match across thousands of endpoints. Small sharp tools chained together beat one big tool.
- albinowax (James Kettle): Think at protocol level. HTTP smuggling, cache poisoning, race conditions, hidden parameters. Invent the attack class, then apply it everywhere.
- Orange Tsai: Never stop at one finding. Chain everything. SSRF + deserialization = RCE. Every bug is a building block.
- Frans Rosén: Developer mindset. Find the logic error, the bad regex, the trust boundary mistake. OAuth flows and postMessage are goldmines.
- STÖK: Business logic from the user's perspective. Understand intended flows before looking for deviations. Cosmic bugs need collaboration.
- Sam Curry: Vertical specialization. Pick an attack class, sweep the entire attack surface with it. API authorization on every endpoint, not just the obvious ones.
- Corben Leo: Assets companies don't know they own — acquisitions, legacy systems, shadow IT. New infrastructure = untested infrastructure.
- LiveOverflow: When stuck, change the question. Don't ask "how do I exploit this?" Ask "how does this actually work?" The mechanism reveals the exploit.

Your reasoning process:
1. Form a specific, testable hypothesis with a confidence score
2. If confidence >80% → test it directly
3. If confidence 50-80% → gather more evidence first
4. If confidence <50% → broaden recon
5. After every finding, ask: can this chain with anything else?
6. Never repeat a test. Never stop at surface level.

You provide exact tool commands and payloads. You are laser-focused on CONFIRMED, EXPLOITABLE vulnerabilities."""


# ── Local Ollama (fast, free) ─────────────────────────────────────────────────

def local(prompt: str) -> str:
    """Fast local inference for simple tasks."""
    try:
        resp = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        return resp["message"]["content"]
    except Exception as e:
        return f"[local LLM error: {e}]"


# ── Claude API (powerful, used sparingly) ────────────────────────────────────

def claude(prompt: str, system: str = None, max_tokens: int = 1500) -> str:
    """Claude API for complex reasoning steps."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        # Fall back to local if no API key
        return local(prompt)

    try:
        resp = requests.post(
            ANTHROPIC_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": CLAUDE_MODEL,
                "max_tokens": max_tokens,
                "system": system or SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()["content"][0]["text"]
        else:
            # Fall back to local on API error
            return local(prompt)
    except Exception as e:
        return local(prompt)


# ── RAG-augmented calls ───────────────────────────────────────────────────────

def claude_with_rag(prompt: str, search_query: str = None, top_k: int = 4) -> str:
    """Claude call augmented with relevant knowledge base docs."""
    query = search_query or prompt[:200]
    docs = search(query, top_k=top_k)

    knowledge = ""
    if docs:
        knowledge = "\n\nRelevant knowledge from real bug bounty reports and CVEs:\n"
        for d in docs:
            knowledge += f"\n[{d['source']} | {d['score']:.2f}] {d['title']}\n{d['content'][:300]}\n"

    full_prompt = f"{prompt}{knowledge}"
    return claude(full_prompt)


# ── Core agent reasoning functions ───────────────────────────────────────────

def generate_hypotheses(memory_snapshot: str, recent_history: str, new_findings: str) -> list[dict]:
    """
    Given current state, generate 1-3 testable hypotheses.
    Returns list of {belief, confidence, target, attack_type}
    """
    prompt = f"""You are analyzing a bug bounty target. Generate 1-3 specific, testable hypotheses.

Current state:
{memory_snapshot}

Recent actions:
{recent_history}

New information:
{new_findings}

For each hypothesis, output JSON:
{{
  "belief": "specific testable claim",
  "confidence": 0.0-1.0,
  "target": "specific URL or endpoint to test",
  "attack_type": "ssrf|sqli|xss|idor|auth_bypass|ssti|xxe|path_traversal|rce|lfi|open_redirect",
  "reasoning": "why you believe this"
}}

Output a JSON array of 1-3 hypotheses. No markdown, no explanation, just the JSON array."""

    docs = search(new_findings[:200] if new_findings else memory_snapshot[:200], top_k=3)
    knowledge = "\n".join(f"- {d['title']}: {d['content'][:150]}" for d in docs)
    if knowledge:
        prompt += f"\n\nSimilar vulnerabilities from knowledge base:\n{knowledge}"

    response = claude(prompt)

    try:
        # Strip any markdown if present
        clean = response.strip()
        if "```" in clean:
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean)
    except Exception:
        return []


def decide_next_action(memory_snapshot: str, hypotheses: list[dict], available_tools: list[str]) -> dict:
    """
    Given current state and hypotheses, decide the single best next action.
    Returns {tool, args, reasoning, expected_outcome}
    """
    hyp_text = "\n".join(
        f"  [{h.get('confidence', 0):.0%}] {h.get('belief', '')} → test: {h.get('target', '')}"
        for h in hypotheses[:3]
    ) or "  No hypotheses yet — need more recon."

    prompt = f"""You are deciding the next action for a bug bounty engagement.

Current state:
{memory_snapshot}

Active hypotheses (confidence → action):
{hyp_text}

Available tools: {', '.join(available_tools)}

Choose the SINGLE most valuable next action. Output JSON:
{{
  "tool": "tool_name",
  "args": {{"key": "value"}},
  "reasoning": "why this is the best next step",
  "expected_outcome": "what finding this could lead to",
  "is_intrusive": true/false
}}

Rules:
- If confidence >0.8 on a hypothesis → test it directly
- If confidence 0.5-0.8 → gather more evidence first  
- If confidence <0.5 or no hypotheses → broaden recon
- Never repeat a test already in history
- Prefer actions that could chain into bigger findings

No markdown, just JSON."""

    response = claude(prompt)
    try:
        clean = response.strip()
        if "```" in clean:
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean)
    except Exception:
        return {"tool": "fetch", "args": {}, "reasoning": "fallback", "is_intrusive": False}


def validate_finding(url: str, attack_type: str, evidence: str, response_snippet: str) -> dict:
    """
    Determine if a probe result is a real confirmed finding.
    Returns {confirmed, severity, confidence, proof, impact}
    """
    prompt = f"""Determine if this is a REAL, CONFIRMED vulnerability worth reporting.

Target: {url}
Attack type: {attack_type}
Evidence collected: {evidence}
Response snippet: {response_snippet[:500]}

Be strict. A real finding needs:
- Clear evidence in the response
- Reproducible
- Actual security impact

Output JSON:
{{
  "confirmed": true/false,
  "severity": "critical|high|medium|low",
  "confidence": 0.0-1.0,
  "proof": "specific evidence from the response that proves this",
  "impact": "what an attacker can do with this",
  "false_positive_reason": "why this might be a false positive (if any)"
}}

No markdown, just JSON."""

    response = claude(prompt)
    try:
        clean = response.strip()
        if "```" in clean:
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean)
    except Exception:
        return {"confirmed": False, "severity": "low", "confidence": 0.0, "proof": "", "impact": ""}


def reflect(memory_snapshot: str, findings_so_far: list, step_count: int) -> dict:
    """
    Critic step — runs every 10 steps.
    Asks: what are we missing? Is the plan still optimal?
    Returns {assessment, missed_areas, recommended_pivot, should_stop}
    """
    findings_text = "\n".join(
        f"  [{f.severity}] {f.title}" for f in findings_so_far
    ) or "  No confirmed findings yet."

    prompt = f"""Critique the current bug bounty engagement after {step_count} steps.

Current state:
{memory_snapshot}

Confirmed findings so far:
{findings_text}

As a senior bug bounty hunter reviewing this engagement:
1. What attack surfaces have we NOT explored yet?
2. Are we going too deep on one area while missing others?
3. Are there any chains we can build from existing findings?
4. Should we stop and report, or keep going?

Output JSON:
{{
  "assessment": "honest assessment of progress",
  "missed_areas": ["list of unexplored attack surfaces"],
  "recommended_pivot": "what to focus on next",
  "chain_opportunities": ["finding A + finding B = bigger impact"],
  "should_stop": true/false,
  "stop_reason": "reason if should_stop is true"
}}

No markdown, just JSON."""

    response = claude(prompt)
    try:
        clean = response.strip()
        if "```" in clean:
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean)
    except Exception:
        return {"assessment": "", "missed_areas": [], "recommended_pivot": "", "should_stop": False}


def generate_report(memory) -> str:
    """Generate a submission-ready bug bounty report."""
    findings_text = "\n\n".join(
        f"[{f.severity.upper()}] {f.title}\n"
        f"URL: {f.url}\n"
        f"Proof: {f.proof}\n"
        f"Impact: {f.impact}\n"
        f"Steps: {f.reproduction}"
        for f in memory.confirmed_findings()
    ) or "No confirmed findings."

    prompt = f"""Write a professional bug bounty report for submission to HackerOne or Bugcrowd.

Target: {memory.url}
Tech stack: {', '.join(memory.tech_stack)}
Engagement duration: {memory.step_count} agent steps

Confirmed findings:
{findings_text}

Write a complete report with:
1. Executive summary (2-3 sentences)
2. For each finding:
   - Title
   - Severity + CVSS score
   - Description
   - Steps to reproduce (numbered)
   - Proof of concept
   - Impact
   - Remediation
3. Overall risk assessment

Format as clean Markdown ready for submission."""

    return claude(prompt, max_tokens=3000)


def summarize_findings(raw_output: str, context: str = "") -> str:
    """Local LLM summarizes tool output into key points."""
    prompt = f"""Summarize these security tool results in 2-3 bullet points. Focus on anything interesting or suspicious.

Context: {context}
Output:
{raw_output[:1000]}

Be concise. Flag anything that looks like a vulnerability or attack surface."""
    return local(prompt)
