"""
agent/agent_loop.py
The core autonomous agent loop.
Observe → Hypothesize → Decide → Execute → Validate → Reflect → Repeat
"""

import json
import time
import os
from urllib.parse import urlparse
from agent.memory import AgentMemory
from agent import brain, tools


MAX_STEPS        = 50
REFLECT_EVERY    = 10
MIN_CONFIDENCE   = 0.4


def _ask_permission(action: dict) -> bool:
    """Ask human before intrusive actions."""
    print(f"\n  {'─'*54}")
    print(f"  🔴 INTRUSIVE ACTION: {action.get('tool')}")
    print(f"  {action.get('reasoning', '')}")
    print(f"  Expected: {action.get('expected_outcome', '')}")
    if action.get('args'):
        print(f"  Args: {json.dumps(action['args'], indent=2)}")
    print(f"  {'─'*54}")
    try:
        choice = input("  Approve? [y]es / [n]o / [a]ll (approve all intrusive): ").strip().lower()
        return choice in ("y", "yes", "a", "all")
    except (EOFError, KeyboardInterrupt):
        return False


def _bootstrap_recon(memory: AgentMemory) -> str:
    """Initial passive recon — no approval needed."""
    print("\n[*] Bootstrapping recon...")
    findings = []

    # Fetch the page
    print(f"  Fetching {memory.url}...")
    page = tools.fetch(memory.url)
    if "error" not in page:
        status = page.get("status", 0)
        print(f"  Status: {status}, Size: {page.get('size', 0)} bytes")

        # Tech fingerprinting from headers
        headers = page.get("headers", {})
        for h in ["server", "x-powered-by", "x-generator", "x-aspnet-version"]:
            val = headers.get(h) or headers.get(h.title())
            if val:
                memory.tech_stack.append(f"{h}: {val}")
                print(f"  🖥️  {h}: {val}")

        memory.response_headers = headers

        # Security headers
        missing = []
        for h in ["content-security-policy", "x-frame-options", "strict-transport-security"]:
            if h not in {k.lower() for k in headers}:
                missing.append(h)
        if missing:
            findings.append(f"Missing security headers: {', '.join(missing)}")
            print(f"  ⚠️  Missing headers: {', '.join(missing)}")

        # CORS check
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append("CORS wildcard: Access-Control-Allow-Origin: *")
            print("  🚨 CORS wildcard detected")

        # Add links as endpoints
        for link in page.get("links", [])[:15]:
            if link.startswith("/"):
                ep = memory.add_endpoint(
                    url=memory.url.rstrip("/") + link,
                    path=link,
                    source="initial_fetch"
                )
                if ep.interest_score > 0.3:
                    print(f"  📌 Interesting path: {link} (score: {ep.interest_score:.2f})")

        # Forms
        for form in page.get("forms", []):
            action = form.get("action", "")
            inputs = form.get("inputs", [])
            if action or inputs:
                findings.append(f"Form found: action={action}, inputs={inputs}")
                print(f"  📋 Form: {action} [{', '.join(inputs)}]")

    # JS files
    print(f"\n  Finding JS files...")
    js_files = tools.find_js_files(memory.url)
    print(f"  Found {len(js_files)} JS files")

    for js_url in js_files[:8]:
        print(f"  Analyzing {js_url.split('/')[-1]}...")
        js_data = tools.extract_js_endpoints(js_url)

        for path in js_data.get("paths", [])[:10]:
            if path.startswith("/"):
                ep = memory.add_endpoint(
                    url=memory.url.rstrip("/") + path,
                    path=path,
                    source=f"js:{js_url.split('/')[-1]}"
                )

        for secret_type, values in js_data.get("secrets", {}).items():
            for val in values:
                memory.js_secrets.append({"type": secret_type, "value": val, "file": js_url})
                findings.append(f"Secret in JS: {secret_type} = {val[:50]}")
                print(f"  🚨 {secret_type} in {js_url.split('/')[-1]}")

    # Wayback
    print(f"\n  Checking Wayback Machine...")
    wb_urls = tools.wayback(memory.domain)
    print(f"  Found {len(wb_urls)} interesting historical URLs")
    for url in wb_urls[:10]:
        path = "/" + "/".join(url.split("/")[3:])
        memory.add_endpoint(url=url, path=path, source="wayback")
    findings.extend([f"Wayback URL: {u}" for u in wb_urls[:5]])

    # crt.sh
    print(f"\n  Certificate transparency lookup...")
    subdomains = tools.crt_sh(memory.domain)
    for sub in subdomains:
        memory.add_asset(sub, "subdomain", "crt.sh")
    print(f"  Found {len(subdomains)} subdomains via crt.sh")

    summary = "\n".join(findings) if findings else "Basic recon complete. No immediate findings."
    print(f"\n  Bootstrap complete — {len(memory.endpoints)} endpoints, {len(memory.js_secrets)} secrets, {len(subdomains)} subdomains")
    return summary


def run(url: str, max_steps: int = MAX_STEPS) -> AgentMemory:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not url.startswith("http"):
        url = "https://" + url

    domain = urlparse(url).netloc

    memory = AgentMemory(url=url, domain=domain)

    print("\n" + "=" * 60)
    print("  vulnrag v3 — Autonomous Agent")
    print("=" * 60)
    print(f"  Target:    {url}")
    print(f"  Max steps: {max_steps}")
    print(f"  LLM:       Hybrid (local + Claude API)")
    print(f"\n  Set ANTHROPIC_API_KEY for best results.")
    print(f"  Ctrl+C anytime to stop and generate report.\n")

    # Approval mode
    print("  Approval mode:")
    print("  [1] Ask before every intrusive action")
    print("  [2] Auto-approve everything (fastest)")
    mode = input("\n  Choose [1/2] (default 1): ").strip() or "1"
    auto_approve = mode == "2"

    # Bootstrap passive recon
    initial_findings = _bootstrap_recon(memory)

    # Generate initial hypotheses
    print("\n[*] Generating initial hypotheses...")
    hypotheses = brain.generate_hypotheses(
        memory_snapshot=memory.snapshot(),
        recent_history=memory.recent_history(),
        new_findings=initial_findings,
    )

    for h in hypotheses:
        hyp = memory.add_hypothesis(
            belief=h.get("belief", ""),
            confidence=float(h.get("confidence", 0.5)),
            target=h.get("target", url),
            attack_type=h.get("attack_type", "unknown"),
            evidence=h.get("reasoning", ""),
        )
        print(f"  💡 [{hyp.confidence:.0%}] {hyp.belief}")

    # ── Main agent loop ───────────────────────────────────────────────────────
    print(f"\n[*] Starting agent loop (max {max_steps} steps)...")

    try:
        while memory.step_count < max_steps and not memory.done:
            memory.step_count += 1
            print(f"\n{'─'*60}")
            print(f"  Step {memory.step_count}/{max_steps} | Findings: {len(memory.confirmed_findings())} | Hypotheses: {len(memory.pending_hypotheses())}")

            # Decide next action
            active_hyps = [
                {"belief": h.belief, "confidence": h.confidence, "target": h.target, "attack_type": h.attack_type}
                for h in memory.high_confidence_hypotheses()[:3]
            ]

            action = brain.decide_next_action(
                memory_snapshot=memory.snapshot(),
                hypotheses=active_hyps,
                available_tools=tools.available_tools(),
            )

            tool_name = action.get("tool", "")
            tool_args = action.get("args", {})
            reasoning = action.get("reasoning", "")

            print(f"  🤖 Decision: {tool_name}")
            print(f"  💭 Reasoning: {reasoning[:100]}")

            # Stop signal
            if tool_name == "done":
                memory.done = True
                memory.stop_reason = reasoning
                print(f"  Agent signalled done: {reasoning}")
                break

            # Skip unknown tools
            if tool_name not in tools.TOOL_REGISTRY:
                print(f"  Unknown tool: {tool_name}, skipping")
                continue

            # Skip already tested
            test_key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
            if memory.already_tested(test_key, tool_name):
                print(f"  Already tested {tool_name} with these args, skipping")
                # Force a new hypothesis
                new_hyps = brain.generate_hypotheses(
                    memory.snapshot(), memory.recent_history(3), "Previous action was already tested."
                )
                for h in new_hyps:
                    memory.add_hypothesis(h.get("belief",""), float(h.get("confidence",0.4)),
                                          h.get("target", url), h.get("attack_type","unknown"))
                continue

            # Human approval for intrusive actions
            if tools.is_intrusive(tool_name) and not auto_approve:
                approved = _ask_permission(action)
                if not approved:
                    print("  Skipped by user.")
                    memory.add_test_record(
                        action=f"skipped:{tool_name}", target=str(tool_args),
                        tool=tool_name, result="Skipped by user"
                    )
                    continue

            # Execute tool
            print(f"  ⚙️  Executing {tool_name}...")
            start = time.time()
            result = tools.dispatch(tool_name, tool_args)
            elapsed = time.time() - start
            print(f"  Done in {elapsed:.1f}s")

            # Summarize result with local LLM
            result_str = json.dumps(result, default=str)[:800]
            summary = brain.summarize_findings(
                result_str,
                context=f"{tool_name} on {tool_args}"
            )
            print(f"  📊 {summary[:200]}")

            # Record test
            memory.add_test_record(
                action=tool_name,
                target=json.dumps(tool_args, default=str),
                tool=tool_name,
                result=summary,
                found_something="error" not in result and len(result_str) > 50,
            )

            # Update memory from results
            _update_memory_from_result(memory, tool_name, tool_args, result)

            # Validate if this looks like a finding
            should_validate = _looks_promising(tool_name, result)
            if should_validate:
                print(f"  🔍 Validating potential finding...")
                validation = brain.validate_finding(
                    url=tool_args.get("url", url),
                    attack_type=tool_name.replace("test_", ""),
                    evidence=summary,
                    response_snippet=result_str,
                )
                if validation.get("confirmed"):
                    finding = memory.add_finding(
                        title=f"{tool_name.replace('test_', '').upper()} at {tool_args.get('url', url)}",
                        attack_type=tool_name.replace("test_", ""),
                        severity=validation.get("severity", "medium"),
                        url=tool_args.get("url", url),
                        parameter=tool_args.get("param", ""),
                        proof=validation.get("proof", ""),
                        impact=validation.get("impact", ""),
                        confirmed=True,
                    )
                    print(f"\n  🚨 CONFIRMED FINDING: [{finding.severity.upper()}] {finding.title}")
                    print(f"  Proof: {finding.proof[:100]}")

            # Generate new hypotheses from what we just found
            new_hyps = brain.generate_hypotheses(
                memory_snapshot=memory.snapshot(),
                recent_history=memory.recent_history(3),
                new_findings=summary,
            )
            for h in new_hyps:
                conf = float(h.get("confidence", 0.4))
                if conf >= MIN_CONFIDENCE:
                    memory.add_hypothesis(
                        belief=h.get("belief", ""),
                        confidence=conf,
                        target=h.get("target", url),
                        attack_type=h.get("attack_type", "unknown"),
                        evidence=h.get("reasoning", ""),
                    )

            # Reflect every N steps
            if memory.step_count % REFLECT_EVERY == 0:
                print(f"\n  🪞 Reflection at step {memory.step_count}...")
                reflection = brain.reflect(
                    memory_snapshot=memory.snapshot(),
                    findings_so_far=memory.confirmed_findings(),
                    step_count=memory.step_count,
                )
                print(f"  Assessment: {reflection.get('assessment', '')[:150]}")
                if reflection.get("missed_areas"):
                    print(f"  Missed: {', '.join(reflection['missed_areas'][:3])}")
                if reflection.get("chain_opportunities"):
                    for chain in reflection["chain_opportunities"][:2]:
                        print(f"  🔗 Chain opportunity: {chain}")
                        memory.chains.append({"description": chain, "step": memory.step_count})
                if reflection.get("should_stop"):
                    print(f"  Agent recommends stopping: {reflection.get('stop_reason', '')}")
                    memory.done = True
                    memory.stop_reason = reflection.get("stop_reason", "")
                    break

    except KeyboardInterrupt:
        print(f"\n  Stopped by user at step {memory.step_count}")
        memory.stop_reason = "Interrupted by user"

    return memory


def _update_memory_from_result(memory: AgentMemory, tool_name: str, args: dict, result: dict):
    """Parse tool results and update structured memory."""
    if tool_name == "extract_js_endpoints":
        for path in result.get("paths", [])[:15]:
            if path.startswith("/"):
                memory.add_endpoint(
                    url=memory.url.rstrip("/") + path,
                    path=path,
                    source="js_extraction"
                )
        for secret_type, values in result.get("secrets", {}).items():
            for val in values:
                if not any(s["type"] == secret_type and s["value"] == val for s in memory.js_secrets):
                    memory.js_secrets.append({"type": secret_type, "value": val})

    elif tool_name == "enum_subdomains":
        for sub in result if isinstance(result, list) else []:
            memory.add_asset(sub, "subdomain", "subfinder")

    elif tool_name == "scan_ports":
        memory.open_ports = result if isinstance(result, list) else []

    elif tool_name == "fetch":
        for link in result.get("links", []):
            if link.startswith("/"):
                memory.add_endpoint(
                    url=memory.url.rstrip("/") + link,
                    path=link,
                    source="fetch"
                )

    elif tool_name == "crt_sh":
        for sub in result if isinstance(result, list) else []:
            memory.add_asset(sub, "subdomain", "crt.sh")

    elif tool_name == "wayback":
        for url in result if isinstance(result, list) else []:
            path = "/" + "/".join(url.split("/")[3:])
            memory.add_endpoint(url=url, path=path, source="wayback")


def _looks_promising(tool_name: str, result: dict) -> bool:
    """Decide if a result warrants full validation."""
    if "error" in result:
        return False

    result_str = json.dumps(result, default=str).lower()

    if tool_name == "test_sqli":
        return any(r.get("has_sql_error") for r in result.get("results", []))

    if tool_name == "test_xss":
        return any(r.get("reflected") for r in result.get("results", []))

    if tool_name == "test_ssrf":
        return any(r.get("possible_hit") for r in result.get("results", []))

    if tool_name == "test_ssti":
        return any(r.get("hit") for r in result.get("results", []))

    if tool_name == "test_open_redirect":
        return any(r.get("redirected_to_payload") for r in result.get("results", []))

    if tool_name == "check_cors":
        return any(r.get("vulnerable") for r in result.get("results", []))

    if tool_name == "check_auth_headers":
        return result.get("possible_bypass", False)

    if tool_name == "test_idor":
        return result.get("possible_idor", False)

    return False
