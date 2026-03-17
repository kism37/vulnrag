"""
methodology/human_gate.py
Permission system. Every intrusive action goes through here.
The tool never fires an active probe without explicit human approval.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class ActionType(Enum):
    PASSIVE   = "passive"    # safe, no approval needed
    ACTIVE    = "active"     # intrusive, requires approval
    INTRUSIVE = "intrusive"  # potentially loud/dangerous, requires approval + warning


@dataclass
class Action:
    name: str
    description: str
    command: str | None         # shell command to display to user
    action_type: ActionType
    fn: Callable | None = None  # callable to execute if approved
    risk: str = ""              # what could go wrong


_auto_approve_all    = False
_auto_approve_active = False
_session_approved    = set()


def set_auto_approve(val: bool):
    global _auto_approve_all
    _auto_approve_all = val


def set_auto_approve_active(val: bool):
    global _auto_approve_active
    _auto_approve_active = val


def request(action: Action) -> bool:
    if action.action_type == ActionType.PASSIVE:
        return True
    if _auto_approve_all:
        return True
    if _auto_approve_active and action.action_type == ActionType.ACTIVE:
        return True
    if action.name in _session_approved:
        return True

    _print_action(action)

    while True:
        try:
            choice = input("\n  Approve? [y]es / [n]o / [a]lways (approve all like this) / [s]kip all: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Skipped.")
            return False

        if choice in ("y", "yes"):
            return True
        elif choice in ("n", "no", "s", "skip"):
            print("  Skipped.")
            return False
        elif choice in ("a", "always"):
            _session_approved.add(action.name)
            print(f"  Auto-approving all '{action.name}' actions this session.")
            return True
        else:
            print("  Enter y, n, a, or s.")


def execute(action: Action) -> tuple[bool, any]:
    """
    Request permission then execute the action if approved.
    Returns (approved: bool, result: any)
    """
    approved = request(action)
    if not approved:
        return False, None

    if action.fn:
        try:
            result = action.fn()
            return True, result
        except Exception as e:
            print(f"  Action failed: {e}")
            return True, None

    return True, None


def _print_action(action: Action):
    icons = {
        ActionType.ACTIVE:    "🟡",
        ActionType.INTRUSIVE: "🔴",
    }
    icon = icons.get(action.action_type, "⚪")

    print(f"\n  {'─'*54}")
    print(f"  {icon} ACTION REQUIRED: {action.name}")
    print(f"  {'─'*54}")
    print(f"  {action.description}")
    if action.command:
        print(f"\n  Command: {action.command}")
    if action.risk:
        print(f"  Risk: {action.risk}")
    print(f"  Type: {action.action_type.value}")


# ── Pre-built common actions ──────────────────────────────────────────────────
def subdomain_enum(domain: str, fn: Callable = None) -> Action:
    return Action(
        name="subdomain_enum",
        description=f"Enumerate subdomains for {domain} using subfinder",
        command=f"subfinder -d {domain} -silent",
        action_type=ActionType.ACTIVE,
        fn=fn,
        risk="Sends DNS queries — visible in DNS logs",
    )


def port_scan(host: str, fn: Callable = None) -> Action:
    return Action(
        name="port_scan",
        description=f"Port scan {host} with nmap service detection",
        command=f"nmap -sV --open -p 21,22,80,443,8080,8443,... -T4 {host}",
        action_type=ActionType.ACTIVE,
        fn=fn,
        risk="Network traffic to target — may trigger IDS/WAF",
    )


def js_fetch(url: str, fn: Callable = None) -> Action:
    return Action(
        name="js_fetch",
        description=f"Fetch and analyze JavaScript files from {url}",
        command=f"curl -s {url} | grep script",
        action_type=ActionType.ACTIVE,
        fn=fn,
        risk="HTTP requests to target origin",
    )


def api_probe(url: str, path: str, fn: Callable = None) -> Action:
    return Action(
        name="api_probe",
        description=f"Check for exposed API schema at {path}",
        command=f"curl -s {url}{path}",
        action_type=ActionType.ACTIVE,
        fn=fn,
        risk="HTTP request to target — may be logged",
    )


def injection_probe(url: str, param: str, payload: str, fn: Callable = None) -> Action:
    return Action(
        name="injection_probe",
        description=f"Test {param} parameter for injection at {url}",
        command=f"curl -s '{url}?{param}={payload}'",
        action_type=ActionType.INTRUSIVE,
        fn=fn,
        risk="Sends potentially malicious input to target — will be logged",
    )


def s3_check(bucket: str, fn: Callable = None) -> Action:
    return Action(
        name="s3_check",
        description=f"Check if S3 bucket '{bucket}' is publicly accessible",
        command=f"curl -s https://{bucket}.s3.amazonaws.com",
        action_type=ActionType.ACTIVE,
        fn=fn,
        risk="HTTP request to AWS — bucket owner may see it in access logs",
    )
