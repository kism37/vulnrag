"""
agent/tools.py
All tools available to the agent.
Each returns structured data the agent can reason about.
"""

import re
import subprocess
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (X11; Linux x86_64) vulnrag/3.0"
HEADERS = {"User-Agent": UA}

# ── Registry — what the agent can call ───────────────────────────────────────

TOOL_REGISTRY = {
    "fetch":               {"desc": "Fetch a URL and return headers + body snippet", "intrusive": False},
    "extract_js_endpoints":{"desc": "Extract all endpoints/paths from a JS file",     "intrusive": False},
    "find_js_files":       {"desc": "Find all JS files linked on a page",             "intrusive": False},
    "wayback":             {"desc": "Get interesting historical URLs from Wayback",    "intrusive": False},
    "crt_sh":              {"desc": "Find subdomains via certificate transparency",    "intrusive": False},
    "enum_subdomains":     {"desc": "Enumerate subdomains with subfinder",            "intrusive": True},
    "scan_ports":          {"desc": "Port scan a host with nmap",                     "intrusive": True},
    "probe_path":          {"desc": "Check if a specific path exists on the target",  "intrusive": True},
    "test_sqli":           {"desc": "Test a parameter for SQL injection",             "intrusive": True},
    "test_xss":            {"desc": "Test a parameter for XSS",                       "intrusive": True},
    "test_ssrf":           {"desc": "Test a parameter for SSRF",                      "intrusive": True},
    "test_ssti":           {"desc": "Test a parameter for SSTI",                      "intrusive": True},
    "test_open_redirect":  {"desc": "Test a parameter for open redirect",             "intrusive": True},
    "test_idor":           {"desc": "Test an endpoint for IDOR",                      "intrusive": True},
    "run_ffuf":            {"desc": "Run ffuf for directory/param fuzzing",           "intrusive": True},
    "check_cors":          {"desc": "Test CORS misconfiguration",                     "intrusive": True},
    "check_auth_headers":  {"desc": "Test if endpoint enforces authentication",       "intrusive": True},
    "done":                {"desc": "Signal engagement complete",                     "intrusive": False},
}


def available_tools() -> list[str]:
    return list(TOOL_REGISTRY.keys())


def is_intrusive(tool_name: str) -> bool:
    return TOOL_REGISTRY.get(tool_name, {}).get("intrusive", True)


# ── Tool implementations ──────────────────────────────────────────────────────

def fetch(url: str) -> dict:
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        text_preview = soup.get_text()[:500].strip()
        forms = []
        for form in soup.find_all("form"):
            inputs = [i.get("name", "") for i in form.find_all("input")]
            forms.append({"action": form.get("action", ""), "inputs": inputs})
        links = list(set(
            a.get("href", "") for a in soup.find_all("a", href=True)
            if a.get("href", "").startswith("/") or url.split("/")[2] in a.get("href", "")
        ))[:20]
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "preview": text_preview,
            "forms": forms,
            "links": links,
            "size": len(r.content),
        }
    except Exception as e:
        return {"error": str(e)}


def find_js_files(url: str) -> list[str]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        base = "{0.scheme}://{0.netloc}".format(urlparse(url))
        js_files = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("http"):
                js_files.append(src)
            elif src.startswith("//"):
                js_files.append("https:" + src)
            else:
                js_files.append(urljoin(base, src))
        return js_files
    except Exception:
        return []


def extract_js_endpoints(js_url: str) -> dict:
    """Extract endpoints, params, and secrets from a JS file."""
    try:
        r = requests.get(js_url, headers=HEADERS, timeout=10, verify=False)
        content = r.text

        # Extract paths
        path_patterns = [
            r'["\'](/[a-zA-Z0-9_\-/]+(?:\?[^"\']*)?)["\']',
            r'(?:url|path|endpoint|api)\s*[:=]\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        ]
        paths = set()
        for pattern in path_patterns:
            for match in re.findall(pattern, content):
                if len(match) > 1 and not match.startswith("//"):
                    paths.add(match)

        # Extract params from paths
        params = set()
        for path in paths:
            if "?" in path:
                for p in path.split("?")[1].split("&"):
                    param = p.split("=")[0]
                    if param:
                        params.add(param)

        # Extract secrets
        secret_patterns = {
            "AWS Key":      r"AKIA[0-9A-Z]{16}",
            "JWT":          r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
            "API Key":      r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]",
            "Firebase":     r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
            "S3 Bucket":    r"s3\.amazonaws\.com/[a-zA-Z0-9\-_\.]+",
            "Internal URL": r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+)",
            "GraphQL":      r"(?i)['\"/](graphql|gql)['\"/]",
            "Private Key":  r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
        }
        secrets = {}
        for name, pattern in secret_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                secrets[name] = list(set(matches))[:2]

        return {
            "paths": list(paths)[:30],
            "params": list(params)[:20],
            "secrets": secrets,
            "size": len(content),
        }
    except Exception as e:
        return {"error": str(e), "paths": [], "params": [], "secrets": {}}


def wayback(domain: str) -> list[str]:
    INTERESTING = ["api", "admin", "login", "auth", "token", "key", "upload",
                   "backup", "config", ".env", ".sql", "graphql", "webhook"]
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=100",
            timeout=15
        )
        if r.status_code != 200:
            return []
        urls = [u[0] for u in r.json()[1:]]
        return [u for u in urls if any(k in u.lower() for k in INTERESTING)][:25]
    except Exception:
        return []


def crt_sh(domain: str) -> list[str]:
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15, headers=HEADERS)
        if r.status_code != 200:
            return []
        found = set()
        for cert in r.json()[:100]:
            for d in cert.get("name_value", "").split("\n"):
                d = d.strip().lstrip("*.")
                if domain in d:
                    found.add(d)
        return list(found)
    except Exception:
        return []


def enum_subdomains(domain: str) -> list[str]:
    try:
        r = subprocess.run(["subfinder", "-d", domain, "-silent"],
                           capture_output=True, text=True, timeout=90)
        return [s.strip() for s in r.stdout.strip().splitlines() if s.strip()]
    except Exception:
        return []


def scan_ports(host: str) -> list[dict]:
    host = re.sub(r"https?://", "", host).split("/")[0]
    PORTS = "21,22,23,25,53,80,110,143,443,445,3000,3306,3389,4443,5432,6379,8080,8443,8888,9200,27017"
    try:
        r = subprocess.run(
            ["nmap", "-sV", "--open", "-p", PORTS, "-T4", "--host-timeout", "60s", host],
            capture_output=True, text=True, timeout=120
        )
        ports = []
        for line in r.stdout.splitlines():
            m = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                port, proto, service, version = m.groups()
                ports.append({"port": port, "proto": proto, "service": service, "version": version.strip()})
        return ports
    except Exception:
        return []


def probe_path(base_url: str, path: str) -> dict:
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, verify=False, allow_redirects=True)
        return {
            "url": url,
            "status": r.status_code,
            "size": len(r.content),
            "redirect": r.url if r.url != url else None,
            "preview": r.text[:200],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def test_sqli(url: str, param: str) -> dict:
    payloads = ["'", "\"", "1' OR '1'='1", "1 AND SLEEP(3)--", "' UNION SELECT NULL--"]
    results = []
    baseline = None
    try:
        baseline = requests.get(url, params={param: "test"}, headers=HEADERS, timeout=8, verify=False)
    except Exception:
        pass

    for payload in payloads[:3]:
        try:
            r = requests.get(url, params={param: payload}, headers=HEADERS, timeout=8, verify=False)
            error_signs = ["sql syntax", "mysql_fetch", "pg_query", "sqlite", "ORA-", "syntax error"]
            has_error = any(e in r.text.lower() for e in error_signs)
            size_diff = abs(len(r.content) - len(baseline.content)) if baseline else 0
            results.append({
                "payload": payload,
                "status": r.status_code,
                "has_sql_error": has_error,
                "size_diff": size_diff,
                "response_preview": r.text[:150],
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})

    return {"url": url, "param": param, "results": results}


def test_xss(url: str, param: str) -> dict:
    payloads = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "{{7*7}}",
    ]
    results = []
    for payload in payloads[:3]:
        try:
            r = requests.get(url, params={param: payload}, headers=HEADERS, timeout=8, verify=False)
            reflected = payload in r.text or payload.lower() in r.text.lower()
            results.append({
                "payload": payload,
                "reflected": reflected,
                "status": r.status_code,
                "response_preview": r.text[:150],
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    return {"url": url, "param": param, "results": results}


def test_ssrf(url: str, param: str, callback_url: str = "http://169.254.169.254/latest/meta-data/") -> dict:
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost/",
        "http://127.0.0.1/",
    ]
    results = []
    for payload in payloads[:3]:
        try:
            r = requests.get(url, params={param: payload}, headers=HEADERS, timeout=8, verify=False)
            cloud_signs = ["ami-id", "instance-id", "security-credentials", "computeMetadata",
                           "iam", "AccessKeyId", "SecretAccessKey"]
            hit = any(s in r.text for s in cloud_signs)
            results.append({
                "payload": payload,
                "status": r.status_code,
                "possible_hit": hit,
                "size": len(r.content),
                "response_preview": r.text[:200],
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    return {"url": url, "param": param, "results": results}


def test_ssti(url: str, param: str) -> dict:
    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("*{7*7}", "49"),
    ]
    results = []
    for payload, expected in payloads:
        try:
            r = requests.get(url, params={param: payload}, headers=HEADERS, timeout=8, verify=False)
            hit = expected in r.text
            results.append({
                "payload": payload,
                "expected": expected,
                "hit": hit,
                "status": r.status_code,
                "response_preview": r.text[:150],
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    return {"url": url, "param": param, "results": results}


def test_open_redirect(url: str, param: str) -> dict:
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%23",
    ]
    results = []
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, headers=HEADERS,
                             timeout=8, verify=False, allow_redirects=False)
            location = r.headers.get("Location", "")
            hit = "evil.com" in location
            results.append({
                "payload": payload,
                "status": r.status_code,
                "location": location,
                "redirected_to_payload": hit,
            })
        except Exception as e:
            results.append({"payload": payload, "error": str(e)})
    return {"url": url, "param": param, "results": results}


def test_idor(url: str, id_param: str, current_id: str, test_id: str) -> dict:
    try:
        r1 = requests.get(url, params={id_param: current_id}, headers=HEADERS, timeout=8, verify=False)
        r2 = requests.get(url, params={id_param: test_id}, headers=HEADERS, timeout=8, verify=False)
        return {
            "url": url,
            "param": id_param,
            "own_id": {"id": current_id, "status": r1.status_code, "size": len(r1.content)},
            "other_id": {"id": test_id, "status": r2.status_code, "size": len(r2.content)},
            "possible_idor": r2.status_code == 200 and len(r2.content) > 50,
            "response_preview": r2.text[:200],
        }
    except Exception as e:
        return {"error": str(e)}


def check_cors(url: str) -> dict:
    origins = ["https://evil.com", "null", "https://attacker.com"]
    results = []
    for origin in origins:
        try:
            r = requests.get(url, headers={**HEADERS, "Origin": origin}, timeout=8, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            results.append({
                "origin_sent": origin,
                "acao": acao,
                "acac": acac,
                "vulnerable": acao == origin or acao == "*",
                "critical": acao == origin and acac.lower() == "true",
            })
        except Exception as e:
            results.append({"origin_sent": origin, "error": str(e)})
    return {"url": url, "results": results}


def check_auth_headers(url: str) -> dict:
    try:
        r_with = requests.get(url, headers=HEADERS, timeout=8, verify=False)
        r_without = requests.get(url, headers={**HEADERS, "Authorization": ""}, timeout=8, verify=False)
        r_bogus = requests.get(url, headers={**HEADERS, "Authorization": "Bearer invalid_token"}, timeout=8, verify=False)
        return {
            "url": url,
            "normal_status": r_with.status_code,
            "no_auth_status": r_without.status_code,
            "bogus_auth_status": r_bogus.status_code,
            "auth_enforced": r_without.status_code in [401, 403],
            "possible_bypass": r_without.status_code == 200,
        }
    except Exception as e:
        return {"error": str(e)}


def run_ffuf(url: str, wordlist: str = None, mode: str = "dirs") -> dict:
    if not wordlist:
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    try:
        import os
        if not os.path.exists(wordlist):
            return {"error": f"Wordlist not found: {wordlist}. Install seclists."}
        cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,301,302,403",
               "-t", "50", "-timeout", "5", "-of", "json", "-o", "/tmp/ffuf_out.json", "-s"]
        subprocess.run(cmd, capture_output=True, timeout=60)
        import json, os
        if os.path.exists("/tmp/ffuf_out.json"):
            with open("/tmp/ffuf_out.json") as f:
                data = json.load(f)
            results = data.get("results", [])
            return {"found": [{"url": r["url"], "status": r["status"], "size": r["length"]} for r in results[:20]]}
        return {"found": []}
    except Exception as e:
        return {"error": str(e)}


def dispatch(tool_name: str, args: dict) -> dict:
    """Central dispatcher — agent calls this with tool name and args."""
    tools = {
        "fetch":                fetch,
        "find_js_files":        find_js_files,
        "extract_js_endpoints": extract_js_endpoints,
        "wayback":              wayback,
        "crt_sh":               crt_sh,
        "enum_subdomains":      enum_subdomains,
        "scan_ports":           scan_ports,
        "probe_path":           probe_path,
        "test_sqli":            test_sqli,
        "test_xss":             test_xss,
        "test_ssrf":            test_ssrf,
        "test_ssti":            test_ssti,
        "test_open_redirect":   test_open_redirect,
        "test_idor":            test_idor,
        "check_cors":           check_cors,
        "check_auth_headers":   check_auth_headers,
        "run_ffuf":             run_ffuf,
    }
    fn = tools.get(tool_name)
    if not fn:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        return fn(**args)
    except TypeError as e:
        return {"error": f"Bad args for {tool_name}: {e}"}
