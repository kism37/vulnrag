"""
engine/recon.py
All active recon tools. Returns structured data for the methodology to use.
"""

import re
import json
import subprocess
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"
HEADERS = {"User-Agent": UA}

VULN_LIBS = {
    "jquery":    [
        {"below": "3.5.0", "cve": "CVE-2020-11022", "desc": "XSS in HTML parsing"},
        {"below": "1.12.0", "cve": "CVE-2015-9251", "desc": "XSS via cross-domain Ajax"},
    ],
    "angular":   [{"below": "1.8.0", "cve": "CVE-2019-14863", "desc": "Prototype pollution"}],
    "lodash":    [
        {"below": "4.17.21", "cve": "CVE-2021-23337", "desc": "Command injection via template"},
        {"below": "4.17.20", "cve": "CVE-2020-8203",  "desc": "Prototype pollution"},
    ],
    "bootstrap": [{"below": "4.3.1", "cve": "CVE-2019-8331", "desc": "XSS in tooltip data-template"}],
    "moment":    [{"below": "2.29.2", "cve": "CVE-2022-24785", "desc": "Path traversal in locale"}],
    "react":     [{"below": "16.0.0", "cve": "CVE-2018-6341", "desc": "XSS via SSR markup"}],
}

SECRET_PATTERNS = {
    "AWS Access Key":   r"AKIA[0-9A-Z]{16}",
    "Generic API Key":  r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]",
    "Bearer Token":     r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "JWT Token":        r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Supabase Key":     r"(?i)supabase.{0,20}['\"][a-zA-Z0-9\-_\.]{30,}['\"]",
    "Firebase URL":     r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "S3 Bucket":        r"s3\.amazonaws\.com/[a-zA-Z0-9\-_\.]+",
    "Internal URL":     r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
    "GraphQL Endpoint": r"(?i)['\"/](graphql|gql)['\"/]",
    "API Endpoint":     r"(?i)['\"]/(api|v\d|rest|internal|admin|auth|oauth|token)[/a-zA-Z0-9\-_]*['\"]",
    "Private Key":      r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
}


def _run(cmd: list, timeout: int = 60) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return f"[{cmd[0]} not found — install it]"
    except Exception as e:
        return f"[error: {e}]"


def fetch(url: str, timeout: int = 10) -> requests.Response | None:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
    except Exception:
        return None


# ── Header analysis ───────────────────────────────────────────────────────────
def analyze_headers(response: requests.Response) -> dict:
    headers = {k.lower(): v for k, v in response.headers.items()}
    result = {
        "tech_fingerprints": [],
        "missing_security_headers": [],
        "cors_issues": [],
        "raw": dict(response.headers),
    }

    for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
        if h in headers:
            result["tech_fingerprints"].append(f"{h}: {headers[h]}")

    security_headers = [
        "content-security-policy", "x-frame-options",
        "strict-transport-security", "x-content-type-options",
        "permissions-policy", "x-xss-protection",
    ]
    for h in security_headers:
        if h not in headers:
            result["missing_security_headers"].append(h)

    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        result["cors_issues"].append("Wildcard CORS: Access-Control-Allow-Origin: *")
    elif acao:
        result["cors_issues"].append(f"CORS origin: {acao}")

    return result


# ── JS analysis ───────────────────────────────────────────────────────────────
def find_js_files(url: str, soup: BeautifulSoup) -> list[str]:
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


def _version_lt(version_str: str, threshold: str) -> bool:
    try:
        v = tuple(int(x) for x in re.split(r"[.\-]", version_str)[:3])
        t = tuple(int(x) for x in threshold.split(".")[:3])
        while len(v) < 3: v = v + (0,)
        while len(t) < 3: t = t + (0,)
        return v < t
    except Exception:
        return False


def analyze_js(js_files: list[str]) -> dict:
    result = {"secrets": [], "vuln_libs": [], "endpoints": []}

    for js_url in js_files[:15]:
        r = fetch(js_url)
        if not r:
            continue
        content = r.text

        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                unique = list(set(matches))[:2]
                for m in unique:
                    display = m[:80] + "..." if len(m) > 80 else m
                    result["secrets"].append({"type": name, "value": display, "file": js_url.split("/")[-1]})

        lib_patterns = {
            "jquery": r"(?i)jquery[^\d]*(\d+\.\d+[\.\d]*)",
            "angular": r"(?i)angular[^\d]*(\d+\.\d+[\.\d]*)",
            "lodash": r"(?i)lodash[^\d]*(\d+\.\d+[\.\d]*)",
            "bootstrap": r"(?i)bootstrap[^\d]*(\d+\.\d+[\.\d]*)",
            "moment": r"(?i)moment[^\d]*(\d+\.\d+[\.\d]*)",
            "react": r"(?i)react[^\d]*(\d+\.\d+[\.\d]*)",
        }
        for lib, pat in lib_patterns.items():
            matches = re.findall(pat, content)
            if matches:
                version = matches[0]
                if lib in VULN_LIBS:
                    for vuln in VULN_LIBS[lib]:
                        if _version_lt(version, vuln["below"]):
                            result["vuln_libs"].append({
                                "lib": lib, "version": version,
                                "cve": vuln["cve"], "desc": vuln["desc"],
                            })

    return result


# ── Subdomain enumeration ─────────────────────────────────────────────────────
def enumerate_subdomains(domain: str, timeout: int = 90) -> list[str]:
    out = _run(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    if "[" in out:
        return []
    return [s.strip() for s in out.strip().splitlines() if s.strip()]


def crt_sh(domain: str) -> list[str]:
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers=HEADERS
        )
        if r.status_code != 200:
            return []
        certs = r.json()
        domains = set()
        for cert in certs[:100]:
            for d in cert.get("name_value", "").split("\n"):
                d = d.strip().lstrip("*.")
                if domain in d:
                    domains.add(d)
        return list(domains)
    except Exception:
        return []


# ── Port scanning ─────────────────────────────────────────────────────────────
COMMON_PORTS = "21,22,23,25,53,80,110,143,443,445,3000,3306,3389,4443,5432,6379,8080,8443,8888,9200,27017"

def scan_ports(host: str, timeout: int = 120) -> list[dict]:
    host = re.sub(r"https?://", "", host).split("/")[0]
    out = _run(
        ["nmap", "-sV", "--open", "-p", COMMON_PORTS, "-T4", "--host-timeout", "60s", host],
        timeout=timeout
    )
    ports = []
    for line in out.splitlines():
        match = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
        if match:
            port, proto, service, version = match.groups()
            ports.append({
                "port": port,
                "proto": proto,
                "service": service,
                "version": version.strip(),
            })
    return ports


# ── API schema checks ─────────────────────────────────────────────────────────
API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
    "/openapi.json", "/api/v1/", "/graphql", "/graphiql",
    "/.well-known/openid-configuration", "/api/swagger.json",
]

def check_api_schemas(base_url: str) -> list[dict]:
    found = []
    for path in API_PATHS:
        r = fetch(urljoin(base_url, path))
        if r and r.status_code == 200 and len(r.content) > 100:
            found.append({"path": path, "size": len(r.content), "status": r.status_code})
    return found


def check_graphql_introspection(base_url: str) -> bool:
    try:
        r = requests.post(
            urljoin(base_url, "/graphql"),
            json={"query": "{__schema{types{name}}}"},
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=8, verify=False
        )
        return r.status_code == 200 and "__schema" in r.text
    except Exception:
        return False


# ── Exposed files check ───────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.env.production", "/.env.local", "/.env.backup",
    "/config.json", "/config.yml", "/app.yaml",
    "/.aws/credentials", "/credentials",
    "/actuator", "/actuator/env", "/actuator/heapdump",
    "/server-status", "/phpinfo.php",
]

def check_exposed_files(base_url: str) -> list[dict]:
    found = []
    for path in SENSITIVE_PATHS:
        r = fetch(urljoin(base_url, path))
        if r and r.status_code == 200 and len(r.content) > 20:
            snippet = r.text[:120].replace("\n", " ").strip()
            found.append({"path": path, "snippet": snippet, "size": len(r.content)})
    return found


# ── S3 bucket enumeration ─────────────────────────────────────────────────────
def check_s3_buckets(domain: str) -> list[dict]:
    base = domain.split(".")[0]
    candidates = [
        domain, domain.replace(".", "-"), base,
        f"{base}-backup", f"{base}-dev", f"{base}-staging",
        f"{base}-assets", f"{base}-static", f"{base}-uploads",
    ]
    found = []
    for bucket in candidates:
        try:
            r = requests.get(f"https://{bucket}.s3.amazonaws.com", timeout=5)
            if r.status_code == 200:
                found.append({"bucket": bucket, "status": "public"})
            elif r.status_code == 403:
                found.append({"bucket": bucket, "status": "exists_private"})
        except Exception:
            pass
    return found


# ── Wayback Machine ───────────────────────────────────────────────────────────
INTERESTING_KEYWORDS = [
    "api", "admin", "login", "auth", "token", "key", "secret",
    "upload", "backup", "config", ".env", ".sql", ".json", "graphql",
]

def wayback_urls(domain: str, limit: int = 100) -> list[str]:
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}",
            timeout=15
        )
        if r.status_code != 200:
            return []
        urls = [u[0] for u in r.json()[1:]]
        return [u for u in urls if any(k in u.lower() for k in INTERESTING_KEYWORDS)]
    except Exception:
        return []
