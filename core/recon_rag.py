import re
import sys
import json
import subprocess
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
import ollama
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Config ───────────────────────────────────────────────────────────────────
COLLECTION_NAME = "bugbounty"
EMBED_MODEL     = "all-MiniLM-L6-v2"
LLM_MODEL       = "llama3.2"
HEADERS         = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) vulnrag/2.0"}

# ── Known vulnerable JS library versions ─────────────────────────────────────
VULN_LIBS = {
    "jquery": [
        {"below": "1.12.0", "cve": "CVE-2015-9251", "desc": "XSS via cross-domain Ajax"},
        {"below": "3.5.0",  "cve": "CVE-2020-11022", "desc": "XSS in HTML parsing"},
        {"below": "3.5.0",  "cve": "CVE-2020-11023", "desc": "XSS via passing HTML to $()"},
    ],
    "angular": [
        {"below": "1.8.0", "cve": "CVE-2019-14863", "desc": "Prototype pollution"},
        {"below": "1.6.0", "cve": "CVE-2016-10726", "desc": "XSS via SVG animations"},
    ],
    "lodash": [
        {"below": "4.17.21", "cve": "CVE-2021-23337", "desc": "Command injection via template"},
        {"below": "4.17.20", "cve": "CVE-2020-8203",  "desc": "Prototype pollution"},
    ],
    "bootstrap": [
        {"below": "3.4.1", "cve": "CVE-2019-8331", "desc": "XSS in tooltip/popover data-template"},
        {"below": "4.3.1", "cve": "CVE-2019-8331", "desc": "XSS in tooltip/popover data-template"},
    ],
    "moment": [
        {"below": "2.29.2", "cve": "CVE-2022-24785", "desc": "Path traversal in locale loading"},
    ],
    "react": [
        {"below": "16.0.0", "cve": "CVE-2018-6341", "desc": "XSS via SSR markup injection"},
    ],
}

# ── Secret patterns ───────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Generic API Key":   r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]",
    "Bearer Token":      r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "Private Key":       r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "JWT Token":         r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Supabase Key":      r"(?i)supabase.{0,20}['\"][a-zA-Z0-9\-_\.]{30,}['\"]",
    "Firebase URL":      r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "S3 Bucket":         r"s3\.amazonaws\.com/[a-zA-Z0-9\-_\.]+",
    "Internal URL":      r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
    "GraphQL Endpoint":  r"(?i)['\"/](graphql|gql)['\"/]",
    "API Endpoint":      r"(?i)['\"]/(api|v\d|rest|internal|admin|auth|oauth|token)[/a-zA-Z0-9\-_]*['\"]",
}

# ── Knowledge base ────────────────────────────────────────────────────────────
WRITEUPS = [
    {
        "title": "Stored XSS via SVG upload",
        "content": """Vuln class: Stored XSS. SVG file uploads without sanitization allow script injection.
        Steps: Upload SVG with embedded script, share link, victim executes JS.
        Impact: Session hijacking, credential theft, account takeover.
        Fix: Sanitize SVG server-side, use Content-Security-Policy.""",
    },
    {
        "title": "IDOR on user profile endpoint",
        "content": """Vuln class: IDOR. /api/v1/users/{id}/profile returned data without ownership check.
        Steps: Change ID in URL to another user's ID, full profile returned.
        Impact: Mass PII leak. Fix: Enforce ownership checks on every request.""",
    },
    {
        "title": "SQL Injection via search parameter",
        "content": """Vuln class: SQL Injection. Search endpoint passes input directly into SQL query.
        Payload: ' UNION SELECT username,password FROM users--
        Impact: Full database dump. Fix: Use parameterized queries.""",
    },
    {
        "title": "SSRF via webhook URL",
        "content": """Vuln class: SSRF. Webhook URL not restricted, server fetches attacker URLs.
        Steps: Set webhook to http://169.254.169.254/latest/meta-data/
        Impact: AWS IAM credential theft. Fix: Whitelist domains, block private IPs.""",
    },
    {
        "title": "JWT None Algorithm Authentication Bypass",
        "content": """Vuln class: Auth Bypass. App accepts JWTs with alg=none, allowing token forgery.
        Steps: Change alg to none, set role=admin, remove signature.
        Impact: Full auth bypass, privilege escalation. Fix: Reject none algorithm.""",
    },
    {
        "title": "Open Redirect to Account Takeover",
        "content": """Vuln class: Open Redirect / OAuth misconfiguration. redirect_uri not validated.
        Steps: Craft OAuth URL with attacker redirect_uri, victim auth code captured.
        Impact: Account takeover. Fix: Whitelist exact redirect URIs.""",
    },
    {
        "title": "Prototype Pollution via JavaScript library",
        "content": """Vuln class: Prototype Pollution. Vulnerable lodash/jQuery versions allow __proto__ manipulation.
        Steps: Pass {"__proto__":{"admin":true}} to merge/extend functions.
        Impact: Privilege escalation, auth bypass, RCE in some Node.js contexts.
        Fix: Update libraries, validate merge inputs.""",
    },
    {
        "title": "XSS via outdated jQuery",
        "content": """Vuln class: XSS. jQuery < 3.5.0 vulnerable to XSS via HTML parsing (CVE-2020-11022).
        Steps: Pass crafted HTML string to $(), script executes.
        Impact: Session hijacking, DOM manipulation. Fix: Upgrade jQuery to 3.5.0+.""",
    },
    {
        "title": "Hardcoded API Key in JavaScript",
        "content": """Vuln class: Secret Exposure. API keys, tokens hardcoded in client-side JS.
        Steps: View source or JS files, grep for key patterns, use key to access API.
        Impact: Unauthorized API access, data breach. Fix: Move secrets server-side, rotate exposed keys.""",
    },
    {
        "title": "GraphQL Introspection Enabled",
        "content": """Vuln class: Information Disclosure. GraphQL introspection exposes full schema.
        Steps: POST {__schema{types{name}}} to /graphql endpoint.
        Impact: Full API schema exposed, facilitates targeted attacks. Fix: Disable introspection in production.""",
    },
    {
        "title": "Subdomain Takeover",
        "content": """Vuln class: Subdomain Takeover. DNS record points to deprovisioned cloud resource.
        Steps: Enumerate subdomains, find CNAME pointing to unclaimed resource (S3, GitHub Pages, Heroku).
        Claim the resource on the provider, serve malicious content.
        Impact: Phishing, cookie theft, reputation damage. Fix: Remove dangling DNS records.""",
    },
    {
        "title": "Open Ports Leading to Admin Panel Exposure",
        "content": """Vuln class: Misconfiguration. Internal admin panels accessible on non-standard ports.
        Steps: Scan target for open ports, find admin panel on port 8080/8443/9000.
        Panel accessible without auth or with default credentials.
        Impact: Full admin access, data exfil. Fix: Firewall internal services, require auth.""",
    },
    {
        "title": "Sensitive Data in robots.txt and sitemap",
        "content": """Vuln class: Information Disclosure. robots.txt reveals hidden endpoints.
        Steps: Fetch /robots.txt and /sitemap.xml, note disallowed paths.
        Visit those paths directly to find admin panels, staging environments, internal APIs.
        Impact: Attack surface expansion. Fix: Don't list sensitive paths in robots.txt.""",
    },
]


# ── RAG setup ─────────────────────────────────────────────────────────────────
def setup_rag():
    print("[*] Loading embedding model...")
    embedder = SentenceTransformer(EMBED_MODEL)
    print("[*] Setting up vector DB...")
    client = QdrantClient(":memory:")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )
    points = []
    for i, w in enumerate(WRITEUPS):
        text = f"{w['title']}\n{w['content']}"
        vector = embedder.encode(text).tolist()
        points.append(PointStruct(id=i, vector=vector, payload=w))
    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"[+] {len(points)} writeups indexed\n")
    return embedder, client


# ── Module 1: Subdomain Enumeration ──────────────────────────────────────────
def enumerate_subdomains(domain):
    print(f"\n[*] Enumerating subdomains for {domain}...")
    subdomains = []
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            subdomains = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
            print(f"[+] Found {len(subdomains)} subdomains")
            for s in subdomains[:20]:  # show first 20
                print(f"    {s}")
            if len(subdomains) > 20:
                print(f"    ... and {len(subdomains) - 20} more")
        else:
            print(f"[-] subfinder error: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("[-] subfinder timed out after 60s")
    except FileNotFoundError:
        print("[-] subfinder not found, skipping")
    return subdomains


# ── Module 2: Port Scanning ───────────────────────────────────────────────────
def scan_ports(host, quick=True):
    print(f"\n[*] Port scanning {host}...")
    open_ports = []
    try:
        # Quick scan: top 1000 ports. Set quick=False for full range.
        cmd = ["nmap", "-T4", "--open", "-oN", "-", host]
        if quick:
            cmd = ["nmap", "-T4", "--open", "--top-ports", "1000", "-sV", "-oN", "-", host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_proto = parts[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    entry = {"port": port_proto, "service": service, "version": version}
                    open_ports.append(entry)
                    print(f"    {port_proto:20} {service:15} {version}")
            if not open_ports:
                print("    No open ports found in top 1000")
        else:
            print(f"[-] nmap error: {result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        print("[-] nmap timed out after 120s")
    except FileNotFoundError:
        print("[-] nmap not found, skipping")
    return open_ports


# ── Module 3: HackerOne Public Report Scraper ────────────────────────────────
def scrape_hackerone(keyword, max_results=5):
    print(f"\n[*] Searching HackerOne public reports for: {keyword}")
    writeups = []
    try:
        url = f"https://hackerone.com/hacktivity?querystring={keyword}"
        r = requests.get(url, headers=HEADERS, timeout=15)
        soup = BeautifulSoup(r.text, "html.parser")

        # HackerOne's hacktivity page is JS-rendered so we fall back to their
        # public GraphQL API for disclosed reports
        api_url = "https://hackerone.com/graphql"
        query = """
        {
          search(query: "%s", product_area: "hacktivity", first: %d) {
            nodes {
              ... on HacktivityDocument {
                report {
                  title
                  vulnerability_information
                  severity_rating
                  disclosed_at
                }
              }
            }
          }
        }
        """ % (keyword, max_results)

        resp = requests.post(
            api_url,
            json={"query": query},
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=15
        )

        if resp.status_code == 200:
            data = resp.json()
            nodes = data.get("data", {}).get("search", {}).get("nodes", [])
            for node in nodes:
                report = node.get("report")
                if report and report.get("title"):
                    writeups.append({
                        "title": report["title"],
                        "content": f"Severity: {report.get('severity_rating', 'unknown')}\n{report.get('vulnerability_information', '')[:500]}"
                    })
                    print(f"    [+] {report['title'][:80]}")

        # Fallback: scrape public writeup repos via GitHub search API
        if not writeups:
            print("    [*] H1 API returned no results, trying GitHub writeup repos...")
            gh_url = f"https://api.github.com/search/repositories?q={keyword}+bugbounty+writeup&sort=stars&per_page=3"
            gh_resp = requests.get(gh_url, headers=HEADERS, timeout=10)
            if gh_resp.status_code == 200:
                repos = gh_resp.json().get("items", [])
                for repo in repos:
                    writeups.append({
                        "title": repo["full_name"],
                        "content": repo.get("description", "") or ""
                    })
                    print(f"    [+] GitHub: {repo['full_name']}")

    except Exception as e:
        print(f"    [-] Scraper error: {e}")

    return writeups


# ── Header Analysis ───────────────────────────────────────────────────────────
def analyze_headers(response):
    print("\n[*] Analyzing headers...")
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
        if h in headers:
            findings.append(f"Tech fingerprint: {h} = {headers[h]}")
            print(f"    tech: {h} = {headers[h]}")

    missing = []
    for h in ["content-security-policy", "x-frame-options", "strict-transport-security",
              "x-content-type-options", "x-xss-protection"]:
        if h not in headers:
            missing.append(h)

    if missing:
        findings.append(f"Missing security headers: {', '.join(missing)}")
        print(f"    missing headers: {', '.join(missing)}")

    if headers.get("access-control-allow-origin") == "*":
        findings.append("CORS misconfiguration: wildcard Access-Control-Allow-Origin")
        print("    CORS wildcard detected")

    return findings


# ── JS Analysis ───────────────────────────────────────────────────────────────
def fetch_page(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=10, verify=False)
    except:
        return None


def find_js_files(url, soup):
    print("\n[*] Finding JS files...")
    js_files = []
    base = "{0.scheme}://{0.netloc}".format(urlparse(url))
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            js_files.append(src)
        elif src.startswith("//"):
            js_files.append("https:" + src)
        else:
            js_files.append(urljoin(base, src))
    print(f"    found {len(js_files)} JS files")
    return js_files


def check_lib_version(lib_name, version_str):
    findings = []
    try:
        parts = [int(x) for x in re.split(r"[.\-]", version_str)[:3]]
        while len(parts) < 3:
            parts.append(0)
        version_tuple = tuple(parts)
    except:
        return findings
    if lib_name.lower() in VULN_LIBS:
        for vuln in VULN_LIBS[lib_name.lower()]:
            try:
                threshold = tuple(int(x) for x in vuln["below"].split(".")[:3])
                if version_tuple < threshold:
                    findings.append(
                        f"VULNERABLE: {lib_name} {version_str} < {vuln['below']} — {vuln['cve']}: {vuln['desc']}"
                    )
            except:
                continue
    return findings


def analyze_js_files(js_files):
    print("\n[*] Analyzing JS files...")
    all_findings = {"secrets": [], "vuln_libs": []}
    for js_url in js_files[:10]:
        r = fetch_page(js_url)
        if not r:
            continue
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, r.text)
            if matches:
                display = list(set(matches))[0][:80]
                all_findings["secrets"].append(f"{name}: {display}")
                print(f"    [!] {name} in {js_url.split('/')[-1]}")

        lib_patterns = {
            "jquery": r"(?i)jquery[^\d]*(\d+\.\d+[\.\d]*)",
            "angular": r"(?i)angular[^\d]*(\d+\.\d+[\.\d]*)",
            "lodash": r"(?i)lodash[^\d]*(\d+\.\d+[\.\d]*)",
            "bootstrap": r"(?i)bootstrap[^\d]*(\d+\.\d+[\.\d]*)",
            "moment": r"(?i)moment[^\d]*(\d+\.\d+[\.\d]*)",
            "react": r"(?i)react[^\d]*(\d+\.\d+[\.\d]*)",
        }
        for lib, pattern in lib_patterns.items():
            matches = re.findall(pattern, r.text)
            if matches:
                vulns = check_lib_version(lib, matches[0])
                for v in vulns:
                    all_findings["vuln_libs"].append(v)
                    print(f"    [!] {v}")

    if not all_findings["secrets"] and not all_findings["vuln_libs"]:
        print("    nothing suspicious found")
    return all_findings


# ── RAG query ─────────────────────────────────────────────────────────────────
def query_rag(target, recon_summary, embedder, qdrant_client, extra_writeups=None):
    print("\n[*] Querying RAG pipeline...")

    # Dynamically add any scraped writeups
    if extra_writeups:
        existing_count = len(WRITEUPS)
        new_points = []
        for i, w in enumerate(extra_writeups):
            text = f"{w['title']}\n{w['content']}"
            vector = embedder.encode(text).tolist()
            new_points.append(PointStruct(id=existing_count + i, vector=vector, payload=w))
        if new_points:
            qdrant_client.upsert(collection_name=COLLECTION_NAME, points=new_points)
            print(f"[+] Added {len(new_points)} live writeups to knowledge base")

    query_vector = embedder.encode(recon_summary).tolist()
    results = qdrant_client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=5,
    ).points

    print(f"[+] Retrieved {len(results)} relevant writeups:")
    context = ""
    for r in results:
        print(f"    {r.payload['title']} (score: {r.score:.2f})")
        context += f"\nWriteup: {r.payload['title']}\n{r.payload['content']}\n"

    prompt = f"""You are an expert penetration tester. You have just completed recon on a target.

TARGET: {target}

RECON FINDINGS:
{recon_summary}

RELEVANT BUG BOUNTY WRITEUPS:
{context}

Based on the recon findings and similar past vulnerabilities, provide:
1. TOP 5 attack paths to investigate (most promising first)
2. For each: specific steps to test on THIS target
3. Tools to use
4. What a successful exploit would look like

Be specific and actionable. Focus on what the recon actually revealed.
"""

    print("\n" + "=" * 60)
    print("ATTACK PATH RECOMMENDATIONS")
    print("=" * 60)
    response = ollama.chat(model=LLM_MODEL, messages=[{"role": "user", "content": prompt}])
    print(response["message"]["content"])
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    embedder, qdrant_client = setup_rag()

    print("=" * 60)
    print("vulnrag v2.0")
    print("=" * 60)

    target = input("\nEnter target URL (e.g. https://example.com): ").strip()
    if not target.startswith("http"):
        target = "https://" + target

    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path

    # ── Run all recon modules ─────────────────────────────────────────────────
    print(f"\n[*] Starting recon on {target}")

    # 1. Page fetch + header analysis + JS
    print(f"\n[*] Fetching {target}...")
    response = fetch_page(target)
    header_findings = []
    js_findings = {"secrets": [], "vuln_libs": []}

    if response:
        print(f"[+] Status: {response.status_code}")
        soup = BeautifulSoup(response.text, "html.parser")
        header_findings = analyze_headers(response)
        js_files = find_js_files(target, soup)
        js_findings = analyze_js_files(js_files)
    else:
        print("[-] Could not reach target")

    # 2. Subdomain enumeration
    subdomains = enumerate_subdomains(domain)

    # 3. Port scan on main domain
    open_ports = scan_ports(domain)

    # 4. Scrape live HackerOne writeups based on tech fingerprint
    tech_keyword = "web application"
    for f in header_findings:
        if "x-powered-by" in f.lower() or "server" in f.lower():
            tech_keyword = f.split("=")[-1].strip().split("/")[0]
            break
    live_writeups = scrape_hackerone(tech_keyword)

    # ── Build recon summary ───────────────────────────────────────────────────
    parts = []

    if header_findings:
        parts.append("Header findings:\n" + "\n".join(f"- {x}" for x in header_findings))

    if js_findings["secrets"]:
        parts.append("Potential secrets in JS:\n" + "\n".join(f"- {x}" for x in js_findings["secrets"]))

    if js_findings["vuln_libs"]:
        vulns = [v for v in js_findings["vuln_libs"] if "VULNERABLE" in v]
        if vulns:
            parts.append("Vulnerable JS libraries:\n" + "\n".join(f"- {v}" for v in vulns))

    if subdomains:
        parts.append(f"Subdomains found ({len(subdomains)} total):\n" + "\n".join(f"- {s}" for s in subdomains[:10]))

    if open_ports:
        port_lines = [f"- {p['port']} {p['service']} {p['version']}" for p in open_ports]
        parts.append("Open ports:\n" + "\n".join(port_lines))

    recon_summary = "\n\n".join(parts) if parts else "No significant findings from automated recon."

    # ── RAG query ─────────────────────────────────────────────────────────────
    query_rag(target, recon_summary, embedder, qdrant_client, extra_writeups=live_writeups)

    # ── Interactive follow-up ─────────────────────────────────────────────────
    print("\nAsk follow-up questions about this target (or 'quit' to exit):")
    while True:
        q = input("\nQuery > ").strip()
        if q.lower() in ("quit", "exit", "q"):
            break
        if q:
            full_query = f"Target: {target}\nRecon: {recon_summary}\nQuestion: {q}"
            query_vector = embedder.encode(full_query).tolist()
            results = qdrant_client.query_points(
                collection_name=COLLECTION_NAME,
                query=query_vector,
                limit=3,
            ).points
            context = "\n".join(f"Writeup: {r.payload['title']}\n{r.payload['content']}" for r in results)
            prompt = f"Target: {target}\nRecon: {recon_summary}\nRelevant writeups: {context}\nQuestion: {q}\nAnswer as a pentester:"
            resp = ollama.chat(model=LLM_MODEL, messages=[{"role": "user", "content": prompt}])
            print("\n" + resp["message"]["content"])


if __name__ == "__main__":
    main()
