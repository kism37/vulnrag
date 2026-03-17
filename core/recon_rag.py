import re
import sys
import json
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
import ollama

# ── Config ───────────────────────────────────────────────────────────────────
COLLECTION_NAME = "bugbounty"
EMBED_MODEL     = "all-MiniLM-L6-v2"
LLM_MODEL       = "llama3.2"
HEADERS         = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) recon-rag/1.0"}

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

# ── Regex patterns for secret/endpoint hunting ────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key":      r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]",
    "Bearer Token":         r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "Private Key":          r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "JWT Token":            r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Supabase Key":         r"(?i)supabase.{0,20}['\"][a-zA-Z0-9\-_\.]{30,}['\"]",
    "Firebase URL":         r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "S3 Bucket":            r"s3\.amazonaws\.com/[a-zA-Z0-9\-_\.]+",
    "Internal URL":         r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
    "Email Address":        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "GraphQL Endpoint":     r"(?i)['\"/](graphql|gql)['\"/]",
    "API Endpoint":         r"(?i)['\"]/(api|v\d|rest|internal|admin|auth|oauth|token)[/a-zA-Z0-9\-_]*['\"]",
}

# ── Knowledge base ────────────────────────────────────────────────────────────
WRITEUPS = [
    {
        "title": "Stored XSS via SVG upload",
        "content": """Vuln class: Stored XSS. SVG file uploads without sanitization allow <script> injection.
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
        Steps: Pass {\"__proto__\":{\"admin\":true}} to merge/extend functions.
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
]


# ── RAG setup ─────────────────────────────────────────────────────────────────
def setup_rag():
    print("🔧 Loading embedding model...")
    embedder = SentenceTransformer(EMBED_MODEL)

    print("🔧 Setting up vector DB...")
    client = QdrantClient(":memory:")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )

    print("📚 Indexing writeups...")
    points = []
    for i, w in enumerate(WRITEUPS):
        text = f"{w['title']}\n{w['content']}"
        vector = embedder.encode(text).tolist()
        points.append(PointStruct(id=i, vector=vector, payload=w))
    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"✅ {len(points)} writeups indexed\n")
    return embedder, client


# ── Recon functions ───────────────────────────────────────────────────────────
def fetch_page(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        return r
    except Exception as e:
        print(f"  ❌ Failed to fetch {url}: {e}")
        return None


def analyze_headers(response):
    print("\n📡 Response Headers Analysis:")
    interesting = {}
    security_headers = {
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "Strict-Transport-Security": "HSTS",
        "X-XSS-Protection": "XSS filter",
        "Access-Control-Allow-Origin": "CORS policy",
    }

    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    # Tech fingerprint
    for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
        if h in headers:
            val = headers[h]
            interesting[h] = val
            findings.append(f"Tech fingerprint: {h} = {val}")
            print(f"  🖥️  {h}: {val}")

    # Missing security headers
    missing = []
    for header, desc in security_headers.items():
        if header.lower() not in headers:
            missing.append(f"{header} ({desc})")

    if missing:
        findings.append(f"Missing security headers: {', '.join(missing)}")
        for m in missing:
            print(f"  ⚠️  Missing: {m}")
    else:
        print("  ✅ All major security headers present")

    # CORS check
    if "access-control-allow-origin" in headers:
        val = headers["access-control-allow-origin"]
        if val == "*":
            findings.append("CORS misconfiguration: Access-Control-Allow-Origin: * (wildcard)")
            print(f"  🚨 CORS wildcard detected!")

    return findings


def find_js_files(url, soup):
    print("\n🔍 Finding JavaScript files...")
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

    print(f"  Found {len(js_files)} JS files")
    for f in js_files:
        print(f"  📄 {f}")
    return js_files


def check_lib_version(lib_name, version_str):
    """Compare version string against known vuln versions"""
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
                        f"VULNERABLE: {lib_name} {version_str} < {vuln['below']} — "
                        f"{vuln['cve']}: {vuln['desc']}"
                    )
            except:
                continue
    return findings


def analyze_js_content(js_url, content):
    findings = {
        "secrets": [],
        "endpoints": [],
        "vuln_libs": [],
    }

    # Secret hunting
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            # Deduplicate and truncate for display
            unique = list(set(matches))[:3]
            for m in unique:
                display = m[:80] + "..." if len(m) > 80 else m
                findings["secrets"].append(f"{name}: {display}")

    # Library version detection
    lib_patterns = {
        "jquery":    r"(?i)jquery[^\d]*(\d+\.\d+[\.\d]*)",
        "angular":   r"(?i)angular[^\d]*(\d+\.\d+[\.\d]*)",
        "lodash":    r"(?i)lodash[^\d]*(\d+\.\d+[\.\d]*)",
        "bootstrap": r"(?i)bootstrap[^\d]*(\d+\.\d+[\.\d]*)",
        "moment":    r"(?i)moment[^\d]*(\d+\.\d+[\.\d]*)",
        "react":     r"(?i)react[^\d]*(\d+\.\d+[\.\d]*)",
    }

    for lib, pattern in lib_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            version = matches[0]
            vuln_findings = check_lib_version(lib, version)
            if vuln_findings:
                for f in vuln_findings:
                    findings["vuln_libs"].append(f)
            else:
                findings["vuln_libs"].append(f"{lib} {version} (no known CVEs)")

    return findings


def analyze_all_js(js_files):
    print("\n🧪 Analyzing JavaScript files...")
    all_findings = {"secrets": [], "endpoints": [], "vuln_libs": []}

    for js_url in js_files[:10]:  # Cap at 10 files
        print(f"  ⏳ Fetching {js_url[:80]}...")
        r = fetch_page(js_url)
        if not r:
            continue

        findings = analyze_js_content(js_url, r.text)

        if findings["secrets"]:
            print(f"  🚨 Potential secrets found in {js_url.split('/')[-1]}:")
            for s in findings["secrets"]:
                print(f"     → {s}")
            all_findings["secrets"].extend(findings["secrets"])

        if findings["vuln_libs"]:
            for v in findings["vuln_libs"]:
                print(f"  {'🚨' if 'VULNERABLE' in v else '📦'} {v}")
            all_findings["vuln_libs"].extend(findings["vuln_libs"])

    if not all_findings["secrets"] and not all_findings["vuln_libs"]:
        print("  ✅ No obvious secrets or vulnerable libraries found")

    return all_findings


# ── RAG query with recon context ──────────────────────────────────────────────
def query_with_recon(target_url, recon_summary, embedder, qdrant_client):
    print("\n🤖 Querying RAG with recon context...")

    # Build a semantic query from recon findings
    query_text = f"attack paths for: {recon_summary}"
    query_vector = embedder.encode(query_text).tolist()

    results = qdrant_client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=4,
    ).points

    print(f"📎 Retrieved {len(results)} relevant writeups:")
    context = ""
    for r in results:
        print(f"  - {r.payload['title']} (score: {r.score:.2f})")
        context += f"\nWriteup: {r.payload['title']}\n{r.payload['content']}\n"

    prompt = f"""You are an expert penetration tester. You have just performed recon on a target.

TARGET: {target_url}

RECON FINDINGS:
{recon_summary}

RELEVANT BUG BOUNTY WRITEUPS FOR CONTEXT:
{context}

Based on the recon findings and similar past vulnerabilities, provide:
1. TOP 5 attack paths to investigate (most promising first)
2. For each: specific steps to test it on THIS target
3. Tools to use for each attack path
4. What a successful exploit would look like

Be specific and actionable. Focus on what the recon actually revealed.
"""

    print("\n" + "=" * 60)
    print("🎯 ATTACK PATH RECOMMENDATIONS")
    print("=" * 60)

    response = ollama.chat(
        model=LLM_MODEL,
        messages=[{"role": "user", "content": prompt}],
    )
    print(response["message"]["content"])
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    embedder, qdrant_client = setup_rag()

    print("=" * 60)
    print("🎯 OFFENSIVE RECON RAG")
    print("=" * 60)

    target = input("\nEnter target URL (e.g. https://example.com): ").strip()
    if not target.startswith("http"):
        target = "https://" + target

    print(f"\n🌐 Fetching {target}...")
    response = fetch_page(target)
    if not response:
        print("❌ Could not reach target. Exiting.")
        sys.exit(1)

    print(f"  ✅ Status: {response.status_code}")
    soup = BeautifulSoup(response.text, "html.parser")

    # Run recon modules
    header_findings = analyze_headers(response)
    js_files        = find_js_files(target, soup)
    js_findings     = analyze_all_js(js_files)

    # Build recon summary for RAG
    recon_parts = []

    if header_findings:
        recon_parts.append("Header findings:\n" + "\n".join(f"- {f}" for f in header_findings))

    if js_findings["secrets"]:
        recon_parts.append("Potential secrets in JS:\n" + "\n".join(f"- {s}" for s in js_findings["secrets"]))

    if js_findings["vuln_libs"]:
        vuln_only = [v for v in js_findings["vuln_libs"] if "VULNERABLE" in v]
        if vuln_only:
            recon_parts.append("Vulnerable JS libraries:\n" + "\n".join(f"- {v}" for v in vuln_only))

    recon_summary = "\n\n".join(recon_parts) if recon_parts else "No major findings from automated recon."

    # Query RAG with findings
    query_with_recon(target, recon_summary, embedder, qdrant_client)

    # Interactive follow-up
    print("\n💬 Ask follow-up questions about this target (or 'quit' to exit):")
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
            context = "\n".join(
                f"Writeup: {r.payload['title']}\n{r.payload['content']}" for r in results
            )
            prompt = f"Target: {target}\nRecon context: {recon_summary}\nRelevant writeups: {context}\nQuestion: {q}\nAnswer as a pentester:"
            resp = ollama.chat(model=LLM_MODEL, messages=[{"role": "user", "content": prompt}])
            print("\n" + resp["message"]["content"])


if __name__ == "__main__":
    main()
