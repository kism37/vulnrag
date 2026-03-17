import requests
from bs4 import BeautifulSoup
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
import ollama
import uuid

# ── Config ──────────────────────────────────────────────────────────────────
COLLECTION_NAME = "bugbounty"
EMBED_MODEL = "all-MiniLM-L6-v2"
LLM_MODEL = "llama3.2"

# ── Sample bug bounty writeups (we'll use these as our knowledge base) ──────
WRITEUPS = [
    {
        "title": "Stored XSS via SVG upload",
        "content": """
        Target: HackerOne public program
        Vuln class: Stored XSS
        Severity: High
        Description: The application allowed SVG file uploads without sanitization.
        By embedding a <script> tag inside an SVG file, an attacker could execute 
        arbitrary JavaScript in the context of any user who viewed the uploaded file.
        Steps to reproduce:
        1. Create an SVG file with <script>alert(document.cookie)</script>
        2. Upload it via the profile picture upload endpoint
        3. Share the profile link with a victim
        4. When victim visits the profile, the script executes
        Impact: Session hijacking, credential theft, account takeover
        Fix: Strip or sanitize SVG content server-side, use Content-Security-Policy
        """,
    },
    {
        "title": "IDOR on user profile endpoint",
        "content": """
        Target: Private bug bounty program
        Vuln class: IDOR (Insecure Direct Object Reference)
        Severity: High
        Description: The /api/v1/users/{id}/profile endpoint returned sensitive user 
        data without verifying that the requesting user owned the profile.
        Steps to reproduce:
        1. Log in as user A, note your user ID from any API response
        2. Change the ID in the URL to another user's ID
        3. Full profile data including email, phone, address returned
        Impact: Mass user data exposure, PII leak
        Fix: Enforce ownership checks server-side on every request
        """,
    },
    {
        "title": "SQL Injection via search parameter",
        "content": """
        Target: E-commerce platform
        Vuln class: SQL Injection
        Severity: Critical
        Description: The search endpoint passed user input directly into a SQL query
        without parameterization. Classic error-based SQLi was possible.
        Steps to reproduce:
        1. Navigate to /search?q=test
        2. Inject: /search?q=test' OR '1'='1
        3. All products returned, confirming injection
        4. Used sqlmap to dump entire database
        Payload: ' UNION SELECT username,password,3,4 FROM users--
        Impact: Full database dump, admin credentials exposed
        Fix: Use parameterized queries / prepared statements
        """,
    },
    {
        "title": "SSRF via webhook URL",
        "content": """
        Target: SaaS platform
        Vuln class: SSRF (Server Side Request Forgery)
        Severity: High
        Description: The webhook configuration feature allowed users to specify any URL.
        The server made requests to that URL without restriction, allowing internal 
        network scanning and metadata service access.
        Steps to reproduce:
        1. Set webhook URL to http://169.254.169.254/latest/meta-data/
        2. Trigger the webhook
        3. AWS instance metadata returned in webhook logs
        4. IAM credentials exposed via metadata endpoint
        Impact: Cloud credential theft, internal network access
        Fix: Whitelist allowed webhook domains, block private IP ranges
        """,
    },
    {
        "title": "JWT None Algorithm Authentication Bypass",
        "content": """
        Target: API platform
        Vuln class: Authentication Bypass
        Severity: Critical
        Description: The application accepted JWTs signed with the 'none' algorithm,
        meaning an attacker could forge tokens for any user without knowing the secret.
        Steps to reproduce:
        1. Capture a valid JWT from login
        2. Decode the token, change alg to 'none' and role to 'admin'
        3. Remove the signature, send modified token
        4. Server accepts the token and grants admin access
        Impact: Full authentication bypass, privilege escalation to admin
        Fix: Explicitly reject 'none' algorithm, whitelist allowed algorithms
        """,
    },
    {
        "title": "Open Redirect to Account Takeover",
        "content": """
        Target: OAuth-enabled web app
        Vuln class: Open Redirect / OAuth misconfiguration
        Severity: High
        Description: The redirect_uri parameter in the OAuth flow was not strictly
        validated, allowing redirection to attacker-controlled domains with the auth code.
        Steps to reproduce:
        1. Craft OAuth URL with redirect_uri=https://attacker.com/callback
        2. Send phishing link to victim
        3. Victim authenticates, auth code sent to attacker
        4. Attacker exchanges code for access token
        Impact: Account takeover without phishing credentials
        Fix: Whitelist exact redirect URIs, no partial matching
        """,
    },
]

# ── Initialize ───────────────────────────────────────────────────────────────
print("🔧 Loading embedding model...")
embedder = SentenceTransformer(EMBED_MODEL)

print("🔧 Connecting to Qdrant (in-memory)...")
client = QdrantClient(":memory:")

# ── Create collection ────────────────────────────────────────────────────────
client.create_collection(
    collection_name=COLLECTION_NAME,
    vectors_config=VectorParams(size=384, distance=Distance.COSINE),
)
print(f"✅ Collection '{COLLECTION_NAME}' created")

# ── Embed and store writeups ─────────────────────────────────────────────────
print("📚 Embedding bug bounty writeups...")
points = []
for i, writeup in enumerate(WRITEUPS):
    text = f"{writeup['title']}\n{writeup['content']}"
    vector = embedder.encode(text).tolist()
    points.append(
        PointStruct(
            id=i,
            vector=vector,
            payload={"title": writeup["title"], "content": writeup["content"]},
        )
    )

client.upsert(collection_name=COLLECTION_NAME, points=points)
print(f"✅ {len(points)} writeups indexed\n")


# ── Query function ────────────────────────────────────────────────────────────
def query_rag(user_query: str, top_k: int = 3):
    print(f"\n🔍 Query: {user_query}")
    print("─" * 60)

    # Embed the query
    query_vector = embedder.encode(user_query).tolist()

    # Search vector DB
    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=top_k,
    ).points

    # Build context from retrieved writeups
    context = ""
    print(f"📎 Retrieved {len(results)} relevant writeups:")
    for r in results:
        print(f"  - {r.payload['title']} (score: {r.score:.2f})")
        context += f"\n\nWriteup: {r.payload['title']}\n{r.payload['content']}"

    # Build prompt
    prompt = f"""You are a security researcher assistant. Based on the following bug bounty writeups, answer the user's question.

Retrieved writeups:
{context}

User question: {user_query}

Provide a concise analysis including:
1. Relevant vulnerability type(s)
2. How this attack works
3. Potential impact
4. Recommended fix
"""

    # Query LLM
    print("\n🤖 Generating response...\n")
    response = ollama.chat(
        model=LLM_MODEL,
        messages=[{"role": "user", "content": prompt}],
    )

    print("=" * 60)
    print(response["message"]["content"])
    print("=" * 60)


# ── Interactive loop ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀 Bug Bounty RAG System Ready!")
    print("Type a query (e.g. 'how does XSS work', 'SSRF attack', 'auth bypass')")
    print("Type 'quit' to exit\n")

    while True:
        query = input("Query > ").strip()
        if query.lower() in ("quit", "exit", "q"):
            break
        if query:
            query_rag(query)
