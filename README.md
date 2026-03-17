# ragent

An AI-powered recon and attack surface analysis tool built on a RAG pipeline. Point it at a target, it fingerprints the stack, hunts for secrets in JS files, flags vulnerable libraries, maps the attack surface, then uses a local LLM to suggest attack paths based on a continuously updated knowledge base of real bug bounty reports and CVEs.

Runs fully local. No API keys required.

![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## What it does

**Recon:**
- Response header analysis — tech fingerprinting, missing security headers, CORS misconfigs
- Finds and fetches all JS files, scans for hardcoded secrets, API keys, JWTs, S3 buckets, internal URLs
- Detects JS library versions and matches against known CVEs (jQuery, React, lodash, Angular, Bootstrap, moment.js)
- Subdomain enumeration via subfinder + certificate transparency (crt.sh)
- Port scanning with service detection via nmap
- Historical URL discovery via Wayback Machine
- Exposed API schema detection (Swagger, OpenAPI, GraphQL introspection)
- S3 bucket enumeration and exposed file checks (.env, actuator, credentials)

**10-stage methodology pipeline:**
1. Passive recon and OSINT
2. Active recon and fingerprinting
3. Attack surface mapping
4. Authentication and session testing
5. Injection testing (SQLi, XSS, SSTI, SSRF, XXE)
6. Access control and IDOR
7. API abuse
8. Business logic flaws
9. Cloud misconfiguration
10. Report generation

**Knowledge base (continuously updated):**
- HackerOne public disclosed reports
- ExploitDB web exploits
- NVD/CVE feeds (last 30 days, high/critical only)
- Security blogs — PortSwigger, ProjectDiscovery, Assetnote, HackTricks
- GitHub Security Advisories
- OWASP Top 10 and Cheat Sheet Series

At every stage the LLM pulls relevant docs from the knowledge base and gives target-specific guidance — not generic advice.

---

## Stack

| Component | Tool |
|---|---|
| LLM | Ollama (llama3.2, runs on CPU) |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2) |
| Vector DB | Qdrant (persistent, on disk) |
| Recon | requests, BeautifulSoup, subfinder, nmap |
| Language | Python 3.10+ |

---

## Quickstart

**1. Install system dependencies**

```bash
# Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2

# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Python deps
pip install -r requirements.txt
```

**2. Seed the knowledge base**

```bash
# Start with OWASP (fast, no rate limits)
python ingest.py --sources owasp

# Then the rest
python ingest.py --sources blogs,nvd,exploitdb

# Check what's indexed
python ingest.py --stats
```

**3. Run a scan**

```bash
# Full 10-stage methodology
python main.py https://target.com

# Skip specific stages
python main.py https://target.com --skip 1,9

# Quick recon only (stages 1-3)
python main.py https://target.com --skip 4,5,6,7,8,9

# Query the knowledge base directly
python main.py --query "how does JWT algorithm confusion work"
```

---

## Knowledge base sources

Run ingestion for any combination of sources:

```bash
python ingest.py --sources owasp,blogs,nvd,exploitdb,h1,github
```

| Source | Flag | What it pulls |
|---|---|---|
| OWASP | `owasp` | Top 10 + 6 cheat sheets |
| Security blogs | `blogs` | PortSwigger, ProjectDiscovery, Assetnote, HackTricks |
| NVD | `nvd` | Last 30 days, high/critical, web CVEs only |
| ExploitDB | `exploitdb` | Web application exploits |
| HackerOne | `h1` | Public disclosed reports |
| GitHub | `github` | Security advisories |

Set up a weekly cron to keep it fresh:

```bash
0 3 * * 1 cd ~/vulnrag && python ingest.py >> logs/ingest.log 2>&1
```

---

## Project structure

```
vulnrag/
  engine/
    embedder.py       embedding model (singleton)
    retriever.py      persistent Qdrant vectorstore
    llm.py            Ollama interface + RAG-augmented calls
    recon.py          all active recon tools
  knowledge/
    scrapers/         one scraper per source
    vectorstore/      persistent DB (gitignored)
  methodology/
    stages/           s01 through s10, one file per stage
    orchestrator.py   runs all stages, passes context between them
    human_gate.py     permission system for intrusive actions
    context.py        shared TargetContext across all stages
  core/
    rag.py            original basic RAG demo
    recon_rag.py      original recon + RAG tool
  ingest.py           knowledge base ingestion runner
  main.py             entry point
  docs/
    architecture.md   how the pipeline works
```

---

## Human-in-the-loop

Active and intrusive actions ask for approval before running. At startup you choose:

```
Approval mode:
[1] Ask before every active action
[2] Auto-approve scans, ask only before sending payloads  ← recommended
[3] Auto-approve everything
```

---

## Adding your own writeups

Drop `.txt` files into `data/writeups/` in this format:

```
Title: SSRF via image upload
Vuln class: SSRF
Severity: High
Description: ...
Steps: ...
Impact: ...
Fix: ...
```

They get picked up automatically on next run.

---

## Disclaimer

For authorized testing only. Only run against targets you own or have explicit written permission to test.

---

## License

MIT
