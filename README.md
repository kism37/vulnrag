# vulnrag

An AI-powered recon and attack surface analysis tool built on a RAG pipeline. Point it at a target, it does the legwork — fingerprints the stack, hunts for secrets in JS, flags vulnerable libraries, then uses a local LLM to suggest attack paths based on real bug bounty writeups.

No API keys. Runs fully local.

![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## What it does

Recon module:
- Grabs and analyzes response headers (missing security headers, CORS misconfig, tech fingerprinting)
- Finds and fetches all JS files on the target
- Scans JS for hardcoded secrets, API keys, JWTs, S3 buckets, internal URLs, GraphQL endpoints
- Detects JS library versions and matches them against known CVEs (jQuery, React, lodash, Angular, Bootstrap, moment.js)

RAG pipeline:
- Embeds a knowledge base of real bug bounty writeups using `sentence-transformers`
- Stores vectors in Qdrant (in-memory, no setup needed)
- Takes your recon findings, retrieves the most relevant historical vulns, feeds everything to a local LLM
- Outputs ranked attack paths specific to what was found on your target

Interactive mode after the initial scan so you can ask follow-up questions about the target.

---

## Stack

| Component | Tool |
|---|---|
| LLM | Ollama (llama3.2, CPU-friendly) |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2) |
| Vector DB | Qdrant (in-memory) |
| Recon | requests, BeautifulSoup |
| Language | Python 3.10+ |

---

## Quickstart

**1. Install Ollama and pull the model**

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Run a scan**

```bash
python core/recon_rag.py
```

Enter your target URL when prompted. That's it.

---

## Usage

```
Enter target URL: https://example.com

[*] Fetching target...
[*] Analyzing headers...
[*] Finding JS files...
[*] Scanning JS for secrets and vulnerable libs...
[*] Querying RAG pipeline...

ATTACK PATH RECOMMENDATIONS
============================================================
1. ...
2. ...
```

After the initial report you drop into an interactive shell to ask follow-up questions about the target.

---

## Project structure

```
vulnrag/
  core/
    recon_rag.py      # main offensive recon tool
    rag.py            # base RAG pipeline (query mode)
  data/
    writeups/         # knowledge base (add your own writeups here)
  scripts/
    scrape_h1.py      # (coming) auto-scrape HackerOne public reports
  docs/
    architecture.md   # how the pipeline works
  requirements.txt
  README.md
```

---

## Roadmap

- [x] JS secret hunting
- [x] CVE matching for JS libraries
- [x] Header analysis
- [x] Local RAG pipeline with attack path generation
- [ ] Subdomain enumeration (subfinder integration)
- [ ] Port scanning (nmap wrapper)
- [ ] Live writeup scraper (HackerOne, ExploitDB, NVD)
- [ ] Persistent vector DB (save knowledge across runs)
- [ ] CVSS-style severity scoring
- [ ] Web UI (Flask)
- [ ] PDF/Markdown report export

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

The pipeline will pick them up automatically on next run.

---

## Disclaimer

For authorized testing only. Only run this against targets you own or have explicit permission to test. The usual.

---

## License

MIT
