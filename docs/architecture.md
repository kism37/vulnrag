# How vulnrag works

## Overview

vulnrag is a two-part system: a recon engine and a RAG pipeline. The recon engine collects raw information about a target. The RAG pipeline turns that information into actionable attack path suggestions by comparing it against a knowledge base of real bug bounty writeups.

## Recon engine

When you point vulnrag at a target URL it does three things:

**Header analysis**
Fetches the page and inspects the response headers. It looks for technology fingerprints (Server, X-Powered-By, X-Generator), checks for missing security headers (CSP, HSTS, X-Frame-Options etc.), and flags CORS misconfigurations like wildcard Access-Control-Allow-Origin.

**JS discovery and secret hunting**
Parses the HTML to find all script tags, then fetches each JS file. For every file it runs a set of regex patterns looking for hardcoded secrets — AWS keys, API tokens, JWTs, Firebase URLs, S3 buckets, internal IP addresses, GraphQL endpoints. Anything suspicious gets flagged with the file it came from.

**Library CVE matching**
While scanning JS files it also looks for version strings from known libraries (jQuery, React, Angular, lodash, Bootstrap, moment.js). If it finds a version it checks it against a local table of known CVEs and flags vulnerable ones with the CVE ID and description.

## RAG pipeline

RAG = Retrieval Augmented Generation. The idea is simple: instead of asking an LLM to reason from scratch about your target, you first pull relevant context from a knowledge base and feed it in alongside the question.

Here's the flow:

```
Writeups (text)
      |
      v
Embedding model (all-MiniLM-L6-v2)
      |
      v
Vector DB (Qdrant)         <-- stored as numerical vectors
      |
      |
Recon findings (text summary)
      |
      v
Same embedding model
      |
      v
Similarity search in Qdrant  <-- finds writeups semantically close to the findings
      |
      v
Top K writeups retrieved
      |
      v
Prompt = recon findings + retrieved writeups
      |
      v
Local LLM (llama3.2 via Ollama)
      |
      v
Attack path recommendations
```

The key insight is that the LLM never has to "remember" bug bounty knowledge from training. It gets the relevant writeups injected into the prompt at inference time. This makes the system extensible — the more writeups you add to the knowledge base, the better the suggestions get.

## Why local?

Everything runs on your machine. No API keys, no data leaving your network, no cost per query. This matters for offensive security work where you might be feeding sensitive target information into the system.

Ollama runs llama3.2 in CPU-only mode if you don't have a GPU. It's slower but it works fine on any modern laptop.

## Extending the knowledge base

The knowledge base lives in `data/writeups/`. Each file is a plain text writeup describing a vulnerability — title, class, steps, impact, fix. The embedding model converts these to vectors at startup. To add more coverage just drop in more files and restart.

Future versions will have a scraper that pulls from HackerOne public reports, ExploitDB, and NVD automatically.
