"""
ingest.py
Runs all knowledge scrapers and loads results into the persistent vectorstore.
Run manually: python ingest.py
Run on a schedule: cron, systemd timer, or GitHub Actions workflow.

Usage:
  python ingest.py                  # run all sources
  python ingest.py --sources h1,nvd # run specific sources
  python ingest.py --stats          # show vectorstore stats
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from engine.retriever import add_documents, stats


SCRAPERS = {
    "h1": {
        "name": "HackerOne",
        "module": "knowledge.scrapers.hackerone",
        "fn": "scrape",
        "source_tag": "hackerone",
    },
    "exploitdb": {
        "name": "ExploitDB",
        "module": "knowledge.scrapers.exploitdb",
        "fn": "scrape",
        "source_tag": "exploitdb",
    },
    "nvd": {
        "name": "NVD / CVE",
        "module": "knowledge.scrapers.nvd",
        "fn": "scrape",
        "source_tag": "nvd",
    },
    "blogs": {
        "name": "Security blogs",
        "module": "knowledge.scrapers.blogs",
        "fn": "scrape",
        "source_tag": "blogs",
    },
    "github": {
        "name": "GitHub advisories",
        "module": "knowledge.scrapers.github_advisories",
        "fn": "scrape",
        "source_tag": "github",
    },
    "owasp": {
        "name": "OWASP",
        "module": "knowledge.scrapers.owasp",
        "fn": "scrape",
        "source_tag": "owasp",
    },
}


def run_scraper(key: str) -> int:
    config = SCRAPERS[key]
    print(f"\n{'='*50}")
    print(f"Source: {config['name']}")
    print(f"{'='*50}")

    try:
        import importlib
        mod = importlib.import_module(config["module"])
        fn = getattr(mod, config["fn"])
        documents = fn()

        if not documents:
            print(f"[!] No documents returned from {config['name']}")
            return 0

        added = add_documents(documents, source=config["source_tag"])
        return added

    except Exception as e:
        print(f"[!] {config['name']} failed: {e}")
        import traceback
        traceback.print_exc()
        return 0


def show_stats():
    print("\nVectorstore statistics:")
    print("=" * 40)
    s = stats()
    print(f"Total documents: {s['total']}")
    print("\nBy source:")
    for source, count in sorted(s["by_source"].items(), key=lambda x: -x[1]):
        print(f"  {source:<20} {count} documents")


def main():
    parser = argparse.ArgumentParser(description="vulnrag knowledge ingestion")
    parser.add_argument(
        "--sources",
        help=f"Comma-separated sources to run. Options: {', '.join(SCRAPERS.keys())}. Default: all",
        default="all",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show vectorstore stats and exit",
    )
    args = parser.parse_args()

    if args.stats:
        show_stats()
        return

    if args.sources == "all":
        sources_to_run = list(SCRAPERS.keys())
    else:
        sources_to_run = [s.strip() for s in args.sources.split(",")]
        invalid = [s for s in sources_to_run if s not in SCRAPERS]
        if invalid:
            print(f"Unknown sources: {invalid}")
            print(f"Valid options: {list(SCRAPERS.keys())}")
            sys.exit(1)

    print(f"\nvulnrag knowledge ingestion")
    print(f"Sources: {', '.join(sources_to_run)}")

    total_added = 0
    for key in sources_to_run:
        total_added += run_scraper(key)

    print(f"\n{'='*50}")
    print(f"Ingestion complete. Total new documents added: {total_added}")
    show_stats()


if __name__ == "__main__":
    main()
