"""
main.py
Single entry point for vulnrag.

Usage:
  python main.py                              # interactive mode
  python main.py https://target.com          # run full methodology
  python main.py https://target.com --skip 1,9  # skip stages
  python main.py --query "how does SSRF work"   # ask the knowledge base
  python main.py --stats                     # show knowledge base stats
"""

import sys
import argparse
import os

sys.path.insert(0, os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(
        description="vulnrag — AI-powered pentest assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://target.com
  python main.py https://target.com --skip 1,9
  python main.py --query "SSRF via webhook"
  python main.py --stats
  python main.py --ingest owasp,nvd
        """
    )
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("--skip", help="Comma-separated stage numbers to skip (e.g. 1,9)")
    parser.add_argument("--query", help="Query the knowledge base directly")
    parser.add_argument("--stats", action="store_true", help="Show knowledge base stats")
    parser.add_argument("--ingest", help="Run ingestion for specific sources (e.g. owasp,nvd)")

    args = parser.parse_args()

    if args.stats:
        from engine.retriever import stats
        s = stats()
        print(f"\nKnowledge base: {s['total']} documents")
        for source, count in sorted(s["by_source"].items(), key=lambda x: -x[1]):
            print(f"  {source:<20} {count}")
        return

    if args.ingest:
        import subprocess
        subprocess.run([sys.executable, "ingest.py", "--sources", args.ingest])
        return

    if args.query:
        from engine.llm import ask_with_rag
        print(f"\nQuerying knowledge base: {args.query}\n")
        result = ask_with_rag(args.query)
        print(result)
        return

    if args.target:
        target = args.target
    else:
        print("\nvulnrag — AI-powered pentest assistant")
        print("=" * 40)
        target = input("Target URL: ").strip()
        if not target:
            print("No target provided.")
            return

    skip = []
    if args.skip:
        skip = [s.strip() for s in args.skip.split(",")]
    else:
        print("\nSkip any stages? Enter numbers separated by commas (e.g. 1,9) or press Enter:")
        skip_input = input("> ").strip()
        if skip_input:
            skip = [s.strip() for s in skip_input.split(",")]

    from methodology.orchestrator import run
    run(target, skip=skip)


if __name__ == "__main__":
    main()
