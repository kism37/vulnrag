"""
engine/llm.py
Ollama interface. All LLM calls go through here.
"""

import ollama
from engine.retriever import search

MODEL = "llama3.2"

SYSTEM_PROMPT = """You are a senior penetration tester and bug bounty hunter with 10+ years of experience.
You think like nahamsec, jhaddix, and tomnomnom — methodical, creative, always looking for non-obvious attack paths.
You provide specific, actionable guidance with real tool commands and payloads, not generic advice.
When you reference a technique, give the exact command or payload. Be concise but complete."""


def ask(prompt: str, system: str = None) -> str:
    """Raw LLM call."""
    messages = [{"role": "system", "content": system or SYSTEM_PROMPT}]
    messages.append({"role": "user", "content": prompt})
    try:
        resp = ollama.chat(model=MODEL, messages=messages)
        return resp["message"]["content"]
    except Exception as e:
        return f"[LLM error: {e}]"


def ask_with_rag(query: str, context: dict = None, top_k: int = 4) -> str:
    """
    RAG-augmented LLM call.
    Retrieves relevant knowledge then asks the LLM with full context.
    context: dict of recon findings to include in the prompt
    """
    # Build semantic query from the question + recon context
    search_query = query
    if context:
        tech = context.get("tech_stack", [])
        findings = context.get("header_findings", [])
        search_query = f"{query} {' '.join(tech)} {' '.join(findings[:3])}"

    results = search(search_query, top_k=top_k)

    knowledge_block = ""
    if results:
        knowledge_block = "\n\nRelevant knowledge from real bug bounty reports and CVEs:\n"
        for r in results:
            knowledge_block += f"\n[{r['source']} | score: {r['score']:.2f}] {r['title']}\n{r['content'][:400]}\n"

    context_block = ""
    if context:
        context_block = "\n\nTarget recon context:\n"
        for key, val in context.items():
            if val:
                if isinstance(val, list):
                    context_block += f"  {key}: {', '.join(str(v) for v in val[:5])}\n"
                else:
                    context_block += f"  {key}: {val}\n"

    full_prompt = f"""{context_block}{knowledge_block}

Question: {query}

Answer as a senior pentester. Be specific to this target based on the context above."""

    return ask(full_prompt)


def decide(situation: str, options: list[str], context: dict = None) -> str:
    """
    Ask the LLM to make a decision about what to do next.
    Returns the recommended action with reasoning.
    """
    results = search(situation, top_k=3)
    knowledge = "\n".join(f"- {r['title']}: {r['content'][:200]}" for r in results)

    context_str = ""
    if context:
        context_str = "\n".join(f"  {k}: {v}" for k, v in context.items() if v)

    prompt = f"""You are deciding the next best action during a penetration test.

Current situation:
{situation}

Recon context:
{context_str}

Relevant past findings from similar targets:
{knowledge}

Available options:
{chr(10).join(f'{i+1}. {opt}' for i, opt in enumerate(options))}

Which option is most likely to find a vulnerability on this specific target? 
Explain your reasoning in 2-3 sentences, then state your recommendation clearly."""

    return ask(prompt)
