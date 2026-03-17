"""
engine/embedder.py
Handles all text embedding. Single place to swap models if needed.
"""

from sentence_transformers import SentenceTransformer
from typing import Union
import numpy as np

MODEL_NAME = "all-MiniLM-L6-v2"
VECTOR_SIZE = 384

_model = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        print(f"[*] Loading embedding model ({MODEL_NAME})...")
        _model = SentenceTransformer(MODEL_NAME)
        print("[+] Embedding model ready")
    return _model


def embed(text: Union[str, list]) -> Union[list, list[list]]:
    """Embed a string or list of strings. Returns list or list of lists."""
    model = get_model()
    result = model.encode(text, show_progress_bar=False)
    if isinstance(text, str):
        return result.tolist()
    return [r.tolist() for r in result]


def embed_document(title: str, content: str) -> list:
    """Embed a full document by combining title and content."""
    return embed(f"{title}\n{content}")
