"""
engine/retriever.py
Persistent Qdrant vectorstore. Knowledge survives restarts and grows over time.
"""

import os
import uuid
from qdrant_client import QdrantClient
from qdrant_client.models import (
    VectorParams, Distance, PointStruct, Filter,
    FieldCondition, MatchValue
)
from engine.embedder import embed, embed_document, VECTOR_SIZE

COLLECTION_NAME = "vulnrag_knowledge"
VECTORSTORE_PATH = "knowledge/vectorstore"


def get_client() -> QdrantClient:
    os.makedirs(VECTORSTORE_PATH, exist_ok=True)
    return QdrantClient(path=VECTORSTORE_PATH)


def ensure_collection(client: QdrantClient):
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME not in existing:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"[+] Created vectorstore collection: {COLLECTION_NAME}")


def add_documents(documents: list[dict], source: str = "manual"):
    """
    Add documents to the vectorstore.
    Each document: {"title": str, "content": str, "tags": list (optional)}
    Skips duplicates based on title + source.
    """
    client = get_client()
    ensure_collection(client)

    added = 0
    skipped = 0

    for doc in documents:
        title = doc.get("title", "").strip()
        content = doc.get("content", "").strip()
        tags = doc.get("tags", [])

        if not title or not content:
            continue

        # Check for duplicates
        existing = client.scroll(
            collection_name=COLLECTION_NAME,
            scroll_filter=Filter(
                must=[
                    FieldCondition(key="title", match=MatchValue(value=title)),
                    FieldCondition(key="source", match=MatchValue(value=source)),
                ]
            ),
            limit=1,
        )
        if existing[0]:
            skipped += 1
            continue

        vector = embed_document(title, content)
        point = PointStruct(
            id=str(uuid.uuid4()),
            vector=vector,
            payload={
                "title": title,
                "content": content,
                "source": source,
                "tags": tags,
            }
        )
        client.upsert(collection_name=COLLECTION_NAME, points=[point])
        added += 1

    print(f"[+] Vectorstore: {added} added, {skipped} skipped (duplicates) from {source}")
    return added


def search(query: str, top_k: int = 5, source_filter: str = None) -> list[dict]:
    """
    Semantic search against the knowledge base.
    Returns list of dicts with title, content, source, score.
    """
    client = get_client()
    ensure_collection(client)

    query_vector = embed(query)

    search_filter = None
    if source_filter:
        search_filter = Filter(
            must=[FieldCondition(key="source", match=MatchValue(value=source_filter))]
        )

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=top_k,
        query_filter=search_filter,
    ).points

    return [
        {
            "title": r.payload.get("title", ""),
            "content": r.payload.get("content", ""),
            "source": r.payload.get("source", ""),
            "tags": r.payload.get("tags", []),
            "score": r.score,
        }
        for r in results
    ]


def count() -> int:
    client = get_client()
    ensure_collection(client)
    return client.count(collection_name=COLLECTION_NAME).count


def stats() -> dict:
    client = get_client()
    ensure_collection(client)
    total = client.count(collection_name=COLLECTION_NAME).count

    # Count by source
    sources = {}
    offset = None
    while True:
        batch, offset = client.scroll(
            collection_name=COLLECTION_NAME,
            limit=100,
            offset=offset,
            with_payload=["source"],
        )
        for point in batch:
            src = point.payload.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1
        if offset is None:
            break

    return {"total": total, "by_source": sources}
