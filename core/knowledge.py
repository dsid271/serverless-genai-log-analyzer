"""
Operational knowledge base for incident enrichment (RAG).

Stores runbooks, postmortems and security references (OWASP Top 10, CWE) in a
dedicated Chroma collection, separate from the log index. Documents come from
`POST /knowledge`, `scripts/load_owasp_cwe.py`, and from resolved
incidents that carry an operator note (closed-loop feedback). Triage analyzers retrieve the closest documents
for an incident and pass them to the LLM as reference material.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, List, Optional

import chromadb

KINDS = ("runbook", "postmortem", "reference")


class KnowledgeBase:
    def __init__(self, collection_name: str = "knowledge", path: Optional[str] = None) -> None:
        client = chromadb.PersistentClient(path=path or os.getenv("CHROMA_PATH", "./data/chroma"))
        self.collection = client.get_or_create_collection(name=collection_name)
        # Chroma's default embedding returns L2 distances; larger means less similar.
        self.max_distance = float(os.getenv("KNOWLEDGE_MAX_DISTANCE", "1.5"))

    def add(
        self,
        kind: str,
        title: str,
        content: str,
        services: Optional[List[str]] = None,
        doc_id: Optional[str] = None,
        url: Optional[str] = None,
    ) -> Dict[str, Any]:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {list(KINDS)}")
        if not title.strip() or not content.strip():
            raise ValueError("title and content are required")
        # Stable id: re-adding the same document replaces it instead of duplicating.
        doc_id = doc_id or f"{kind}-{hashlib.sha256(title.strip().encode()).hexdigest()[:16]}"
        metadata: Dict[str, Any] = {
            "kind": kind,
            "title": title.strip(),
            "services": ",".join(sorted(set(services or []))),
            "added_at": time.time(),
        }
        if url:
            metadata["url"] = url
        self.collection.upsert(ids=[doc_id], documents=[f"{title.strip()}\n\n{content.strip()}"], metadatas=[metadata])
        return {"id": doc_id, **metadata}

    def search(self, query: str, limit: int = 3) -> List[Dict[str, Any]]:
        if not query.strip() or self.collection.count() == 0:
            return []
        res = self.collection.query(query_texts=[query], n_results=min(limit, self.collection.count()))
        out: List[Dict[str, Any]] = []
        for doc_id, doc, meta, dist in zip(
            res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0]
        ):
            if dist > self.max_distance:
                continue
            out.append({
                "id": doc_id,
                "kind": meta.get("kind"),
                "title": meta.get("title"),
                "url": meta.get("url"),
                "distance": round(float(dist), 4),
                "content": doc,
            })
        return out

    def list(self, limit: int = 100) -> List[Dict[str, Any]]:
        res = self.collection.get(limit=limit, include=["metadatas"])
        return [{"id": i, **m} for i, m in zip(res["ids"], res["metadatas"])]

    def delete(self, doc_id: str) -> bool:
        if not self.collection.get(ids=[doc_id])["ids"]:
            return False
        self.collection.delete(ids=[doc_id])
        return True


def incident_query(incident: Dict[str, Any]) -> str:
    """Retrieval query built from non-sensitive incident fields."""
    details = incident.get("details") or {}
    parts = [str(incident.get("message") or "")]
    parts.append("services: " + ", ".join(details.get("sources") or []))
    parts.extend(str(s) for s in (details.get("samples") or [])[:3])
    return "\n".join(p for p in parts if p.strip())
