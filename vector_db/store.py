import os
import uuid
from typing import List, Dict, Any, Optional
import chromadb


def _clean_metadata(md: Dict[str, Any]) -> Dict[str, Any]:
    """Chroma only accepts scalar metadata values (str/int/float/bool).
    Flatten lists, drop empties and Nones."""
    out: Dict[str, Any] = {}
    for k, v in md.items():
        if isinstance(v, (list, tuple, set)):
            if not v:
                continue                          # empty list -> omit key entirely
            out[k] = ",".join(map(str, v))
        elif isinstance(v, bool) or isinstance(v, (str, int, float)):
            out[k] = v
        elif v is None:
            continue
        elif isinstance(v, dict):
            continue                              # nested dicts unsupported
        else:
            out[k] = str(v)
    return out


class VectorStore:
    """
    Abstractions for Vector DB operations (ChromaDB).
    Uses Chroma's built-in local embedding function (no external API calls).
    """
    def __init__(self, collection_name: str = "logs"):
        self.chroma_client = chromadb.PersistentClient(
            path=os.getenv("CHROMA_PATH", "./data/chroma")
        )
        self.collection = self.chroma_client.get_or_create_collection(
            name=collection_name
        )

    def add_logs(self, logs: List[Dict[str, Any]]):
        """Indexes processed logs into the vector store."""
        if not logs:
            return

        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        ids: List[str] = []

        for log in logs:
            doc = log.get("message") or log.get("raw") or str(log)
            documents.append(str(doc))
            metadatas.append(_clean_metadata(log))
            ids.append(f"{log.get('request_id', 'log')}-{uuid.uuid4().hex[:12]}")

        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids,
        )

    def search_logs(
        self,
        query: str,
        n_results: int = 5,
        where_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Semantic search for relevant logs."""
        kwargs: Dict[str, Any] = {
            "query_texts": [query],
            "n_results": n_results,
        }
        if where_filter:
            kwargs["where"] = where_filter

        results = self.collection.query(**kwargs)

        flattened: List[Dict[str, Any]] = []
        metadatas = results.get("metadatas") or []
        if metadatas and metadatas[0]:
            for meta in metadatas[0]:
                flattened.append(meta)
        return flattened