import os
from typing import List, Dict, Any
import chromadb
from chromadb.config import Settings
from langchain_google_genai import GoogleGenerativeAIEmbeddings

class VectorStore:
    """
    Abstractions for Vector DB operations (ChromaDB).
    Connects to the embedding model for log indexing.
    """
    def __init__(self, collection_name: str = "logs"):
        self.chroma_client = chromadb.PersistentClient(
            path=os.getenv("CHROMA_PATH", "./data/chroma")
        )
        self.collection = self.chroma_client.get_or_create_collection(
            name=collection_name
        )
        self.embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")

    def add_logs(self, logs: List[Dict[str, Any]]):
        """Indexes processed logs into the vector store."""
        documents = [log["message"] for log in logs]
        metadatas = [log for log in logs]
        ids = [log.get("request_id", f"id-{i}") for i, log in enumerate(logs)]
        
        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

    def search_logs(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Semantic search for relevant logs."""
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results
        )
        # Flatten results into a cleaner list of logs
        flattened = []
        if results["metadatas"]:
            for meta in results["metadatas"][0]:
                flattened.append(meta)
        return flattened
