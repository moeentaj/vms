import chromadb
from chromadb.config import Settings
from typing import List, Dict, Optional
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

class VectorDatabase:
    def __init__(self):
        self.client = chromadb.PersistentClient(
            path=settings.CHROMA_DB_PATH,
            settings=Settings(anonymized_telemetry=False)
        )
        self.collection_name = "cve_embeddings"
        self.collection = None
    
    def initialize_collection(self):
        """Initialize or get existing collection"""
        try:
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "CVE embeddings for similarity search"}
            )
            logger.info(f"Vector database collection '{self.collection_name}' ready")
        except Exception as e:
            logger.error(f"Failed to initialize vector database: {e}")
    
    def add_cve_embedding(self, cve_id: str, description: str, metadata: Dict):
        """Add CVE embedding to the collection"""
        if not self.collection:
            self.initialize_collection()
        
        try:
            self.collection.add(
                documents=[description],
                metadatas=[metadata],
                ids=[cve_id]
            )
            logger.debug(f"Added embedding for CVE {cve_id}")
        except Exception as e:
            logger.error(f"Failed to add CVE embedding: {e}")
    
    def search_similar_cves(self, query: str, n_results: int = 5) -> List[Dict]:
        """Search for similar CVEs based on description"""
        if not self.collection:
            self.initialize_collection()
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            return [
                {
                    "cve_id": results['ids'][0][i],
                    "description": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i],
                    "distance": results['distances'][0][i] if 'distances' in results else None
                }
                for i in range(len(results['ids'][0]))
            ]
        except Exception as e:
            logger.error(f"Failed to search similar CVEs: {e}")
            return []
