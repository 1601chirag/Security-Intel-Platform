import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from typing import List, Dict
from src.config import config
import os

class SecurityKnowledgeBase:
    def __init__(self):
        os.makedirs(config.CHROMA_PERSIST_DIR, exist_ok=True)
        
        self.client = chromadb.PersistentClient(
            path=config.CHROMA_PERSIST_DIR,
            settings=Settings(anonymized_telemetry=False)
        )
        
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
        try:
            self.collection = self.client.get_collection("security_kb")
        except:
            self.collection = self.client.create_collection(
                name="security_kb",
                metadata={"description": "Security knowledge base for policies and findings"}
            )
    
    def add_security_policy(self, policy_name: str, policy_content: str):
        """Add security policy to knowledge base"""
        embedding = self.embedder.encode(policy_content).tolist()
        
        self.collection.add(
            embeddings=[embedding],
            documents=[policy_content],
            metadatas=[{"type": "policy", "name": policy_name}],
            ids=[f"policy_{policy_name}"]
        )
    
    def add_vulnerability_finding(self, cve_id: str, analysis: str):
        """Add vulnerability analysis to knowledge base"""
        embedding = self.embedder.encode(analysis).tolist()
        
        self.collection.add(
            embeddings=[embedding],
            documents=[analysis],
            metadatas=[{"type": "vulnerability", "cve_id": cve_id}],
            ids=[f"vuln_{cve_id}"]
        )
    
    def query_knowledge(self, query: str, n_results: int = 3) -> List[Dict]:
        """Query knowledge base"""
        query_embedding = self.embedder.encode(query).tolist()
        
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results
        )
        
        return [
            {
                "document": doc,
                "metadata": meta,
                "distance": dist
            }
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0]
            )
        ]
    
    def seed_owasp_policies(self):
        """Seed OWASP Top 10 policies"""
        owasp_policies = {
            "A01_Broken_Access_Control": "Implement proper authorization checks at every access point. Use deny-by-default approach. Enforce record ownership. Disable directory listing. Log access control failures.",
            "A02_Cryptographic_Failures": "Classify data sensitivity. Encrypt all sensitive data at rest and in transit. Use strong encryption algorithms. Implement proper key management. Disable caching for sensitive data.",
            "A03_Injection": "Use parameterized queries. Validate and sanitize all inputs. Use ORM frameworks. Implement WAF rules. Escape special characters.",
            "A05_Security_Misconfiguration": "Harden all configurations. Remove unnecessary features. Update regularly. Implement segmentation. Automate configuration verification."
        }
        
        for policy_name, content in owasp_policies.items():
            self.add_security_policy(policy_name, content)