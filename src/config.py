import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    MODEL_NAME = os.getenv("MODEL_NAME", "mistral")
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_db")
    CVE_API_URL = os.getenv("CVE_API_URL")
    
    # Security scanning thresholds
    CRITICAL_CVSS_THRESHOLD = 9.0
    HIGH_CVSS_THRESHOLD = 7.0
    MEDIUM_CVSS_THRESHOLD = 4.0
    
    # OWASP Top 10 categories
    OWASP_CATEGORIES = [
        "A01:2021-Broken Access Control",
        "A02:2021-Cryptographic Failures",
        "A03:2021-Injection",
        "A04:2021-Insecure Design",
        "A05:2021-Security Misconfiguration",
        "A06:2021-Vulnerable and Outdated Components",
        "A07:2021-Identification and Authentication Failures",
        "A08:2021-Software and Data Integrity Failures",
        "A09:2021-Security Logging and Monitoring Failures",
        "A10:2021-Server-Side Request Forgery"
    ]

config = Config()