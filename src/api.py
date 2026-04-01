from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
from datetime import datetime

from src.cve_fetcher import CVEFetcher
from src.ai_agent import SecurityAIAgent
from src.knowledge_base import SecurityKnowledgeBase
from src.dashboard_generator import DashboardGenerator
from src.config import config

app = FastAPI(title="Security Intelligence Platform", version="1.0.0")

# Initialize components
cve_fetcher = CVEFetcher()
ai_agent = SecurityAIAgent()
kb = SecurityKnowledgeBase()
dashboard_gen = DashboardGenerator()

# Data models
class ScanRequest(BaseModel):
    days: int = 7
    results_per_page: int = 20

class TriageRequest(BaseModel):
    cve_id: str

class QueryRequest(BaseModel):
    query: str
    n_results: int = 3

# Global state (in production, use database)
scan_results = {
    "cves": [],
    "categorized": {},
    "last_scan": None
}

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <head><title>Security Intelligence Platform</title></head>
        <body style="background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 40px;">
            <h1>🛡️ Security Intelligence Platform</h1>
            <h3>Available Endpoints:</h3>
            <ul>
                <li><a href="/scan?days=7" style="color: #58a6ff;">POST /scan</a> - Scan recent CVEs</li>
                <li><a href="/triage" style="color: #58a6ff;">POST /triage</a> - AI-powered vulnerability triage</li>
                <li><a href="/dashboard" style="color: #58a6ff;">GET /dashboard</a> - View security dashboard</li>
                <li><a href="/compliance-report" style="color: #58a6ff;">GET /compliance-report</a> - Generate compliance report</li>
                <li><a href="/knowledge/query" style="color: #58a6ff;">POST /knowledge/query</a> - Query security knowledge base</li>
                <li><a href="/health" style="color: #58a6ff;">GET /health</a> - Health check</li>
            </ul>
        </body>
    </html>
    """

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/scan")
async def scan_vulnerabilities(request: ScanRequest):
    """Scan for recent CVEs"""
    try:
        cves = await cve_fetcher.fetch_recent_cves(
            days=request.days,
            results_per_page=request.results_per_page
        )
        
        categorized = cve_fetcher.categorize_by_severity(cves)
        
        # Update global state
        scan_results["cves"] = cves
        scan_results["categorized"] = categorized
        scan_results["last_scan"] = datetime.now().isoformat()
        
        return {
            "status": "success",
            "total_cves": len(cves),
            "categorized_counts": {k: len(v) for k, v in categorized.items()},
            "scan_timestamp": scan_results["last_scan"]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/triage")
async def triage_vulnerability(request: TriageRequest):
    """AI-powered vulnerability triage"""
    try:
        # Find CVE in scan results
        cve_data = next(
            (cve for cve in scan_results["cves"] if cve["cve_id"] == request.cve_id),
            None
        )
        
        if not cve_data:
            raise HTTPException(status_code=404, detail="CVE not found in scan results")
        
        analysis = await ai_agent.triage_vulnerability(cve_data)
        
        # Store in knowledge base
        kb.add_vulnerability_finding(request.cve_id, analysis["ai_analysis"])
        
        return analysis
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    """Generate and return security dashboard"""
    try:
        if not scan_results["cves"]:
            return "<html><body><h2>No scan data available. Run /scan first.</h2></body></html>"
        
        dashboard_html = dashboard_gen.generate_full_dashboard(
            categorized_cves=scan_results["categorized"],
            all_cves=scan_results["cves"],
            findings_count=len(scan_results["cves"]),
            resolved_count=0  # Placeholder
        )
        
        return dashboard_html
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/compliance-report")
async def generate_compliance_report():
    """Generate ISO 27001 / SOC2 compliance report"""
    try:
        if not scan_results["cves"]:
            raise HTTPException(status_code=400, detail="No scan data available")
        
        report = await ai_agent.generate_compliance_report(scan_results["cves"])
        
        # Save to reports directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"reports/compliance_report_{timestamp}.txt"
        
        with open(report_path, "w") as f:
            f.write(report)
        
        return {
            "status": "success",
            "report": report,
            "saved_to": report_path
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/knowledge/query")
async def query_knowledge_base(request: QueryRequest):
    """Query security knowledge base"""
    try:
        results = kb.query_knowledge(request.query, request.n_results)
        return {"results": results}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def startup_event():
    """Seed knowledge base on startup"""
    kb.seed_owasp_policies()
    print("✅ Security Knowledge Base seeded with OWASP Top 10 policies")