import httpx
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict
from src.config import config

class CVEFetcher:
    def __init__(self):
        self.base_url = config.CVE_API_URL
        self.headers = {"User-Agent": "SecurityIntelPlatform/1.0"}
    
    async def fetch_recent_cves(self, days: int = 7, results_per_page: int = 20) -> List[Dict]:
        """Fetch recent CVEs from NVD API"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": results_per_page
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(self.base_url, params=params, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = []
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "N/A")
                    
                    # Extract CVSS score
                    metrics = cve_data.get("metrics", {})
                    cvss_score = None
                    severity = "UNKNOWN"
                    
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                        severity = metrics["cvssMetricV2"][0]["baseSeverity"]
                    
                    # Extract description
                    descriptions = cve_data.get("descriptions", [])
                    description = descriptions[0].get("value", "No description") if descriptions else "No description"
                    
                    vulnerabilities.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score or 0.0,
                        "severity": severity,
                        "published_date": cve_data.get("published", "Unknown")
                    })
                
                return vulnerabilities
            
            except Exception as e:
                print(f"Error fetching CVEs: {e}")
                return []
    
    def categorize_by_severity(self, cves: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize CVEs by severity"""
        categorized = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": []
        }
        
        for cve in cves:
            score = cve.get("cvss_score", 0)
            if score >= config.CRITICAL_CVSS_THRESHOLD:
                categorized["CRITICAL"].append(cve)
            elif score >= config.HIGH_CVSS_THRESHOLD:
                categorized["HIGH"].append(cve)
            elif score >= config.MEDIUM_CVSS_THRESHOLD:
                categorized["MEDIUM"].append(cve)
            else:
                categorized["LOW"].append(cve)
        
        return categorized