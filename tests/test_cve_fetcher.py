import pytest
from src.cve_fetcher import CVEFetcher

@pytest.mark.asyncio
async def test_fetch_recent_cves():
    fetcher = CVEFetcher()
    cves = await fetcher.fetch_recent_cves(days=3, results_per_page=5)
    
    assert isinstance(cves, list)
    if cves:  # May be empty depending on API
        assert "cve_id" in cves[0]
        assert "cvss_score" in cves[0]

def test_categorize_by_severity():
    fetcher = CVEFetcher()
    sample_cves = [
        {"cve_id": "CVE-2024-0001", "cvss_score": 9.8, "severity": "CRITICAL"},
        {"cve_id": "CVE-2024-0002", "cvss_score": 7.5, "severity": "HIGH"},
        {"cve_id": "CVE-2024-0003", "cvss_score": 4.3, "severity": "MEDIUM"}
    ]
    
    categorized = fetcher.categorize_by_severity(sample_cves)
    
    assert len(categorized["CRITICAL"]) == 1
    assert len(categorized["HIGH"]) == 1
    assert len(categorized["MEDIUM"]) == 1