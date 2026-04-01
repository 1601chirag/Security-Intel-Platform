from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from src.config import config
from typing import List, Dict

class SecurityAIAgent:
    def __init__(self):
        self.llm = ChatOllama(
            model=config.MODEL_NAME,
            base_url=config.OLLAMA_BASE_URL,
            temperature=0.3
        )
    
    async def triage_vulnerability(self, cve_data: Dict) -> Dict:
        """AI-powered vulnerability triage"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a security analyst AI specializing in vulnerability triage.
            Given a CVE, provide:
            1. Exploitability assessment (Low/Medium/High)
            2. Business impact (Low/Medium/High/Critical)
            3. Recommended priority (P0/P1/P2/P3)
            4. Remediation steps (bullet points)
            5. OWASP Top 10 mapping (if applicable)
            
            Be concise and actionable."""),
            ("user", """CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score}
Severity: {severity}

Provide triage analysis.""")
        ])
        
        chain = prompt | self.llm | StrOutputParser()
        
        analysis = await chain.ainvoke({
            "cve_id": cve_data["cve_id"],
            "description": cve_data["description"],
            "cvss_score": cve_data["cvss_score"],
            "severity": cve_data["severity"]
        })
        
        return {
            "cve_id": cve_data["cve_id"],
            "ai_analysis": analysis,
            "cvss_score": cve_data["cvss_score"],
            "severity": cve_data["severity"]
        }
    
    async def generate_compliance_report(self, findings: List[Dict]) -> str:
        """Generate compliance summary for ISO 27001 / SOC2"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a compliance officer generating security reports for ISO 27001 and SOC2 audits.
            Given security findings, produce a professional summary covering:
            - Total findings count by severity
            - High-priority items requiring immediate attention
            - Compliance posture assessment
            - Recommended actions for audit readiness
            
            Format as a professional report."""),
            ("user", "Security findings data:\n{findings_summary}")
        ])
        
        findings_summary = "\n".join([
            f"- {f['cve_id']}: {f['severity']} (CVSS: {f.get('cvss_score', 'N/A')})"
            for f in findings[:10]  # Limit for context
        ])
        
        chain = prompt | self.llm | StrOutputParser()
        report = await chain.ainvoke({"findings_summary": findings_summary})
        
        return report
    
    async def summarize_security_report(self, report_text: str) -> str:
        """Summarize lengthy security reports"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a security analyst. Summarize the following security report into 3-5 key bullet points."),
            ("user", "{report_text}")
        ])
        
        chain = prompt | self.llm | StrOutputParser()
        summary = await chain.ainvoke({"report_text": report_text})
        
        return summary