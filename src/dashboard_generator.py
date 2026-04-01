import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict
import pandas as pd
from datetime import datetime

class DashboardGenerator:
    def generate_severity_chart(self, categorized_cves: Dict[str, List[Dict]]) -> str:
        """Generate severity distribution chart"""
        severity_counts = {k: len(v) for k, v in categorized_cves.items()}
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(severity_counts.keys()),
                y=list(severity_counts.values()),
                marker_color=['#dc3545', '#fd7e14', '#ffc107', '#28a745']
            )
        ])
        
        fig.update_layout(
            title="Vulnerability Severity Distribution",
            xaxis_title="Severity",
            yaxis_title="Count",
            template="plotly_dark"
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def generate_cvss_timeline(self, cves: List[Dict]) -> str:
        """Generate CVSS score timeline"""
        df = pd.DataFrame(cves)
        df['published_date'] = pd.to_datetime(df['published_date'])
        df = df.sort_values('published_date')
        
        fig = px.scatter(
            df,
            x='published_date',
            y='cvss_score',
            color='severity',
            hover_data=['cve_id'],
            title="CVE CVSS Score Timeline"
        )
        
        fig.update_layout(template="plotly_dark")
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def generate_compliance_metrics(self, findings_count: int, resolved_count: int) -> str:
        """Generate compliance KPI gauge"""
        compliance_rate = (resolved_count / findings_count * 100) if findings_count > 0 else 100
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=compliance_rate,
            title={'text': "Security Compliance Rate (%)"},
            delta={'reference': 95},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 85], 'color': "gray"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 95
                }
            }
        ))
        
        fig.update_layout(template="plotly_dark")
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def generate_full_dashboard(self, categorized_cves: Dict, all_cves: List[Dict], 
                                findings_count: int, resolved_count: int) -> str:
        """Generate complete HTML dashboard"""
        severity_chart = self.generate_severity_chart(categorized_cves)
        timeline_chart = self.generate_cvss_timeline(all_cves)
        compliance_gauge = self.generate_compliance_metrics(findings_count, resolved_count)
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Intelligence Dashboard</title>
            <style>
                body {{ 
                    background: #0d1117; 
                    color: #c9d1d9; 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    padding: 20px;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 40px;
                }}
                .metrics {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 40px;
                }}
                .metric-card {{
                    background: #161b22;
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid #30363d;
                }}
                .chart-container {{
                    margin-bottom: 40px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Security Intelligence Dashboard</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="metrics">
                <div class="metric-card">
                    <h3>Total Findings</h3>
                    <h2 style="color: #58a6ff;">{findings_count}</h2>
                </div>
                <div class="metric-card">
                    <h3>Critical Vulnerabilities</h3>
                    <h2 style="color: #f85149;">{len(categorized_cves.get('CRITICAL', []))}</h2>
                </div>
                <div class="metric-card">
                    <h3>High Priority</h3>
                    <h2 style="color: #d29922;">{len(categorized_cves.get('HIGH', []))}</h2>
                </div>
                <div class="metric-card">
                    <h3>Resolved</h3>
                    <h2 style="color: #3fb950;">{resolved_count}</h2>
                </div>
            </div>
            
            <div class="chart-container">
                {severity_chart}
            </div>
            
            <div class="chart-container">
                {timeline_chart}
            </div>
            
            <div class="chart-container">
                {compliance_gauge}
            </div>
        </body>
        </html>
        """
        
        return html_template