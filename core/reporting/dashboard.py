"""
Dashboard Module for LLMs.txt Security Analysis Platform

Responsibilities:
- Data visualization components
- Interactive filtering system
- Trend analysis functionality
- Finding exploration interface
"""

from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict
import datetime
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from pathlib import Path

class Dashboard:
    def __init__(self, findings: Optional[List[Dict[str, Any]]] = None):
        self.findings = findings or []
        self.temporal_results = []

    def set_findings(self, findings: List[Dict[str, Any]]):
        self.findings = findings

    def get_severity_distribution_fig(self) -> Optional[go.Figure]:
        """Return a Plotly figure for severity distribution."""
        if not self.findings:
            return None
        severities = [f.get("severity", "INFO") for f in self.findings]
        counts = Counter(severities)
        fig = go.Figure(data=[go.Bar(x=list(counts.keys()), y=list(counts.values()))])
        fig.update_layout(title_text="Finding Severity Distribution")
        return fig

    def filter_findings(self, severity: Optional[str] = None, finding_type: Optional[str] = None, date_start: Optional[str] = None, date_end: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter findings by severity, type, and/or date range."""
        filtered = self.findings
        if severity:
            filtered = [f for f in filtered if f.get("severity") == severity]
        if finding_type:
            filtered = [f for f in filtered if f.get("type") == finding_type] # Assuming 'type' field exists
        if date_start:
            try:
                start_date = datetime.datetime.fromisoformat(date_start).date()
                filtered = [f for f in filtered if f.get("timestamp") and datetime.datetime.fromisoformat(f["timestamp"]).date() >= start_date]
            except ValueError:
                pass # Invalid date format
        if date_end:
            try:
                end_date = datetime.datetime.fromisoformat(date_end).date()
                filtered = [f for f in filtered if f.get("timestamp") and datetime.datetime.fromisoformat(f["timestamp"]).date() <= end_date]
            except ValueError:
                pass # Invalid date format
        return filtered

    def get_trend_analysis_fig(self, date_field: str = "timestamp") -> Optional[go.Figure]:
        """
        Return a Plotly figure for trend analysis of findings over time (by day).
        Assumes findings have a date_field in ISO format.
        """
        if not self.findings:
            return None
        trends = defaultdict(int)
        dates = []
        for f in self.findings:
            ts_str = f.get(date_field)
            if ts_str:
                try:
                    # Attempt to parse with or without timezone
                    if 'Z' in ts_str:
                        dt_obj = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    elif '+' in ts_str or '-' in ts_str[10:]: # check for timezone offset
                         dt_obj = datetime.datetime.fromisoformat(ts_str)
                    else: # Assume naive datetime, or specific format if known
                        dt_obj = datetime.datetime.fromisoformat(ts_str)
                    
                    day = dt_obj.date()
                    dates.append(day)
                    trends[day.isoformat()] += 1
                except ValueError:
                    # Fallback for simple date strings if fromisoformat fails
                    try:
                        day = datetime.datetime.strptime(ts_str, '%Y-%m-%d').date()
                        dates.append(day)
                        trends[day.isoformat()] += 1
                    except ValueError:
                        print(f"Warning: Could not parse date string: {ts_str}")
                        continue
        
        if not trends:
            return None

        sorted_days = sorted(trends.keys())
        counts = [trends[day] for day in sorted_days]
        
        fig = go.Figure(data=[go.Scatter(x=sorted_days, y=counts, mode='lines+markers')])
        fig.update_layout(title_text="Findings Over Time", xaxis_title="Date", yaxis_title="Number of Findings")
        return fig

    def get_temporal_risk_trend_fig(self, temporal_results: List[Dict[str, Any]]) -> Optional[go.Figure]:
        """
        Generate a visualization of temporal risk trends.
        
        Args:
            temporal_results: Results from temporal analysis
            
        Returns:
            Plotly figure with temporal risk trends
        """
        if not temporal_results:
            return None
        
        # Store temporal results for later use
        self.temporal_results = temporal_results
        
        # Extract data for visualization
        urls = []
        versions = []
        timestamps = []
        suspicious_changes = []
        gradual_mods = []
        
        for result in temporal_results:
            url = result.get('url', '')
            if url and url not in urls:
                urls.append(url)
            
            versions.append(result.get('version', 0))
            timestamps.append(result.get('timestamp', ''))
            suspicious_changes.append(len(result.get('suspicious_changes', [])))
            gradual_mods.append(len(result.get('gradual_modifications', [])))
        
        if not timestamps:
            return None
        
        # Create figure with two subplots
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=("Suspicious Changes Over Time", "Gradual Modifications Over Time"),
            vertical_spacing=0.2
        )
        
        # Add suspicious changes trace
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=suspicious_changes,
                mode='lines+markers',
                name='Suspicious Changes',
                line=dict(color='red', width=2)
            ),
            row=1, col=1
        )
        
        # Add gradual modifications trace
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=gradual_mods,
                mode='lines+markers',
                name='Gradual Modifications',
                line=dict(color='orange', width=2)
            ),
            row=2, col=1
        )
        
        # Add version annotations
        for i, (ts, v) in enumerate(zip(timestamps, versions)):
            fig.add_annotation(
                x=ts,
                y=suspicious_changes[i],
                text=f"v{v}",
                showarrow=True,
                arrowhead=1,
                row=1, col=1
            )
        
        # Update layout
        fig.update_layout(
            title_text=f"Temporal Analysis for {', '.join(urls)}",
            height=600,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        # Update y-axes
        fig.update_yaxes(title_text="Count", row=1, col=1)
        fig.update_yaxes(title_text="Count", row=2, col=1)
        
        return fig
    
    def explore_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Return details for a specific finding."""
        for f in self.findings:
            if str(f.get("id")) == str(finding_id):
                return f
        return None

    def render_dashboard_html(self, output_dir: str = "reports", filename: str = "dashboard.html") -> Optional[str]:
        """
        Generates an HTML dashboard file with Plotly visualizations and finding details.
        Returns the path to the generated HTML file or None if no data.
        """
        if not self.findings:
            print("No findings to render in dashboard.")
            return None

        output_path = Path(output_dir) / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        severity_fig = self.get_severity_distribution_fig()
        trend_fig = self.get_trend_analysis_fig()
        
        # Generate temporal visualization if we have temporal results
        temporal_fig = None
        if self.temporal_results:
            temporal_fig = self.get_temporal_risk_trend_fig(self.temporal_results)

        # Basic HTML structure
        html_content = f"""
        <html>
        <head>
            <title>LLMs.txt Security Dashboard</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .chart-container {{ width: 80%; margin: auto; margin-bottom: 40px; border: 1px solid #ccc; padding: 10px; }}
                .findings-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                .findings-table th, .findings-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .findings-table th {{ background-color: #f2f2f2; }}
                pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }}
            </style>
        </head>
        <body>
            <h1>LLMs.txt Security Dashboard</h1>
        """

        if severity_fig:
            html_content += "<div class='chart-container'>"
            html_content += severity_fig.to_html(full_html=False, include_plotlyjs='cdn')
            html_content += "</div>"
        
        if trend_fig:
            html_content += "<div class='chart-container'>"
            html_content += trend_fig.to_html(full_html=False, include_plotlyjs='cdn')
            html_content += "</div>"
        
        # Add temporal visualization if available
        if temporal_fig:
            html_content += "<h2>Temporal Analysis</h2>"
            html_content += "<div class='chart-container'>"
            html_content += temporal_fig.to_html(full_html=False, include_plotlyjs='cdn')
            html_content += "</div>"

        html_content += "<h2>All Findings</h2>"
        html_content += "<table class='findings-table'>"
        html_content += "<tr><th>ID</th><th>Title</th><th>Severity</th><th>Description</th><th>Source</th><th>Timestamp</th><th>Evidence</th><th>Context</th><th>Remediation</th></tr>"

        for f in self.findings:
            html_content += "<tr>"
            html_content += f"<td>{f.get('id', 'N/A')}</td>"
            html_content += f"<td>{f.get('title', 'N/A')}</td>"
            html_content += f"<td>{f.get('severity', 'N/A')}</td>"
            html_content += f"<td>{f.get('description', 'N/A')}</td>"
            html_content += f"<td>{f.get('source', 'N/A')}</td>"
            html_content += f"<td>{f.get('timestamp', 'N/A')}</td>"
            html_content += f"<td><pre>{json.dumps(f.get('evidence', {}), indent=2)}</pre></td>"
            html_content += f"<td><pre>{json.dumps(f.get('context', {}), indent=2)}</pre></td>"
            html_content += f"<td>{f.get('remediation', 'N/A')}</td>"
            html_content += "</tr>"
        
        html_content += "</table>"
        html_content += "</body></html>"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"Dashboard HTML generated at: {output_path.resolve()}")
        return str(output_path.resolve())