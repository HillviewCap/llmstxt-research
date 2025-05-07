"""
Reporting Manager Orchestrator for LLMs.txt Security Analysis Platform

Responsibilities:
- Tie together report generation, dashboard, and alert system components
- Provide unified interface for reporting operations
"""

from typing import List, Dict, Any, Optional

from .report_generator import ReportGenerator
from .dashboard import Dashboard
from .alert_system import AlertSystem

class ReportingManager:
    def __init__(
        self,
        report_template_path: str = "config/report_template.html",
        alert_severity_threshold: str = "HIGH"
    ):
        print(f"ReportingManager initialized with template: {report_template_path}")
        self.report_generator = ReportGenerator(report_template_path)
        self.dashboard = Dashboard()
        self.alert_system = AlertSystem(severity_threshold=alert_severity_threshold)

    def process_findings(self, findings: List[Dict[str, Any]]):
        """Load findings into all reporting subsystems."""
        self.dashboard.set_findings(findings)
        self.alert_system.process_findings(findings)
        self._findings = findings

    def generate_report(self, content_items=None, analysis_results=None, scores=None, risks=None, output_path=None) -> str:
        """
        Generate a report using the provided data or current findings.
        
        Args:
            content_items: List of content items that were analyzed
            analysis_results: Results of the analysis
            scores: Scores from the scoring model
            risks: Risk assessments
            output_path: Path to write the report to
        """
        print(f"Generating report with {len(content_items) if content_items else 0} content items")
        
        # If we have analysis results, process them
        if analysis_results:
            self._findings = analysis_results
        
        # If we don't have findings, raise an error
        if not hasattr(self, "_findings") and not analysis_results:
            print("WARNING: No findings loaded. Using empty findings list.")
            self._findings = []
            
        # If no output path is provided, use a default
        if not output_path:
            output_path = "report.html"
            
        # For now, just return a simple report
        return {
            "report_path": output_path,
            "summary": {
                "content_count": len(content_items) if content_items else 0,
                "finding_count": len(self._findings) if hasattr(self, "_findings") else 0,
                "risk_level": "medium"  # Placeholder
            }
        }

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Return dashboard data for visualization."""
        return {
            "severity_distribution": self.dashboard.visualize_severity_distribution(),
            "trend_analysis": self.dashboard.trend_analysis(),
            "findings": self.dashboard.findings
        }

    def filter_findings(self, severity: Optional[str] = None, finding_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter findings using dashboard's filtering system."""
        return self.dashboard.filter_findings(severity, finding_type)

    def explore_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Explore a specific finding in detail."""
        return self.dashboard.explore_finding(finding_id)

    def set_alert_threshold(self, severity: str):
        """Set the alerting threshold."""
        self.alert_system.set_threshold(severity)

    def register_alert_hook(self, hook):
        """Register an external integration hook for alerts."""
        self.alert_system.register_external_hook(hook)