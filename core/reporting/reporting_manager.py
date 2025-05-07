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
        reporting_config_path: str = "config/reporting.yaml" # For AlertSystem config
    ):
        print(f"ReportingManager initialized with template: {report_template_path} and config: {reporting_config_path}")
        self.report_generator = ReportGenerator(template_path=report_template_path)
        self.dashboard = Dashboard() # Dashboard initializes with empty findings
        self.alert_system = AlertSystem(config_path=reporting_config_path)
        self._findings: List[Dict[str, Any]] = [] # Initialize _findings
        self._temporal_results: List[Dict[str, Any]] = [] # Initialize temporal results

    def process_findings(self, findings: List[Dict[str, Any]]):
        """Load findings into all reporting subsystems."""
        if not isinstance(findings, list):
            print(f"Warning: process_findings expects a list, got {type(findings)}. Attempting to proceed if it's a dict with 'findings'.")
            if isinstance(findings, dict) and 'findings' in findings and isinstance(findings['findings'], list):
                findings = findings['findings']
            else:
                print("Error: Invalid findings format. Cannot process.")
                self._findings = []
                self.dashboard.set_findings([])
                # Alert system might still process an empty list or handle error internally
                self.alert_system.process_findings([])
                return

        self._findings = findings
        self.dashboard.set_findings(self._findings)
        self.alert_system.process_findings(self._findings)
        print(f"ReportingManager processed {len(self._findings)} findings.")
    
    def process_temporal_results(self, temporal_results: List[Dict[str, Any]]):
        """
        Process temporal analysis results.
        
        Args:
            temporal_results: Results from temporal analysis
        """
        if not isinstance(temporal_results, list):
            print(f"Warning: process_temporal_results expects a list, got {type(temporal_results)}.")
            self._temporal_results = []
            return
            
        self._temporal_results = temporal_results
        print(f"ReportingManager processed {len(self._temporal_results)} temporal analysis results.")

    def generate_html_report(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        Generate an HTML report using the ReportGenerator.
        
        Args:
            output_path: Path to write the report to. Defaults to "llms_security_report.html".
        
        Returns:
            The path to the generated report file, or None if generation failed.
        """
        if not self._findings:
            print("No findings available to generate a report.")
            # Optionally, generate an empty report
            # return self.report_generator.generate_report([], output_path or "empty_report.html")
            return None
            
        report_out_path = output_path or "llms_security_report.html"
        
        try:
            # Include temporal results if available
            temporal_data = None
            if self._temporal_results:
                temporal_data = {
                    "results": self._temporal_results,
                    "has_changes": any(r.get("changes_detected", False) for r in self._temporal_results),
                    "suspicious_changes": [
                        change for r in self._temporal_results
                        for change in r.get("suspicious_changes", [])
                    ],
                    "gradual_modifications": [
                        mod for r in self._temporal_results
                        for mod in r.get("gradual_modifications", [])
                    ]
                }
            
            generated_path = self.report_generator.generate_report(
                findings=self._findings,
                output_path=report_out_path,
                temporal_data=temporal_data
            )
            print(f"HTML report generated at: {generated_path}")
            return generated_path
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return None

    def generate_dashboard_html(self, output_dir: str = "reports", filename: str = "dashboard.html") -> Optional[str]:
        """
        Generates an HTML dashboard file using the Dashboard component.
        """
        if not self._findings:
             print("No findings available to generate a dashboard.")
             return None
        # Ensure dashboard has the latest findings (already set by process_findings)
        return self.dashboard.render_dashboard_html(output_dir=output_dir, filename=filename)

    def get_dashboard_figures(self) -> Dict[str, Optional[Any]]:
        """Return Plotly figure objects for dashboard visualizations."""
        if not self._findings:
            return {
                "severity_distribution_fig": None,
                "trend_analysis_fig": None,
                "temporal_risk_trend_fig": None,
            }
        
        # Get standard figures
        figures = {
            "severity_distribution_fig": self.dashboard.get_severity_distribution_fig(),
            "trend_analysis_fig": self.dashboard.get_trend_analysis_fig(),
            "temporal_risk_trend_fig": None
        }
        
        # Add temporal visualization if available
        if hasattr(self.dashboard, 'get_temporal_risk_trend_fig') and self._temporal_results:
            try:
                figures["temporal_risk_trend_fig"] = self.dashboard.get_temporal_risk_trend_fig(self._temporal_results)
            except Exception as e:
                print(f"Error generating temporal risk trend figure: {e}")
        
        return figures

    def get_all_findings_for_dashboard(self) -> List[Dict[str, Any]]:
        """Returns all current findings, typically for dashboard display."""
        return self.dashboard.findings # or self._findings, should be the same

    def filter_findings(self, severity: Optional[str] = None, finding_type: Optional[str] = None, date_start: Optional[str] = None, date_end: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter findings using dashboard's filtering system."""
        return self.dashboard.filter_findings(severity=severity, finding_type=finding_type, date_start=date_start, date_end=date_end)

    def explore_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Explore a specific finding in detail."""
        return self.dashboard.explore_finding(finding_id)

    def set_alert_threshold(self, severity: str):
        """Set the alerting threshold."""
        self.alert_system.set_threshold(severity)

    def register_alert_hook(self, hook):
        """Register an external integration hook for alerts."""
        self.alert_system.register_external_hook(hook)