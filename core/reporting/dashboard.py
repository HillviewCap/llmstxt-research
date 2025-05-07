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

class Dashboard:
    def __init__(self, findings: Optional[List[Dict[str, Any]]] = None):
        self.findings = findings or []

    def set_findings(self, findings: List[Dict[str, Any]]):
        self.findings = findings

    def visualize_severity_distribution(self) -> Dict[str, int]:
        """Return a count of findings by severity."""
        severities = [f.get("severity", "INFO") for f in self.findings]
        return dict(Counter(severities))

    def filter_findings(self, severity: Optional[str] = None, finding_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter findings by severity and/or type."""
        filtered = self.findings
        if severity:
            filtered = [f for f in filtered if f.get("severity") == severity]
        if finding_type:
            filtered = [f for f in filtered if f.get("type") == finding_type]
        return filtered

    def trend_analysis(self, date_field: str = "timestamp") -> Dict[str, int]:
        """
        Analyze trends in findings over time (by day).
        Assumes findings have a date_field in ISO format.
        """
        trends = defaultdict(int)
        for f in self.findings:
            ts = f.get(date_field)
            if ts:
                try:
                    day = datetime.datetime.fromisoformat(ts).date().isoformat()
                    trends[day] += 1
                except Exception:
                    continue
        return dict(trends)

    def explore_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Return details for a specific finding."""
        for f in self.findings:
            if str(f.get("id")) == str(finding_id):
                return f
        return None

    # Stub for future UI integration
    def render_dashboard(self):
        """Stub: Render dashboard (to be implemented in UI layer)."""
        pass