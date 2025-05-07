"""
Alert System for LLMs.txt Security Analysis Platform

Responsibilities:
- Severity-based alerting
- Notification system (mocked)
- Threshold configuration
- Integration hooks for external systems (mocked)
"""

from typing import List, Dict, Any, Callable, Optional

class AlertSystem:
    def __init__(self, severity_threshold: str = "HIGH", notifier: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.severity_threshold = severity_threshold
        self.notifier = notifier or self.mock_notifier
        self.external_hooks = []

    def set_threshold(self, severity: str):
        if severity in self.severity_levels:
            self.severity_threshold = severity

    def register_external_hook(self, hook: Callable[[Dict[str, Any]], None]):
        """Register an integration hook for external systems."""
        self.external_hooks.append(hook)

    def process_findings(self, findings: List[Dict[str, Any]]):
        """Process findings and trigger alerts as needed."""
        threshold_idx = self.severity_levels.index(self.severity_threshold)
        for finding in findings:
            sev = finding.get("severity", "INFO")
            if self.severity_levels.index(sev) >= threshold_idx:
                self.trigger_alert(finding)

    def trigger_alert(self, finding: Dict[str, Any]):
        """Trigger an alert and notify via all channels."""
        message = f"ALERT [{finding.get('severity', 'INFO')}] - {finding.get('title', 'Untitled')}: {finding.get('description', '')}"
        self.notifier(message, finding)
        for hook in self.external_hooks:
            hook(finding)

    @staticmethod
    def mock_notifier(message: str, finding: Dict[str, Any]):
        """Mock notification system (prints to console or logs)."""
        print(f"[MockNotification] {message}")

    # Example: mock integration with an external system
    @staticmethod
    def mock_external_integration(finding: Dict[str, Any]):
        print(f"[MockExternalIntegration] Finding sent: {finding.get('id')}")