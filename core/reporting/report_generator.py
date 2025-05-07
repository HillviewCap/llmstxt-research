"""
Report Generator for LLMs.txt Security Analysis Platform

Responsibilities:
- Templated report generation
- Finding summarization
- Evidence collection and formatting
- Remediation suggestion system
"""

from typing import List, Dict, Any
from pathlib import Path

class ReportGenerator:
    def __init__(self, template_path: str):
        self.template_path = template_path

    def summarize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Summarize findings for the report."""
        summary = []
        for finding in findings:
            summary.append(f"- [{finding.get('severity', 'INFO')}] {finding.get('title', 'Untitled')}: {finding.get('description', '')}")
        return "\n".join(summary)

    def collect_evidence(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collect and format evidence for each finding."""
        evidence_list = []
        for finding in findings:
            evidence = {
                "id": finding.get("id"),
                "evidence": finding.get("evidence", "No evidence provided"),
                "source": finding.get("source", "Unknown"),
                "context": finding.get("context", {})
            }
            evidence_list.append(evidence)
        return evidence_list

    def suggest_remediation(self, findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Suggest remediation steps for each finding."""
        remediations = []
        for finding in findings:
            suggestion = finding.get("remediation", "Review and address the finding as appropriate.")
            remediations.append({
                "id": finding.get("id"),
                "remediation": suggestion
            })
        return remediations

    def generate_report(self, findings: List[Dict[str, Any]], output_path: str) -> str:
        """Generate a report using the template and findings."""
        summary = self.summarize_findings(findings)
        evidence = self.collect_evidence(findings)
        remediations = self.suggest_remediation(findings)

        # Load template
        template = Path(self.template_path).read_text(encoding="utf-8")

        # Simple template rendering (replace placeholders)
        report = template.replace("{{SUMMARY}}", summary)
        report = report.replace("{{EVIDENCE}}", self._format_evidence(evidence))
        report = report.replace("{{REMEDIATIONS}}", self._format_remediations(remediations))

        # Write report to output_path
        Path(output_path).write_text(report, encoding="utf-8")
        return output_path

    def _format_evidence(self, evidence: List[Dict[str, Any]]) -> str:
        lines = []
        for ev in evidence:
            lines.append(f"ID: {ev['id']}\nSource: {ev['source']}\nEvidence: {ev['evidence']}\nContext: {ev['context']}\n")
        return "\n".join(lines)

    def _format_remediations(self, remediations: List[Dict[str, str]]) -> str:
        lines = []
        for rem in remediations:
            lines.append(f"ID: {rem['id']}\nRemediation: {rem['remediation']}\n")
        return "\n".join(lines)