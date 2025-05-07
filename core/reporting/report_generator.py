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
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def __init__(self, template_path: str):
        self.template_path = Path(template_path)
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_path.parent)),
            autoescape=True
        )

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
        evidence_list = self.collect_evidence(findings)
        remediation_suggestions = self.suggest_remediation(findings)

        template = self.jinja_env.get_template(self.template_path.name)

        report_context = {
            "summary": summary,
            "findings": findings, # Pass full findings for more detailed templating
            "evidence_list": evidence_list,
            "remediation_suggestions": remediation_suggestions
        }

        report_content = template.render(report_context)

        # Write report to output_path
        Path(output_path).write_text(report_content, encoding="utf-8")
        return output_path