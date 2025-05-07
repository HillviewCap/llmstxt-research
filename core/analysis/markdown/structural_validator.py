import re
from typing import List, Dict, Any, Optional

class MarkdownStructuralValidator:
    """
    Validates the structure of llms.txt markdown files.
    Integrates with a (mocked) validator library, applies custom rules,
    detects abnormal patterns, and compares structure to known-good templates.
    """

    def __init__(self, template: Optional[str] = None):
        # template: a known-good llms.txt markdown string for structure comparison
        self.template = template

    def validate(self, markdown: str) -> Dict[str, Any]:
        """
        Run all structural validation checks.
        Returns a dict with results and findings.
        """
        results = {
            "remark_lint": self._mock_remark_lint(markdown),
            "custom_rules": self._check_custom_rules(markdown),
            "abnormal_patterns": self._detect_abnormal_patterns(markdown),
            "structure_comparison": self._compare_structure(markdown, self.template) if self.template else None,
        }
        return results

    def _mock_remark_lint(self, markdown: str) -> List[str]:
        # Placeholder for integration with remark-lint or similar
        # For now, just check for common markdown issues
        issues = []
        if not markdown.strip():
            issues.append("Markdown is empty.")
        if "# " not in markdown:
            issues.append("No top-level heading found.")
        return issues

    def _check_custom_rules(self, markdown: str) -> List[str]:
        # Example: llms.txt must have a '## Models' section
        issues = []
        if "## Models" not in markdown:
            issues.append("Missing '## Models' section.")
        # Add more llms.txt-specific rules as needed
        return issues

    def _detect_abnormal_patterns(self, markdown: str) -> List[str]:
        # Example: detect suspiciously long lines or repeated patterns
        findings = []
        for i, line in enumerate(markdown.splitlines(), 1):
            if len(line) > 500:
                findings.append(f"Line {i} is unusually long.")
            if re.search(r"(.)\1{20,}", line):
                findings.append(f"Line {i} contains repeated characters.")
        return findings

    def _compare_structure(self, markdown: str, template: str) -> Dict[str, Any]:
        # Compare the outline (headings) of the markdown to the template
        def extract_headings(md: str) -> List[str]:
            return [line.strip() for line in md.splitlines() if re.match(r"^#+ ", line)]
        user_headings = extract_headings(markdown)
        template_headings = extract_headings(template)
        return {
            "user_headings": user_headings,
            "template_headings": template_headings,
            "matches_template": user_headings == template_headings,
        }