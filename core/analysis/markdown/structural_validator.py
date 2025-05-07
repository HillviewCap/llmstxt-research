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
        # Validates llms.txt specific structural rules.
        issues = []
        required_sections = [
            "MARKDOWN RULES",
            "TOOL USE",
            # "MCP SERVERS", # MCP Servers might be optional depending on context
            "CAPABILITIES",
            "MODES",
            "RULES",
            "SYSTEM INFORMATION",
            "OBJECTIVE"
        ]
        for section in required_sections:
            if f"====\n\n{section}" not in markdown and f"\n{section}\n\n====" not in markdown and not re.search(rf"^#+ {section}", markdown, re.MULTILINE):
                 # Check for section heading as well, as format can vary slightly
                if not re.search(rf"^\#+ {section}", markdown, re.MULTILINE):
                    issues.append(f"Missing required section: '{section}'. Expected '==== {section} ====' or '# {section}'.")

        if "=====" not in markdown:
            issues.append("Missing '=====' separators, which are typical in llms.txt.")

        # Check for common llms.txt patterns, e.g. tool definitions
        if "TOOL USE" in markdown and "<tool_name>" not in markdown:
            issues.append("'TOOL USE' section found, but no '<tool_name>' tags detected, which might indicate malformed tool definitions.")
        
        if "MODE" in markdown and "<slug>" not in markdown:
            issues.append("'MODES' section found, but no '<slug>' tags detected, which might indicate malformed mode definitions.")

        # Example: Check for presence of <attempt_completion> tag
        if "OBJECTIVE" in markdown and "<attempt_completion>" not in markdown:
            issues.append("OBJECTIVE section is present, but no '<attempt_completion>' tag found. Ensure the agent can complete tasks.")

        return issues

    def _detect_abnormal_patterns(self, markdown: str) -> List[str]:
        # Detects unusual structural patterns in the markdown.
        findings = []
        lines = markdown.splitlines()
        empty_line_count = 0
        max_consecutive_empty_lines = 0
        current_consecutive_empty_lines = 0

        for i, line in enumerate(lines, 1):
            if len(line) > 1000: # Increased threshold for long lines
                findings.append(f"Line {i} is unusually long (>{len(line)} chars).")
            if re.search(r"(.)\1{30,}", line): # Increased threshold for repeated chars
                findings.append(f"Line {i} contains 30+ repeated characters.")
            if re.search(r"^#{6,}", line): # Detect H6 or deeper
                findings.append(f"Line {i} uses a very deep heading level (H6+).")
            
            if not line.strip():
                empty_line_count += 1
                current_consecutive_empty_lines +=1
            else:
                if current_consecutive_empty_lines > max_consecutive_empty_lines:
                    max_consecutive_empty_lines = current_consecutive_empty_lines
                current_consecutive_empty_lines = 0
        
        if current_consecutive_empty_lines > max_consecutive_empty_lines: # check after loop
            max_consecutive_empty_lines = current_consecutive_empty_lines

        if empty_line_count > len(lines) / 2: # More than 50% empty lines
            findings.append(f"Excessive empty lines: {empty_line_count} out of {len(lines)} lines.")
        
        if max_consecutive_empty_lines > 10: # More than 10 consecutive empty lines
            findings.append(f"Excessive consecutive empty lines: {max_consecutive_empty_lines} lines.")
            
        # Check for an unusually high number of headings
        headings = [line for line in lines if re.match(r"^#+ ", line)]
        if len(headings) > 50 and len(lines) < 1000 : # Arbitrary threshold: >50 headings in <1000 lines
            findings.append(f"Unusually high number of headings: {len(headings)} headings in {len(lines)} lines.")

        return findings

    def _compare_structure(self, markdown: str, template: Optional[str]) -> Dict[str, Any]:
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