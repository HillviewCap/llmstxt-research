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
            "structure_comparison": (
                self._compare_structure(markdown, self.template)
                if self.template
                else None
            ),
            "llmstxt_standard_validation_issues": self._validate_llmstxt_format(
                markdown
            ),
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
            "OBJECTIVE",
        ]
        for section in required_sections:
            if (
                f"====\n\n{section}" not in markdown
                and f"\n{section}\n\n====" not in markdown
                and not re.search(rf"^#+ {section}", markdown, re.MULTILINE)
            ):
                # Check for section heading as well, as format can vary slightly
                if not re.search(rf"^\#+ {section}", markdown, re.MULTILINE):
                    issues.append(
                        f"Missing required section: '{section}'. Expected '==== {section} ====' or '# {section}'."
                    )

        if "=====" not in markdown:
            issues.append("Missing '=====' separators, which are typical in llms.txt.")

        # Check for common llms.txt patterns, e.g. tool definitions
        if "TOOL USE" in markdown and "<tool_name>" not in markdown:
            issues.append(
                "'TOOL USE' section found, but no '<tool_name>' tags detected, which might indicate malformed tool definitions."
            )

        if "MODE" in markdown and "<slug>" not in markdown:
            issues.append(
                "'MODES' section found, but no '<slug>' tags detected, which might indicate malformed mode definitions."
            )

        # Example: Check for presence of <attempt_completion> tag
        if "OBJECTIVE" in markdown and "<attempt_completion>" not in markdown:
            issues.append(
                "OBJECTIVE section is present, but no '<attempt_completion>' tag found. Ensure the agent can complete tasks."
            )

        return issues

    def _detect_abnormal_patterns(self, markdown: str) -> List[str]:
        # Detects unusual structural patterns in the markdown.
        findings = []
        lines = markdown.splitlines()
        empty_line_count = 0
        max_consecutive_empty_lines = 0
        current_consecutive_empty_lines = 0

        for i, line in enumerate(lines, 1):
            if len(line) > 1000:  # Increased threshold for long lines
                findings.append(f"Line {i} is unusually long (>{len(line)} chars).")
            if re.search(r"(.)\1{30,}", line):  # Increased threshold for repeated chars
                findings.append(f"Line {i} contains 30+ repeated characters.")
            if re.search(r"^#{6,}", line):  # Detect H6 or deeper
                findings.append(f"Line {i} uses a very deep heading level (H6+).")

            if not line.strip():
                empty_line_count += 1
                current_consecutive_empty_lines += 1
            else:
                if current_consecutive_empty_lines > max_consecutive_empty_lines:
                    max_consecutive_empty_lines = current_consecutive_empty_lines
                current_consecutive_empty_lines = 0

        if (
            current_consecutive_empty_lines > max_consecutive_empty_lines
        ):  # check after loop
            max_consecutive_empty_lines = current_consecutive_empty_lines

        if empty_line_count > len(lines) / 2:  # More than 50% empty lines
            findings.append(
                f"Excessive empty lines: {empty_line_count} out of {len(lines)} lines."
            )

        if max_consecutive_empty_lines > 10:  # More than 10 consecutive empty lines
            findings.append(
                f"Excessive consecutive empty lines: {max_consecutive_empty_lines} lines."
            )

        # Check for an unusually high number of headings
        headings = [line for line in lines if re.match(r"^#+ ", line)]
        if (
            len(headings) > 50 and len(lines) < 1000
        ):  # Arbitrary threshold: >50 headings in <1000 lines
            findings.append(
                f"Unusually high number of headings: {len(headings)} headings in {len(lines)} lines."
            )

        return findings

    def _compare_structure(
        self, markdown: str, template: Optional[str]
    ) -> Dict[str, Any]:
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

    def _validate_llmstxt_format(self, markdown: str) -> List[str]:
        """
        Validates if a markdown string conforms to the "llms.txt" standard.

        The "llms.txt" standard requires:
        1. Exactly one H1 heading at the start
        2. Optional blockquote summary immediately following the H1
        3. Optional general information (no H2 headings)
        4. Zero or more H2 sections for file lists
        5. Each H2 section should contain a markdown list
        6. Each list item should be a link with optional description

        Returns a list of validation issues found.
        """
        issues = []

        # Skip empty markdown
        if not markdown.strip():
            issues.append("Markdown is empty.")
            return issues

        # Check for H1 heading at the start
        h1_pattern = r"^#\s+(.+?)$"
        h1_matches = re.findall(h1_pattern, markdown, re.MULTILINE)

        if not h1_matches:
            issues.append("Missing H1 heading at the start of the document.")
            return issues  # Early return as this is a critical requirement

        if len(h1_matches) > 1:
            issues.append(
                f"Found {len(h1_matches)} H1 headings, but exactly one is required."
            )

        # Check if H1 is at the very beginning (allowing for whitespace)
        if not re.match(r"^\s*#\s+", markdown):
            issues.append("H1 heading is not at the beginning of the document.")

        # Split content into sections
        sections = re.split(r"^##\s+(.*?)$", markdown, flags=re.MULTILINE)

        # First section should be everything before the first H2
        first_section = sections[0]

        # Check for optional blockquote summary after H1
        lines = first_section.strip().split("\n")
        if len(lines) > 1:  # At least H1 and potentially more content
            # Remove the H1 line
            content_after_h1 = "\n".join(lines[1:]).strip()

            # Check if content after H1 starts with a blockquote
            has_blockquote = content_after_h1.startswith(">")

            # If there's a blockquote, check if there's content after it
            if has_blockquote:
                blockquote_lines = []
                general_info_lines = []

                in_blockquote = True
                for line in content_after_h1.split("\n"):
                    if in_blockquote:
                        if line.strip() and not line.strip().startswith(">"):
                            in_blockquote = False
                            general_info_lines.append(line)
                        else:
                            blockquote_lines.append(line)
                    else:
                        general_info_lines.append(line)

                # Check if there are H2 headings in the general info section
                if general_info_lines and re.search(
                    r"^##\s+", "\n".join(general_info_lines), re.MULTILINE
                ):
                    issues.append(
                        "Found H2 heading in the general information section before the first file list section."
                    )

            # If no blockquote, check if there are H2 headings in the content after H1
            elif re.search(r"^##\s+", content_after_h1, re.MULTILINE):
                issues.append(
                    "Found H2 heading in the general information section before the first file list section."
                )

        # Check H2 sections (file lists)
        if len(sections) > 1:
            # sections[1::2] contains the H2 headings
            # sections[2::2] contains the content under each H2
            for i, (heading, content) in enumerate(zip(sections[1::2], sections[2::2])):
                # Check if the section contains a markdown list
                list_items = re.findall(
                    r"^\s*-\s+\[.+?\]\(.+?\)", content, re.MULTILINE
                )
                if not list_items:
                    issues.append(
                        f"H2 section '{heading}' does not contain a markdown list with links."
                    )

                # Check link format in the list
                links = re.findall(
                    r"^\s*-\s+\[(.+?)\]\((.+?)\)(?::\s*(.*))?$", content, re.MULTILINE
                )
                if not links and list_items:
                    issues.append(
                        f"H2 section '{heading}' contains a list but items don't follow the required link format."
                    )

                # Check if there's content other than the list
                non_list_content = re.sub(
                    r"^\s*-\s+\[.+?\]\(.+?\)(?::\s*.*)?$",
                    "",
                    content,
                    flags=re.MULTILINE,
                ).strip()
                if non_list_content and not re.search(
                    r"^\s*$", non_list_content, re.MULTILINE
                ):
                    # Allow some non-list content, but warn if it's substantial
                    substantial_content = len(non_list_content.split("\n")) > 3
                    if substantial_content:
                        issues.append(
                            f"H2 section '{heading}' contains substantial content other than the link list."
                        )

        return issues
