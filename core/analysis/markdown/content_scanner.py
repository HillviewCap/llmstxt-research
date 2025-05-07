import re
from typing import List, Dict, Any

class MockHtmlSanitizer:
    def sanitize(self, html: str) -> str:
        # Mock: In real use, integrate with bleach or similar
        # Here, just strip <script> tags as a placeholder
        return re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)

class MarkdownContentScanner:
    """
    Scans markdown content for security issues:
    - HTML sanitization
    - XSS vector detection
    - LLM prompt injection
    - Behavior manipulation patterns
    """

    XSS_PATTERNS = [
        re.compile(r'<script.*?>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),  # onerror=, onclick=, etc.
    ]

    PROMPT_INJECTION_PATTERNS = [
        re.compile(r'(ignore|disregard|override|bypass|forget)\b.*(previous|all|above)', re.IGNORECASE),
        re.compile(r'(as an ai|as a language model)', re.IGNORECASE),
        re.compile(r'(repeat after me:)', re.IGNORECASE),
    ]

    BEHAVIOR_MANIPULATION_PATTERNS = [
        re.compile(r'(please|kindly)?\s*(output|print|show|leak)\s+(your|the)\s*(instructions|prompt|internal)', re.IGNORECASE),
        re.compile(r'(simulate|impersonate|pretend to be)', re.IGNORECASE),
    ]

    def __init__(self, sanitizer: MockHtmlSanitizer = None):
        self.sanitizer = sanitizer or MockHtmlSanitizer()

    def scan(self, markdown: str) -> Dict[str, Any]:
        html = self._extract_html(markdown)
        sanitized = self.sanitizer.sanitize(html)
        xss = self._detect_xss(html)
        prompt_injection = self._detect_prompt_injection(markdown)
        behavior_manip = self._detect_behavior_manipulation(markdown)
        return {
            "sanitized_html": sanitized,
            "xss_vectors": xss,
            "prompt_injection": prompt_injection,
            "behavior_manipulation": behavior_manip,
        }

    def _extract_html(self, markdown: str) -> str:
        # Naive: extract all HTML tags in markdown
        return "\n".join(re.findall(r'<[^>]+>', markdown))

    def _detect_xss(self, html: str) -> List[str]:
        findings = []
        for pattern in self.XSS_PATTERNS:
            for match in pattern.findall(html):
                findings.append(match)
        return findings

    def _detect_prompt_injection(self, markdown: str) -> List[str]:
        findings = []
        for pattern in self.PROMPT_INJECTION_PATTERNS:
            for match in pattern.findall(markdown):
                findings.append(match if isinstance(match, str) else match[0])
        return findings

    def _detect_behavior_manipulation(self, markdown: str) -> List[str]:
        findings = []
        for pattern in self.BEHAVIOR_MANIPULATION_PATTERNS:
            for match in pattern.findall(markdown):
                findings.append(match if isinstance(match, str) else match[0])
        return findings