import re
from typing import List, Dict, Any, Callable, Optional

class SensitivePattern:
    """
    Represents a sensitive information pattern (PII, infra, config).
    """
    def __init__(self, name: str, regex: str, context: Optional[Callable[[str, re.Match], bool]] = None, flags=0):
        self.name = name
        self.regex = regex
        self.context = context
        self.flags = flags

    def match(self, text: str) -> List[Dict[str, Any]]:
        matches = []
        for m in re.finditer(self.regex, text, self.flags):
            if self.context is None or self.context(text, m):
                matches.append({
                    'name': self.name,
                    'match': m.group(0),
                    'start': m.start(),
                    'end': m.end(),
                    'groups': m.groups(),
                })
        return matches

class SensitiveDetector:
    """
    Detects sensitive information such as PII, internal infra, and config data.
    """
    def __init__(self):
        self.patterns: List[SensitivePattern] = []
        self._load_default_patterns()

    def _load_default_patterns(self):
        # PII patterns
        self.add_pattern(SensitivePattern(
            name="Email Address",
            regex=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        ))
        self.add_pattern(SensitivePattern(
            name="US Phone Number",
            regex=r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ))
        self.add_pattern(SensitivePattern(
            name="US SSN",
            regex=r"\b\d{3}-\d{2}-\d{4}\b"
        ))
        # Internal infrastructure patterns
        self.add_pattern(SensitivePattern(
            name="Internal IP Address",
            regex=r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
        ))
        self.add_pattern(SensitivePattern(
            name="Hostname",
            regex=r"\b[a-zA-Z0-9-]{2,}\.(corp|internal|intra|lan|local)\b"
        ))
        # Configuration data patterns
        self.add_pattern(SensitivePattern(
            name="Database Connection String",
            regex=r"(postgres|mysql|mongodb|redis):\/\/[^\s]+"
        ))
        self.add_pattern(SensitivePattern(
            name="JWT Secret",
            regex=r"jwt[_-]?secret[=:][^\s]+",
            context=self._not_in_comment
        ))

    def add_pattern(self, pattern: SensitivePattern):
        self.patterns.append(pattern)

    def match(self, text: str) -> List[Dict[str, Any]]:
        results = []
        for pattern in self.patterns:
            results.extend(pattern.match(text))
        return self._reduce_false_positives(results, text)

    def _reduce_false_positives(self, results: List[Dict[str, Any]], text: str) -> List[Dict[str, Any]]:
        # Example: Remove emails in code comments or test data
        filtered = []
        for r in results:
            if r['name'] == "Email Address":
                if self._is_in_comment(text, r['start']):
                    continue
            filtered.append(r)
        return filtered

    @staticmethod
    def _is_in_comment(text: str, pos: int) -> bool:
        # Simple heuristic: check if the match is within a Python or JS-style comment
        before = text[max(0, pos-100):pos]
        return "#" in before or "//" in before

    @staticmethod
    def _not_in_comment(text: str, match: re.Match) -> bool:
        # Used for context-based filtering
        return not SensitiveDetector._is_in_comment(text, match.start())