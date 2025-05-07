import re
from typing import List, Dict, Any, Callable, Optional

class Pattern:
    """
    Represents a credential or sensitive data pattern.
    """
    def __init__(self, name: str, regex: str, context: Optional[Callable[[str, re.Match], bool]] = None, flags=0):
        self.name = name
        self.regex = regex
        self.context = context  # Optional function for context-aware matching
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

class PatternLibrary:
    """
    Library of patterns for LLM-specific credentials and sensitive data.
    """
    def __init__(self):
        self.patterns: List[Pattern] = []
        self._load_default_patterns()

    def _load_default_patterns(self):
        # Example LLM-specific credential patterns
        self.add_pattern(
            Pattern(
                name="OpenAI API Key",
                regex=r"sk-[a-zA-Z0-9]{48}",
            )
        )
        self.add_pattern(
            Pattern(
                name="HuggingFace Token",
                regex=r"hf_[a-zA-Z0-9]{40,}",
            )
        )
        # Encoded/obfuscated credential pattern (e.g., base64)
        self.add_pattern(
            Pattern(
                name="Base64-Encoded Token",
                regex=r"(?:[A-Za-z0-9+/]{20,}={0,2})",
                context=self._is_likely_base64,
            )
        )

    def add_pattern(self, pattern: Pattern):
        self.patterns.append(pattern)

    def match(self, text: str) -> List[Dict[str, Any]]:
        results = []
        for pattern in self.patterns:
            results.extend(pattern.match(text))
        return results

    @staticmethod
    def _is_likely_base64(text: str, match: re.Match) -> bool:
        # Heuristic: base64 strings often have high entropy and valid padding
        s = match.group(0)
        if len(s) < 20 or len(s) % 4 != 0:
            return False
        try:
            import base64
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False

class PatternTester:
    """
    Simple framework for testing patterns against sample texts.
    """
    def __init__(self, library: PatternLibrary):
        self.library = library

    def test(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        samples: List of {'text': ..., 'expected': [pattern names]}
        Returns: List of {'text': ..., 'found': [pattern names], 'expected': ...}
        """
        results = []
        for sample in samples:
            found = [m['name'] for m in self.library.match(sample['text'])]
            results.append({
                'text': sample['text'],
                'found': found,
                'expected': sample.get('expected', []),
                'success': set(found) == set(sample.get('expected', [])),
            })
        return results