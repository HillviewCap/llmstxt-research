import re
from typing import List, Dict, Any, Optional

class TruffleHogRunner:
    """
    Mock runner for TruffleHog secret scanning.
    Allows custom configuration and pattern injection.
    """
    def __init__(self, custom_patterns: Optional[List[Dict[str, Any]]] = None, config: Optional[Dict[str, Any]] = None):
        self.custom_patterns = custom_patterns or []
        self.config = config or {}

    def run(self, content: str) -> List[Dict[str, Any]]:
        """
        Simulate running TruffleHog on the provided content.
        Returns a list of findings (mocked).
        """
        findings = []
        # Simulate built-in and custom pattern matching
        patterns = self._get_patterns()
        for pattern in patterns:
            for match in re.finditer(pattern['regex'], content):
                findings.append({
                    'type': pattern['name'],
                    'match': match.group(0),
                    'start': match.start(),
                    'end': match.end(),
                    'entropy': self._mock_entropy(match.group(0)),
                    'raw': match.group(0),
                })
        return findings

    def _get_patterns(self) -> List[Dict[str, Any]]:
        # Built-in mock patterns
        built_in = [
            {'name': 'AWS Access Key', 'regex': r'AKIA[0-9A-Z]{16}'},
            {'name': 'Generic API Key', 'regex': r'api_key[=:][a-zA-Z0-9]{32,}'},
        ]
        return built_in + self.custom_patterns

    def _mock_entropy(self, s: str) -> float:
        # Simple entropy mock
        return min(8.0, len(set(s)) / len(s) * 8) if s else 0.0

class TruffleHogResultParser:
    """
    Parses TruffleHog findings and normalizes them for the platform.
    """
    @staticmethod
    def parse(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for f in findings:
            normalized.append({
                'credential_type': f['type'],
                'value': f['match'],
                'location': {'start': f['start'], 'end': f['end']},
                'entropy': f.get('entropy', None),
                'raw': f.get('raw', None),
            })
        return normalized

class CustomRegexPatternManager:
    """
    Manages custom regex patterns for credential detection.
    """
    def __init__(self):
        self.patterns = []

    def add_pattern(self, name: str, regex: str):
        self.patterns.append({'name': name, 'regex': regex})

    def get_patterns(self) -> List[Dict[str, str]]:
        return self.patterns

def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a single finding to the platform's credential finding schema.
    """
    return {
        'type': finding.get('credential_type', finding.get('type', 'Unknown')),
        'value': finding.get('value', finding.get('match', '')),
        'location': finding.get('location', {}),
        'entropy': finding.get('entropy', None),
        'raw': finding.get('raw', None),
    }