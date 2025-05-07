from typing import List, Dict, Any, Optional

from .trufflehog_runner import TruffleHogRunner, TruffleHogResultParser, CustomRegexPatternManager, normalize_finding
from .pattern_library import PatternLibrary
from .sensitive_detector import SensitiveDetector

class SecretsAnalyzer:
    """
    Orchestrates credential and sensitive data detection using multiple strategies.
    """
    def __init__(
        self,
        trufflehog_config: Optional[Dict[str, Any]] = None,
        custom_patterns: Optional[List[Dict[str, str]]] = None
    ):
        # TruffleHog runner setup
        self.trufflehog_runner = TruffleHogRunner(
            custom_patterns=custom_patterns,
            config=trufflehog_config
        )
        self.trufflehog_parser = TruffleHogResultParser()
        self.pattern_library = PatternLibrary()
        self.sensitive_detector = SensitiveDetector()

    def analyze(self, data: Any) -> Dict[str, List[Dict[str, Any]]]:
        """
        Runs all detection modules and returns normalized findings.
        
        Args:
            data: Either a string or a dictionary with content
        """
        # Extract content from the input
        if isinstance(data, dict):
            print(f"Secrets analyzing content item: {data.get('id', 'unknown')}")
            content = data.get('content', '')
            if not isinstance(content, str):
                print(f"Warning: content is not a string, using empty string instead. Type: {type(content)}")
                content = ''
        else:
            content = str(data)
        results = {
            'credentials': [],
            'llm_patterns': [],
            'sensitive_info': [],
        }

        # 1. TruffleHog (mocked)
        trufflehog_findings = self.trufflehog_runner.run(content)
        results['credentials'] = [
            normalize_finding(f) for f in self.trufflehog_parser.parse(trufflehog_findings)
        ]

        # 2. LLM-specific patterns
        llm_matches = self.pattern_library.match(content)
        results['llm_patterns'] = [
            {
                'type': m['name'],
                'value': m['match'],
                'location': {'start': m['start'], 'end': m['end']},
                'groups': m.get('groups', ()),
            }
            for m in llm_matches
        ]

        # 3. Sensitive info (PII, infra, config)
        sensitive_matches = self.sensitive_detector.match(content)
        results['sensitive_info'] = [
            {
                'type': m['name'],
                'value': m['match'],
                'location': {'start': m['start'], 'end': m['end']},
                'groups': m.get('groups', ()),
            }
            for m in sensitive_matches
        ]

        return results