from typing import List, Dict, Any, Optional

from .trufflehog_runner import TruffleHogRunner # Removed TruffleHogResultParser, normalize_finding
from .pattern_library import PatternLibrary
from .sensitive_detector import SensitiveDetector
from .finding_manager import SecretFindingManager # Added SecretFindingManager

class SecretsAnalyzer:
    """
    Orchestrates credential and sensitive data detection using multiple strategies,
    normalizing all findings through a SecretFindingManager.
    """
    def __init__(
        self,
        trufflehog_config: Optional[Dict[str, Any]] = None,
        custom_patterns: Optional[List[Dict[str, str]]] = None # This seems to be for TruffleHog custom patterns
    ):
        # TruffleHog runner setup
        self.trufflehog_runner = TruffleHogRunner(
            custom_patterns=custom_patterns, # Pass custom regex patterns for TruffleHog
            config=trufflehog_config
        )
        # Note: PatternLibrary and SensitiveDetector might have their own pattern loading mechanisms
        self.pattern_library = PatternLibrary()
        self.sensitive_detector = SensitiveDetector()
        # SecretFindingManager will be instantiated per analysis run to handle context like file_path

    def analyze(self, data: Any, file_path: Optional[str] = None, analysis_id: Optional[Any] = None) -> List[Dict[str, Any]]:
        """
        Runs all detection modules and returns a unified list of normalized findings.
        
        Args:
            data: Either a string containing the content to analyze,
                  or a dictionary which might contain 'content', 'id' (for analysis_id),
                  and 'path' (for file_path).
            file_path: Optional path of the file/content being analyzed.
                       If 'data' is a dict, 'path' key will be preferred.
            analysis_id: Optional ID for the overall analysis session.
                         If 'data' is a dict, 'id' key will be preferred.
        """
        content_to_analyze: str = ""
        current_analysis_id: Optional[Any] = analysis_id
        current_file_path: Optional[str] = file_path

        if isinstance(data, dict):
            item_id = data.get('id', 'unknown_item')
            print(f"Secrets analyzing content item: {item_id}")
            content_to_analyze = data.get('content', '')
            if not isinstance(content_to_analyze, str):
                print(f"Warning: content for item {item_id} is not a string (type: {type(content_to_analyze)}), using empty string.")
                content_to_analyze = ''
            
            # Prefer 'id' and 'path' from data dict if available
            if 'id' in data and current_analysis_id is None:
                current_analysis_id = data['id']
            if 'path' in data and current_file_path is None:
                current_file_path = data['path']
            elif 'file_path' in data and current_file_path is None: # Check alternative
                 current_file_path = data['file_path']

        elif isinstance(data, str):
            content_to_analyze = data
            print(f"Secrets analyzing raw string content (length: {len(content_to_analyze)}).")
        else:
            print(f"Warning: Unsupported data type for secrets analysis: {type(data)}. Using empty content.")
            content_to_analyze = ''

        finding_manager = SecretFindingManager(file_path=current_file_path, analysis_id=current_analysis_id)

        # 1. TruffleHog
        # TruffleHogRunner.run already returns a list of raw finding dicts
        raw_trufflehog_findings = self.trufflehog_runner.run(content_to_analyze)
        for th_finding in raw_trufflehog_findings:
            finding_manager.store_finding(th_finding, "trufflehog")

        # 2. LLM-specific patterns (PatternLibrary)
        # PatternLibrary.match returns a list of raw finding dicts
        llm_pattern_matches = self.pattern_library.match(content_to_analyze)
        for pl_match in llm_pattern_matches:
            finding_manager.store_finding(pl_match, "pattern_library")

        # 3. Sensitive info (SensitiveDetector)
        # SensitiveDetector.match returns a list of raw finding dicts
        sensitive_info_matches = self.sensitive_detector.match(content_to_analyze)
        for sd_match in sensitive_info_matches:
            finding_manager.store_finding(sd_match, "sensitive_detector")

        return finding_manager.get_all_findings()