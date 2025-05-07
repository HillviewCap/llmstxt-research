"""
Pattern Analysis Orchestrator
Coordinates YARA integration, rule library, and behavioral analysis for LLMs.txt Security Analysis Platform.
"""

from typing import Dict, Any, List
from .yara_runner import YaraRuleManager
from .rule_library import LLMRuleLibrary, RuleDocumentation
from .behavior_analyzer import BehaviorAnalyzer

class PatternAnalysisOrchestrator:
    """
    Orchestrates advanced pattern matching components.
    """
    def __init__(self):
        self.rule_manager = YaraRuleManager()
        self.doc_manager = RuleDocumentation()
        self.rule_library = LLMRuleLibrary(self.rule_manager, self.doc_manager)
        self.behavior_analyzer = BehaviorAnalyzer(self.rule_manager, self.rule_library)

    def analyze(self, data: Any) -> Dict[str, Any]:
        """
        Runs the full suite of pattern analysis on the input data.
        
        Args:
            data: Either a string or a dictionary with content
        """
        # Extract content from the input
        if isinstance(data, dict):
            print(f"Pattern analyzing content item: {data.get('id', 'unknown')}")
            content = data.get('content', '')
            if not isinstance(content, str):
                print(f"Warning: content is not a string, using empty string instead. Type: {type(content)}")
                content = ''
        else:
            content = str(data)
            
        return self.behavior_analyzer.analyze(content)

    def list_rules(self) -> List[str]:
        return self.rule_library.list_rules()

    def get_rule_doc(self, rule_name: str) -> str:
        return self.rule_library.get_rule_doc(rule_name)

    def test_rule(self, rule_name: str, test_data: str) -> bool:
        rule = self.rule_manager.get_rule(rule_name)
        if not rule:
            return False
        return rule.match(test_data)

# Create an alias for compatibility with existing code
PatternAnalyzer = PatternAnalysisOrchestrator