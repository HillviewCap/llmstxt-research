import os
from typing import List, Dict, Any, Optional

from .semgrep_runner import SemgrepRunner, SemgrepRunnerError
from .rule_manager import RuleManager, RuleManagerError
from .finding_manager import FindingManager, FindingManagerError

class StaticAnalyzerError(Exception):
    pass

class StaticAnalyzer:
    def __init__(self, rules_path: str = "rules/semgrep"):
        print(f"StaticAnalyzer initialized with rules_path: {rules_path}")
        self.rules_path = rules_path
        self.rule_manager = RuleManager(rules_path)
        self.semgrep_runner = SemgrepRunner(rules_path)
        self.finding_manager = FindingManager()

    def analyze(self, data: Any, language: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            # Extract content from the input
            if isinstance(data, dict):
                print(f"Static analyzing content item: {data.get('id', 'unknown')}")
                # For static analysis, we need a path to a file, but we're getting a content item
                # So we'll just return an empty list for now
                print("Static analysis requires a file path, not a content item. Returning empty results.")
                return []
            
            target_path = str(data)
            
            # Select rules for the language (if specified)
            if language:
                rules = self.rule_manager.get_rules_for_language(language)
                if not rules:
                    raise StaticAnalyzerError(f"No rules found for language: {language}")
                # For now, run all rules in the directory (Semgrep CLI limitation for per-rule)
                findings = self.semgrep_runner.run(target_path, languages=[language])
            else:
                findings = self.semgrep_runner.run(target_path)
            for finding in findings:
                self.finding_manager.store_finding(finding)
            return self.finding_manager.get_all_findings()
        except (SemgrepRunnerError, RuleManagerError, FindingManagerError) as e:
            raise StaticAnalyzerError(str(e))

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.semgrep_runner.list_rules()

    def clear_findings(self):
        self.finding_manager.clear()