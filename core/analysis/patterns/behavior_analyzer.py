"""
Behavioral Pattern Analyzer for LLMs.txt Security Analysis Platform
Detects LLM manipulation, jailbreaking, data extraction, and context-based threats.
"""

from typing import Dict, Any, List
from .yara_runner import YaraRunner, YaraRuleManager
from .rule_library import LLMRuleLibrary, RuleDocumentation

class BehaviorAnalyzer:
    """
    Analyzes text for behavioral patterns indicating LLM threats.
    """
    def __init__(self, rule_manager: YaraRuleManager, rule_library: LLMRuleLibrary):
        self.yara_runner = YaraRunner(rule_manager)
        self.rule_library = rule_library

    def analyze(self, data: str) -> Dict[str, Any]:
        """
        Runs all behavioral pattern analyses and returns a summary.
        """
        scan_result = self.yara_runner.scan(data)
        summary = {
            "manipulation": [],
            "jailbreak": [],
            "data_extraction": [],
            "other": []
        }
        for match in scan_result["matches"]:
            rule_name = match["rule_name"]
            doc = self.rule_library.get_rule_doc(rule_name)
            threat_type = self._classify_threat(rule_name)
            summary[threat_type].append({
                "rule": rule_name,
                "doc": doc,
                "excerpt": match["match_excerpt"]
            })
        summary["scan_time_ms"] = scan_result["scan_time_ms"]
        summary["rule_count"] = scan_result["rule_count"]
        return summary

    def _classify_threat(self, rule_name: str) -> str:
        """
        Classifies the rule into a threat category.
        """
        if "injection" in rule_name:
            return "manipulation"
        if "jailbreak" in rule_name:
            return "jailbreak"
        if "data_extraction" in rule_name:
            return "data_extraction"
        return "other"

    def detect_jailbreaking(self, data: str) -> List[Dict[str, Any]]:
        """
        Specialized detection for jailbreaking attempts.
        """
        # For demonstration, look for rules with 'jailbreak' in the name
        results = []
        for rule_name in self.rule_library.list_rules():
            if "jailbreak" in rule_name:
                rule = self.yara_runner.rule_manager.get_rule(rule_name)
                if rule and rule.match(data):
                    results.append({
                        "rule": rule_name,
                        "doc": self.rule_library.get_rule_doc(rule_name)
                    })
        return results

    def detect_data_extraction(self, data: str) -> List[Dict[str, Any]]:
        """
        Specialized detection for data extraction attempts.
        """
        results = []
        for rule_name in self.rule_library.list_rules():
            if "data_extraction" in rule_name:
                rule = self.yara_runner.rule_manager.get_rule(rule_name)
                if rule and rule.match(data):
                    results.append({
                        "rule": rule_name,
                        "doc": self.rule_library.get_rule_doc(rule_name)
                    })
        return results

    def context_based_match(self, data: str, context_keywords: List[str]) -> List[Dict[str, Any]]:
        """
        Matches rules only if certain context keywords are present.
        """
        results = []
        if not any(kw in data for kw in context_keywords):
            return results
        scan_result = self.yara_runner.scan(data)
        for match in scan_result["matches"]:
            results.append({
                "rule": match["rule_name"],
                "excerpt": match["match_excerpt"]
            })
        return results