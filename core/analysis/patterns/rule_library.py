"""
Rule Library for LLMs.txt Threats
Defines and manages custom YARA rules for LLM manipulation and evasion detection.
Includes documentation and a simple testing framework.
"""

from typing import List, Dict, Any
from .yara_runner import YaraRuleManager

class RuleDocumentation:
    """
    Stores documentation for each rule.
    """
    def __init__(self):
        self.docs: Dict[str, str] = {}

    def add_doc(self, rule_name: str, doc: str):
        self.docs[rule_name] = doc

    def get_doc(self, rule_name: str) -> str:
        return self.docs.get(rule_name, "No documentation available.")

class LLMRuleLibrary:
    """
    Manages a library of YARA rules for LLM threats.
    """
    def __init__(self, rule_manager: YaraRuleManager, doc_manager: RuleDocumentation):
        self.rule_manager = rule_manager
        self.doc_manager = doc_manager
        self._load_rules()

    def _load_rules(self):
        # Example: LLM prompt injection pattern
        self.rule_manager.add_rule(
            name="llm_prompt_injection",
            condition="ignore previous instructions",
            meta={"threat": "manipulation", "severity": "high"}
        )
        self.doc_manager.add_doc(
            "llm_prompt_injection",
            "Detects attempts to override or ignore previous LLM instructions (prompt injection)."
        )

        # Example: Evasion technique
        self.rule_manager.add_rule(
            name="llm_evasion_obfuscation",
            condition="bypass content filter",
            meta={"threat": "evasion", "severity": "medium"}
        )
        self.doc_manager.add_doc(
            "llm_evasion_obfuscation",
            "Detects phrases commonly used to evade LLM content filters."
        )

        # Example: Data extraction
        self.rule_manager.add_rule(
            name="llm_sensitive_data_extraction",
            condition="extract confidential",
            meta={"threat": "data_extraction", "severity": "high"}
        )
        self.doc_manager.add_doc(
            "llm_sensitive_data_extraction",
            "Detects attempts to extract confidential or sensitive information from LLMs."
        )

    def list_rules(self) -> List[str]:
        return self.rule_manager.list_rules()

    def get_rule_doc(self, rule_name: str) -> str:
        return self.doc_manager.get_doc(rule_name)

class RuleTestFramework:
    """
    Simple framework to test rules against sample data.
    """
    def __init__(self, rule_manager: YaraRuleManager):
        self.runner = rule_manager

    def test_rule(self, rule_name: str, test_data: str) -> bool:
        rule = self.runner.get_rule(rule_name)
        if not rule:
            return False
        return rule.match(test_data)

    def test_all(self, test_cases: Dict[str, str]) -> Dict[str, bool]:
        results = {}
        for rule_name, data in test_cases.items():
            results[rule_name] = self.test_rule(rule_name, data)
        return results