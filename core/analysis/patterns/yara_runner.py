"""
YARA Runner Module (Mocked)
Handles YARA rule management, scanning, and result normalization for LLMs.txt Security Analysis Platform.
"""

from typing import List, Dict, Any, Optional
import time

class MockYaraRule:
    def __init__(self, name: str, condition: str, meta: Optional[Dict[str, Any]] = None):
        self.name = name
        self.condition = condition
        self.meta = meta or {}

    def match(self, data: str) -> bool:
        # Mock: If the condition string is in the data, it's a match
        return self.condition in data

class YaraRuleManager:
    """
    Manages YARA rules: add, remove, list, and retrieve rules.
    """
    def __init__(self):
        self.rules: Dict[str, MockYaraRule] = {}

    def add_rule(self, name: str, condition: str, meta: Optional[Dict[str, Any]] = None):
        self.rules[name] = MockYaraRule(name, condition, meta)

    def remove_rule(self, name: str):
        if name in self.rules:
            del self.rules[name]

    def get_rule(self, name: str) -> Optional[MockYaraRule]:
        return self.rules.get(name)

    def list_rules(self) -> List[str]:
        return list(self.rules.keys())

class YaraRunner:
    """
    Handles scanning data with YARA rules and normalizing results.
    """
    def __init__(self, rule_manager: YaraRuleManager):
        self.rule_manager = rule_manager

    def scan(self, data: str) -> List[Dict[str, Any]]:
        """
        Scans the input data with all loaded YARA rules.
        Returns a list of normalized match results.
        """
        start_time = time.time()
        results = []
        for rule in self.rule_manager.rules.values():
            if rule.match(data):
                results.append(self._normalize_result(rule, data))
        elapsed = time.time() - start_time
        return {
            "matches": results,
            "scan_time_ms": int(elapsed * 1000),
            "rule_count": len(self.rule_manager.rules)
        }

    def _normalize_result(self, rule: MockYaraRule, data: str) -> Dict[str, Any]:
        """
        Normalizes the result of a YARA rule match.
        """
        return {
            "rule_name": rule.name,
            "meta": rule.meta,
            "matched_string": rule.condition,
            "match_excerpt": self._extract_excerpt(data, rule.condition),
        }

    @staticmethod
    def _extract_excerpt(data: str, pattern: str, context: int = 20) -> str:
        idx = data.find(pattern)
        if idx == -1:
            return ""
        start = max(0, idx - context)
        end = min(len(data), idx + len(pattern) + context)
        return data[start:end]