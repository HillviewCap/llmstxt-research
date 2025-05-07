import os
import yaml
from typing import List, Dict, Any, Optional

class RuleManagerError(Exception):
    pass

class RuleManager:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        rules = []
        if not os.path.isdir(self.rules_path):
            raise RuleManagerError(f"Rules path does not exist: {self.rules_path}")
        for file in os.listdir(self.rules_path):
            if file.endswith(".yml") or file.endswith(".yaml"):
                rule_file = os.path.join(self.rules_path, file)
                try:
                    with open(rule_file, "r", encoding="utf-8") as f:
                        rule = yaml.safe_load(f)
                        rule["_file"] = rule_file
                        rules.append(rule)
                except Exception as e:
                    continue
        return rules

    def get_rules_for_language(self, language: str) -> List[Dict[str, Any]]:
        # Assumes 'languages' field in rule metadata
        applicable = []
        for rule in self.rules:
            langs = rule.get("languages") or rule.get("language")
            if not langs:
                continue
            if isinstance(langs, str):
                langs = [langs]
            if language.lower() in [l.lower() for l in langs]:
                applicable.append(rule)
        return applicable

    def list_rule_ids(self) -> List[str]:
        return [rule.get("id", "unknown") for rule in self.rules]

    def get_rule_doc(self, rule_id: str) -> Optional[str]:
        for rule in self.rules:
            if rule.get("id") == rule_id:
                return rule.get("message") or rule.get("description")
        return None

    def test_rule(self, rule_id: str, test_code: str) -> Dict[str, Any]:
        # Framework stub: In practice, would invoke Semgrep with the rule and test_code
        # Here, just returns a stub result
        rule = next((r for r in self.rules if r.get("id") == rule_id), None)
        if not rule:
            raise RuleManagerError(f"Rule not found: {rule_id}")
        return {
            "rule_id": rule_id,
            "test_code": test_code,
            "result": "Not implemented (stub)"
        }