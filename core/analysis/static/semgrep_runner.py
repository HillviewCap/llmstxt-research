import subprocess
import json
import os
from typing import List, Dict, Any, Optional

class SemgrepRunnerError(Exception):
    pass

class SemgrepRunner:
    def __init__(self, rules_path: str, config: Optional[Dict[str, Any]] = None):
        self.rules_path = rules_path
        self.config = config or {}
        self.rules = self._load_rules()
        self.rule_metadata = self._extract_rule_metadata()

    def _load_rules(self) -> List[str]:
        if not os.path.isdir(self.rules_path):
            raise SemgrepRunnerError(f"Rules path does not exist: {self.rules_path}")
        rules = []
        for file in os.listdir(self.rules_path):
            if file.endswith(".yml") or file.endswith(".yaml"):
                rules.append(os.path.join(self.rules_path, file))
        if not rules:
            raise SemgrepRunnerError("No Semgrep rules found in the specified directory.")
        return rules

    def _extract_rule_metadata(self) -> Dict[str, Dict[str, Any]]:
        # Extracts priority and category from rule YAML headers (simple parsing)
        metadata = {}
        for rule_file in self.rules:
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                rule_id, category, priority = None, "Uncategorized", "Medium"
                for line in lines:
                    if line.strip().startswith("id:"):
                        rule_id = line.split(":", 1)[1].strip()
                    if line.strip().startswith("category:"):
                        category = line.split(":", 1)[1].strip()
                    if line.strip().startswith("priority:"):
                        priority = line.split(":", 1)[1].strip()
                    if rule_id and category and priority:
                        break
                if rule_id:
                    metadata[rule_id] = {"category": category, "priority": priority, "file": rule_file}
            except Exception:
                continue
        return metadata

    def run(self, target_path: str, languages: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if not os.path.exists(target_path):
            raise SemgrepRunnerError(f"Target path does not exist: {target_path}")
        cmd = [
            "semgrep",
            "--json",
            "--config",
            self.rules_path,
            target_path
        ]
        if languages:
            for lang in languages:
                cmd.extend(["--lang", lang])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return self.parse_results(result.stdout)
        except subprocess.CalledProcessError as e:
            raise SemgrepRunnerError(f"Semgrep failed: {e.stderr}")

    def parse_results(self, output: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(output)
            findings = []
            for result in data.get("results", []):
                rule_id = result.get("check_id")
                finding = {
                    "rule_id": rule_id,
                    "path": result.get("path"),
                    "start": result.get("start"),
                    "end": result.get("end"),
                    "extra": result.get("extra", {}),
                    "category": self.rule_metadata.get(rule_id, {}).get("category", "Uncategorized"),
                    "priority": self.rule_metadata.get(rule_id, {}).get("priority", "Medium"),
                }
                findings.append(finding)
            return findings
        except Exception as e:
            raise SemgrepRunnerError(f"Failed to parse Semgrep output: {e}")

    def list_rules(self) -> List[Dict[str, Any]]:
        return [
            {"id": rule_id, **meta}
            for rule_id, meta in self.rule_metadata.items()
        ]