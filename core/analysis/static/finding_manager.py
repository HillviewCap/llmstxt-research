from typing import List, Dict, Any, Optional, Set, Tuple

class FindingManagerError(Exception):
    pass

class FindingManager:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self._dedup_set: Set[Tuple] = set()

    def normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        # Standardize finding fields
        normalized = {
            "rule_id": finding.get("rule_id"),
            "path": finding.get("path"),
            "start": finding.get("start"),
            "end": finding.get("end"),
            "message": finding.get("extra", {}).get("message"),
            "category": finding.get("category", "Uncategorized"),
            "priority": finding.get("priority", "Medium"),
            "severity": self.classify_severity(finding),
        }
        
        # Include code block ID if present
        if "code_block_id" in finding:
            normalized["code_block_id"] = finding["code_block_id"]
            
        return normalized

    def classify_severity(self, finding: Dict[str, Any]) -> str:
        # Map priority/category to severity
        priority = finding.get("priority", "Medium").lower()
        if priority in ("high", "critical"):
            return "High"
        elif priority in ("medium",):
            return "Medium"
        elif priority in ("low",):
            return "Low"
        return "Medium"

    def store_finding(self, finding: Dict[str, Any]) -> bool:
        # Deduplicate based on (rule_id, path, start, end)
        key = (
            finding.get("rule_id"),
            finding.get("path"),
            str(finding.get("start")),
            str(finding.get("end")),
        )
        if key in self._dedup_set:
            return False
        self._dedup_set.add(key)
        self.findings.append(self.normalize_finding(finding))
        return True

    def get_all_findings(self) -> List[Dict[str, Any]]:
        return self.findings

    def clear(self):
        self.findings.clear()
        self._dedup_set.clear()