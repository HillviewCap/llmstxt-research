from typing import Dict, Any, Optional


class DomainReputationService:
    """
    Mocked domain reputation integration.
    """
    def get_reputation(self, domain: str) -> float:
        # Mock: return 0.9 for known good, 0.2 for suspicious, 0.5 for unknown
        if domain.endswith(".gov") or domain.endswith(".edu"):
            return 0.9
        elif domain.endswith(".xyz") or "suspicious" in domain:
            return 0.2
        return 0.5


class ContentPurposeDetector:
    """
    Detects the likely purpose of content (e.g., credential, prompt, code, documentation).
    """
    def detect(self, content: str) -> str:
        content = content.lower()
        if "password" in content or "api_key" in content:
            return "credential"
        if "prompt" in content or "instruction" in content:
            return "prompt"
        if "def " in content or "function" in content:
            return "code"
        if "introduction" in content or "overview" in content:
            return "documentation"
        return "unknown"


class BaselineComparator:
    """
    Compares findings to a baseline for anomaly/contextual scoring.
    """
    def __init__(self, baseline: Optional[Dict[str, Any]] = None):
        self.baseline = baseline or {}

    def compare(self, finding: Dict[str, Any]) -> float:
        """
        Returns a similarity score (0-1) to the baseline (mocked).
        """
        # Mock: if finding type in baseline, higher similarity
        finding_type = finding.get("type", "")
        if finding_type in self.baseline.get("types", []):
            return 0.8
        return 0.4


class ContextualAdjuster:
    """
    Adjusts risk/confidence based on context.
    """
    def adjust(self, score: float, context: Dict[str, Any]) -> float:
        """
        Example: lower risk if domain is reputable, raise if purpose is credential.
        """
        adjustment = 1.0
        if context.get("domain_reputation", 0.5) > 0.8:
            adjustment *= 0.8  # Lower risk for reputable domains
        if context.get("purpose") == "credential":
            adjustment *= 1.2  # Raise risk for credentials
        if context.get("baseline_similarity", 0.4) > 0.7:
            adjustment *= 0.9  # Lower risk if similar to baseline
        return min(max(score * adjustment, 0.0), 1.0)