from typing import Dict, Any, List, Optional


class SeverityClassifier:
    def __init__(self, thresholds: Dict[str, float]):
        """
        :param thresholds: Dict mapping severity label to minimum score (e.g., {'critical': 0.85, 'high': 0.7, ...})
        """
        self.thresholds = sorted(thresholds.items(), key=lambda x: -x[1])  # Descending by score

    def classify(self, score: float) -> str:
        for label, threshold in self.thresholds:
            if score >= threshold:
                return label
        return "info"


class CategoryTaxonomy:
    def __init__(self, categories: Dict[str, List[str]]):
        """
        :param categories: Dict mapping category name to list of keywords
        """
        self.categories = categories

    def categorize(self, finding: Dict[str, Any]) -> List[str]:
        """
        Categorize a finding based on its description/content.
        """
        description = finding.get("description", "").lower()
        matched = []
        for category, keywords in self.categories.items():
            if any(kw.lower() in description for kw in keywords):
                matched.append(category)
        return matched or ["uncategorized"]


class FindingCategorizer:
    def __init__(self, taxonomy: CategoryTaxonomy):
        self.taxonomy = taxonomy

    def categorize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        categories = self.taxonomy.categorize(finding)
        return {
            "categories": categories,
            "primary_category": categories[0] if categories else "uncategorized"
        }


class ConfidenceAssessor:
    @staticmethod
    def assess(finding: Dict[str, Any]) -> float:
        """
        Mock confidence assessment based on finding metadata.
        """
        evidence = finding.get("evidence", [])
        if not evidence:
            return 0.5
        # Example: more evidence = higher confidence, capped at 1.0
        return min(0.5 + 0.1 * len(evidence), 1.0)