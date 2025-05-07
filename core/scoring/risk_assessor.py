from typing import Dict, Any, Optional

from .scoring_model import ScoringModel, ScoringModelConfig
from .classification import (
    SeverityClassifier,
    CategoryTaxonomy,
    FindingCategorizer,
    ConfidenceAssessor,
)
from .context_analyzer import (
    DomainReputationService,
    ContentPurposeDetector,
    BaselineComparator,
    ContextualAdjuster,
)


class RiskAssessor:
    def __init__(
        self,
        scoring_config: Dict[str, Any] = None,
        severity_thresholds: Dict[str, float] = None,
        category_keywords: Dict[str, list] = None,
        baseline: Optional[Dict[str, Any]] = None,
    ):
        print("Initializing RiskAssessor with default values")
        
        # Default values if not provided
        if scoring_config is None:
            scoring_config = {
                "dimensions": {
                    "impact": 0.4,
                    "likelihood": 0.3,
                    "exposure": 0.3
                },
                "confidence_weight": 0.8
            }
            
        if severity_thresholds is None:
            severity_thresholds = {
                "critical": 0.8,
                "high": 0.6,
                "medium": 0.4,
                "low": 0.2,
                "info": 0.0
            }
            
        if category_keywords is None:
            category_keywords = {
                "injection": ["sql", "command", "injection", "execute"],
                "authentication": ["auth", "login", "password", "credential"],
                "data_exposure": ["leak", "exposure", "sensitive", "pii"],
                "configuration": ["config", "setting", "environment", "setup"]
            }
        self.scoring_model = ScoringModel(
            ScoringModelConfig(
                dimensions=scoring_config.get("dimensions", {}),
                confidence_weight=scoring_config.get("confidence_weight", 1.0),
            )
        )
        self.severity_classifier = SeverityClassifier(severity_thresholds)
        self.taxonomy = CategoryTaxonomy(category_keywords)
        self.categorizer = FindingCategorizer(self.taxonomy)
        self.confidence_assessor = ConfidenceAssessor()
        self.domain_reputation = DomainReputationService()
        self.purpose_detector = ContentPurposeDetector()
        self.baseline_comparator = BaselineComparator(baseline)
        self.contextual_adjuster = ContextualAdjuster()

    def assess(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        # 1. Contextual analysis
        domain = finding.get("domain", "")
        content = finding.get("content", "")
        context = {
            "domain_reputation": self.domain_reputation.get_reputation(domain) if domain else 0.5,
            "purpose": self.purpose_detector.detect(content),
            "baseline_similarity": self.baseline_comparator.compare(finding),
        }

        # 2. Dimension scoring (mock: use finding['scores'] or zeros)
        dimension_scores = finding.get("scores", {dim: 0.0 for dim in self.scoring_model.config.dimensions})

        # 3. Confidence
        confidence = self.confidence_assessor.assess(finding)

        # 4. Aggregate risk score
        scoring_result = self.scoring_model.score(dimension_scores, confidence=confidence)
        aggregate_score = scoring_result["aggregate_score"]

        # 5. Contextual adjustment
        adjusted_score = self.contextual_adjuster.adjust(aggregate_score, context)

        # 6. Classification
        severity = self.severity_classifier.classify(adjusted_score)
        categories = self.categorizer.categorize_finding(finding)

        return {
            "aggregate_score": aggregate_score,
            "adjusted_score": adjusted_score,
            "severity": severity,
            "categories": categories,
            "confidence": confidence,
            "context": context,
            "breakdown": scoring_result["breakdown"],
        }