from typing import Dict, Any, List, Optional


class ScoringModelConfig:
    def __init__(self, dimensions: Dict[str, float], confidence_weight: float = 1.0):
        """
        :param dimensions: Dict of dimension name to weight (e.g., {'impact': 0.5, 'likelihood': 0.3, 'exposure': 0.2})
        :param confidence_weight: Weight to apply to the confidence score in aggregation
        """
        self.dimensions = dimensions
        self.confidence_weight = confidence_weight


class ScoringModel:
    def __init__(self, config: ScoringModelConfig = None):
        if config is None:
            # Create a default configuration
            print("Creating default ScoringModelConfig")
            config = ScoringModelConfig(
                dimensions={
                    "impact": 0.4,
                    "likelihood": 0.3,
                    "exposure": 0.3
                },
                confidence_weight=0.8
            )
        self.config = config

    def score(self, dimension_scores: Dict[str, float], confidence: Optional[float] = None) -> Dict[str, Any]:
        """
        Calculate the aggregate risk score using weighted dimensions and confidence.

        :param dimension_scores: Dict of dimension name to score (0-1)
        :param confidence: Optional confidence score (0-1)
        :return: Dict with aggregate score, weighted breakdown, and confidence
        """
        weighted_sum = 0.0
        total_weight = 0.0
        breakdown = {}

        for dim, weight in self.config.dimensions.items():
            score = dimension_scores.get(dim, 0.0)
            weighted = score * weight
            breakdown[dim] = {"score": score, "weight": weight, "weighted": weighted}
            weighted_sum += weighted
            total_weight += weight

        # Normalize if weights don't sum to 1
        aggregate = weighted_sum / total_weight if total_weight > 0 else 0.0

        # Confidence adjustment
        if confidence is not None:
            aggregate = self._apply_confidence(aggregate, confidence)
        else:
            confidence = 1.0  # Default to max confidence

        return {
            "aggregate_score": aggregate,
            "breakdown": breakdown,
            "confidence": confidence
        }

    def _apply_confidence(self, score: float, confidence: float) -> float:
        """
        Adjust the aggregate score by the confidence level.
        """
        # Simple linear adjustment; can be replaced with more complex logic
        return score * (confidence * self.config.confidence_weight)

    @staticmethod
    def calculate_confidence(evidence: List[Any]) -> float:
        """
        Mock confidence calculation based on evidence list.
        """
        if not evidence:
            return 0.5  # Default low confidence
        # Example: more evidence = higher confidence, capped at 1.0
        return min(0.5 + 0.1 * len(evidence), 1.0)