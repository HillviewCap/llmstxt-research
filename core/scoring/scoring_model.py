import yaml
from typing import Dict, Any, List, Optional

CONFIG_FILE_PATH = "config/scoring_config.yaml"


class ScoringModelConfig:
    def __init__(self, dimensions: Dict[str, float], confidence_weight: float = 1.0):
        """
        :param dimensions: Dict of dimension name to weight (e.g., {'impact': 0.5, 'likelihood': 0.3, 'exposure': 0.2})
        :param confidence_weight: Weight to apply to the confidence score in aggregation
        """
        self.dimensions = dimensions
        self.confidence_weight = confidence_weight


class ScoringModel:
    def __init__(self, config: Optional[ScoringModelConfig] = None, config_path: str = CONFIG_FILE_PATH):
        if config is None:
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                
                model_config_data = yaml_config.get('scoring_model', {})
                dimensions = model_config_data.get('dimensions', {})
                confidence_weight = model_config_data.get('confidence_weight', 1.0)

                if not dimensions:
                    print(f"Warning: 'dimensions' not found or empty in {config_path}. Using default dimensions.")
                    dimensions = {
                        "impact": 0.4,
                        "likelihood": 0.3,
                        "exposure": 0.3
                    }
                
                config = ScoringModelConfig(
                    dimensions=dimensions,
                    confidence_weight=confidence_weight
                )
                print(f"Loaded ScoringModelConfig from {config_path}")
            except FileNotFoundError:
                print(f"Error: Config file {config_path} not found. Using default ScoringModelConfig.")
                config = ScoringModelConfig(
                    dimensions={
                        "impact": 0.4,
                        "likelihood": 0.3,
                        "exposure": 0.3
                    },
                    confidence_weight=0.8
                )
            except yaml.YAMLError as e:
                print(f"Error parsing YAML from {config_path}: {e}. Using default ScoringModelConfig.")
                config = ScoringModelConfig(
                    dimensions={
                        "impact": 0.4,
                        "likelihood": 0.3,
                        "exposure": 0.3
                    },
                    confidence_weight=0.8
                )
            except Exception as e:
                print(f"An unexpected error occurred while loading config from {config_path}: {e}. Using default ScoringModelConfig.")
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
    def calculate_confidence(evidence: List[Dict[str, Any]]) -> float:
        """
        Calculate confidence based on the quality and quantity of evidence.
        Evidence items are expected to be dictionaries, e.g.,
        {'source': 'YARA_RULE_HIGH_CONFIDENCE', 'strength': 0.9, 'details': 'Matched specific pattern'}
        {'source': 'HEURISTIC_LOW_CONFIDENCE', 'strength': 0.4, 'details': 'General suspicious keyword'}

        :param evidence: A list of evidence dictionaries.
        :return: A confidence score between 0.0 and 1.0.
        """
        if not evidence:
            return 0.3  # Default low confidence for no evidence

        total_strength = 0.0
        num_strong_sources = 0
        
        # Define some example evidence source "reliabilities"
        # These could also be part of the configuration
        source_reliability = {
            "YARA_RULE_HIGH_CONFIDENCE": 0.9,
            "SEMGREP_PRECISE_MATCH": 0.85,
            "TRUFFLEHOG_VERIFIED": 0.95,
            "BEHAVIOR_CONFIRMED": 0.8,
            "HEURISTIC_GENERAL": 0.6,
            "TEXT_PATTERN_WEAK": 0.4,
            "DEFAULT_SOURCE": 0.5 # For sources not explicitly listed
        }

        for item in evidence:
            source_type = item.get("source", "DEFAULT_SOURCE")
            strength = item.get("strength", source_reliability.get(source_type, 0.5))
            
            reliability_modifier = source_reliability.get(source_type, source_reliability["DEFAULT_SOURCE"])
            
            # Weighted strength based on source reliability and reported strength
            adjusted_strength = strength * reliability_modifier
            total_strength += adjusted_strength
            
            if reliability_modifier >= 0.75: # Consider sources with reliability >= 0.75 as "strong"
                num_strong_sources +=1

        # Normalize based on number of evidence items
        # This is a simple approach; more sophisticated aggregation could be used
        if not evidence: # Should be caught by the first check, but for safety
             return 0.3

        average_strength = total_strength / len(evidence)

        # Boost confidence if multiple strong, corroborating sources are present
        corroboration_bonus = 0.0
        if num_strong_sources > 1:
            corroboration_bonus = min(0.1 * (num_strong_sources -1), 0.2) # Cap bonus

        final_confidence = average_strength + corroboration_bonus
        
        return min(max(final_confidence, 0.0), 1.0) # Ensure score is between 0 and 1