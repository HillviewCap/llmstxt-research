from typing import Dict, Any, Optional, List

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
        # Configuration for components like DomainReputationService, ContentPurposeDetector,
        # BaselineComparator, and ContextualAdjuster can be passed here if needed,
        # or they can load their own from specific files if designed that way.
        # For now, we rely on their internal defaults or YAML loading for some.
        baseline_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        known_domains_for_reputation: Optional[Dict[str, float]] = None,
        content_purpose_definitions: Optional[Dict[str, Dict[str, Any]]] = None,
        contextual_adjustment_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initializes the RiskAssessor and its sub-components.
        Sub-components like ScoringModel, SeverityClassifier, CategoryTaxonomy,
        and ConfidenceAssessor are expected to load their primary configurations
        from 'config/scoring_config.yaml' or use their improved defaults.
        Other components can be configured via parameters.
        """
        print("Initializing RiskAssessor...")

        # ScoringModel will load from 'config/scoring_config.yaml' or use defaults
        self.scoring_model = ScoringModel()

        # SeverityClassifier will load 'severity_thresholds' from 'config/scoring_config.yaml'
        self.severity_classifier = SeverityClassifier()

        # CategoryTaxonomy will load 'category_keywords' from 'config/scoring_config.yaml'
        self.taxonomy = CategoryTaxonomy()
        self.categorizer = FindingCategorizer(self.taxonomy) # FindingCategorizer uses the taxonomy instance

        # ConfidenceAssessor will load 'evidence_source_reliability' from 'config/scoring_config.yaml' if present
        self.confidence_assessor = ConfidenceAssessor() # Relies on its own config loading/defaults

        # Contextual Analysis Components
        # These can be configured via passed arguments or use their robust defaults.
        self.domain_reputation = DomainReputationService(known_domains=known_domains_for_reputation)
        self.purpose_detector = ContentPurposeDetector(purpose_definitions=content_purpose_definitions)
        self.baseline_comparator = BaselineComparator(baseline_data=baseline_data)
        self.contextual_adjuster = ContextualAdjuster(adjustment_config=contextual_adjustment_config)
        
        print("RiskAssessor initialized.")

    def assess(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs a comprehensive risk assessment for a given finding.

        :param finding: A dictionary representing the finding, expected to contain keys like
                        'description', 'evidence', 'scores' (for dimensions), 'domain' (optional),
                        'content' (optional, for purpose detection), 'file_path' (optional, for baseline context).
        :return: A dictionary containing the detailed risk assessment.
        """
        
        # 1. Initial data extraction from finding
        description = finding.get("description", "")
        evidence_list = finding.get("evidence", []) # Expected by confidence assessors
        dimension_scores = finding.get("scores", {dim: 0.0 for dim in self.scoring_model.config.dimensions})
        content_for_purpose_detection = finding.get("content", description) # Use description if no specific content
        domain_to_check = finding.get("domain")
        file_path_for_baseline = finding.get("file_path")


        # 2. Contextual Analysis Pre-computation
        domain_reputation_score = self.domain_reputation.get_reputation(domain_to_check) if domain_to_check else None
        content_purposes = self.purpose_detector.detect(content_for_purpose_detection, top_n=3) # Get top 3 purposes
        
        # Pass the finding itself to compare, and optionally a specific context_id (like file_path)
        baseline_info = self.baseline_comparator.compare(finding, context_id=file_path_for_baseline)

        # Prepare contextual_info for the adjuster
        contextual_info_for_adjustment = {
            "domain_reputation_score": domain_reputation_score,
            "content_purposes": content_purposes, # List of purposes
            "baseline_info": baseline_info, # Dict from BaselineComparator
            # Other finding-specific details can be added if ContextualAdjuster uses them
            "finding_type": finding.get("type"),
            "source_tool": finding.get("source_tool")
        }

        # 3. Confidence Assessment
        # The assess method in ConfidenceAssessor now takes the finding dict
        raw_confidence = self.confidence_assessor.assess(finding)
        # The scoring_model's calculate_confidence also takes the evidence list directly
        # We might want to unify this or decide which confidence (raw or model-calculated) to use.
        # For now, let's assume raw_confidence is the primary one for the scoring model input.
        # Alternatively, scoring_model.calculate_confidence can be called here if preferred.
        
        # Let's use the evidence from the finding for the main scoring model's confidence calculation
        # This aligns with the updated ScoringModel.calculate_confidence
        model_input_confidence = self.scoring_model.calculate_confidence(evidence_list)


        # 4. Scoring Model - Calculate Aggregate Risk Score
        # Uses dimension_scores from the finding and the model_input_confidence.
        scoring_result = self.scoring_model.score(dimension_scores, confidence=model_input_confidence)
        aggregate_score = scoring_result["aggregate_score"]
        # The confidence reported by scoring_result is the one it used/calculated.

        # 5. Contextual Adjustment of the Aggregate Score
        # The ContextualAdjuster uses the pre-computed contextual_info_for_adjustment.
        final_adjusted_score = self.contextual_adjuster.adjust(aggregate_score, contextual_info_for_adjustment)

        # 6. Classification based on the final_adjusted_score
        severity = self.severity_classifier.classify(final_adjusted_score)
        # Categorizer uses the original finding details (e.g., description)
        category_details = self.categorizer.categorize_finding(finding)

        return {
            "raw_dimension_scores": dimension_scores,
            "raw_confidence_from_assessor": raw_confidence, # Confidence from standalone assessor
            "model_input_confidence": model_input_confidence, # Confidence used by ScoringModel
            "aggregate_score_pre_adjustment": aggregate_score,
            "final_adjusted_score": final_adjusted_score,
            "severity": severity,
            "categories": category_details.get("categories", ["uncategorized"]),
            "primary_category": category_details.get("primary_category", "uncategorized"),
            "scoring_model_breakdown": scoring_result["breakdown"],
            "contextual_factors": { # Store the computed contextual factors for transparency
                "domain_reputation_used": domain_reputation_score,
                "detected_content_purposes": content_purposes,
                "baseline_comparison_result": baseline_info,
                "full_adjustment_input_context": contextual_info_for_adjustment # For debugging/transparency
            }
        }