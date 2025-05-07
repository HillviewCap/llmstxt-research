import yaml
from typing import Dict, Any, List, Optional

CONFIG_FILE_PATH = "config/scoring_config.yaml"


class SeverityClassifier:
    def __init__(self, thresholds: Optional[Dict[str, float]] = None, config_path: str = CONFIG_FILE_PATH):
        """
        :param thresholds: Dict mapping severity label to minimum score (e.g., {'critical': 0.85, 'high': 0.7, ...})
        :param config_path: Path to the YAML configuration file.
        """
        if thresholds is None:
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                loaded_thresholds = yaml_config.get('severity_thresholds')
                if not loaded_thresholds or not isinstance(loaded_thresholds, dict):
                    print(f"Warning: 'severity_thresholds' not found or invalid in {config_path}. Using default thresholds.")
                    loaded_thresholds = {"critical": 0.85, "high": 0.7, "medium": 0.5, "low": 0.3, "info": 0.0}
                thresholds = loaded_thresholds
                print(f"Loaded severity thresholds from {config_path}")
            except FileNotFoundError:
                print(f"Error: Config file {config_path} not found. Using default severity thresholds.")
                thresholds = {"critical": 0.85, "high": 0.7, "medium": 0.5, "low": 0.3, "info": 0.0}
            except yaml.YAMLError as e:
                print(f"Error parsing YAML from {config_path}: {e}. Using default severity thresholds.")
                thresholds = {"critical": 0.85, "high": 0.7, "medium": 0.5, "low": 0.3, "info": 0.0}
            except Exception as e:
                print(f"An unexpected error occurred while loading severity thresholds from {config_path}: {e}. Using default thresholds.")
                thresholds = {"critical": 0.85, "high": 0.7, "medium": 0.5, "low": 0.3, "info": 0.0}
        
        self.thresholds = sorted(thresholds.items(), key=lambda x: -x[1])  # Descending by score

    def classify(self, score: float) -> str:
        for label, threshold in self.thresholds:
            if score >= threshold:
                return label
        return "info"


class CategoryTaxonomy:
    def __init__(self, categories: Optional[Dict[str, List[str]]] = None, config_path: str = CONFIG_FILE_PATH):
        """
        :param categories: Dict mapping category name to list of keywords
        :param config_path: Path to the YAML configuration file.
        """
        if categories is None:
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                loaded_categories = yaml_config.get('category_keywords')
                if not loaded_categories or not isinstance(loaded_categories, dict):
                    print(f"Warning: 'category_keywords' not found or invalid in {config_path}. Using default categories.")
                    loaded_categories = {
                        "credential_exposure": ["password", "api_key", "secret"],
                        "uncategorized_default": ["issue", "finding"] # Default if nothing else loads
                    }
                categories = loaded_categories
                print(f"Loaded category keywords from {config_path}")
            except FileNotFoundError:
                print(f"Error: Config file {config_path} not found. Using default category keywords.")
                categories = {
                    "credential_exposure": ["password", "api_key", "secret"],
                    "uncategorized_default": ["issue", "finding"]
                }
            except yaml.YAMLError as e:
                print(f"Error parsing YAML from {config_path}: {e}. Using default category keywords.")
                categories = {
                    "credential_exposure": ["password", "api_key", "secret"],
                    "uncategorized_default": ["issue", "finding"]
                }
            except Exception as e:
                print(f"An unexpected error occurred while loading category keywords from {config_path}: {e}. Using default categories.")
                categories = {
                    "credential_exposure": ["password", "api_key", "secret"],
                    "uncategorized_default": ["issue", "finding"]
                }
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
    def assess(finding: Dict[str, Any], config_path: str = CONFIG_FILE_PATH) -> float:
        """
        Assess confidence in a finding based on its evidence.
        Evidence items are expected to be dictionaries, e.g.,
        {'source': 'YARA_RULE_HIGH_CONFIDENCE', 'strength': 0.9, 'details': '...'}
        
        Relies on 'evidence_source_reliability' from the config file if available.

        :param finding: The finding dictionary, expected to contain an 'evidence' list.
        :param config_path: Path to the YAML configuration file.
        :return: A confidence score between 0.0 and 1.0.
        """
        evidence = finding.get("evidence")
        if not evidence or not isinstance(evidence, list): # Check if evidence is a list
            return 0.3  # Default low confidence for no or malformed evidence

        total_strength = 0.0
        num_strong_sources = 0
        
        # Default source reliabilities, can be overridden by config
        source_reliability_config = {
            "YARA_RULE_HIGH_CONFIDENCE": 0.9,
            "SEMGREP_PRECISE_MATCH": 0.85,
            "TRUFFLEHOG_VERIFIED": 0.95,
            "BEHAVIOR_CONFIRMED": 0.8,
            "HEURISTIC_GENERAL": 0.6,
            "TEXT_PATTERN_WEAK": 0.4,
            "MANUAL_VERIFICATION": 1.0, # Highest confidence
            "DEFAULT_SOURCE": 0.5
        }

        try:
            with open(config_path, 'r') as f:
                yaml_config = yaml.safe_load(f)
            loaded_reliability = yaml_config.get('evidence_source_reliability')
            if loaded_reliability and isinstance(loaded_reliability, dict):
                source_reliability_config.update(loaded_reliability)
                # print(f"Loaded evidence source reliability from {config_path}")
        except FileNotFoundError:
            # print(f"Warning: Config file {config_path} not found for evidence reliability. Using defaults.")
            pass # Defaults are already set
        except yaml.YAMLError as e:
            # print(f"Warning: Error parsing YAML for evidence reliability from {config_path}: {e}. Using defaults.")
            pass # Defaults are already set
        except Exception as e:
            # print(f"Warning: An unexpected error occurred loading evidence reliability from {config_path}: {e}. Using defaults.")
            pass


        for item in evidence:
            if not isinstance(item, dict): # Skip malformed evidence items
                continue
            source_type = item.get("source", "DEFAULT_SOURCE")
            # Use strength from evidence if provided, otherwise from config/default for the source type
            strength = item.get("strength", source_reliability_config.get(source_type, source_reliability_config["DEFAULT_SOURCE"]))
            
            reliability_modifier = source_reliability_config.get(source_type, source_reliability_config["DEFAULT_SOURCE"])
            
            adjusted_strength = strength * reliability_modifier
            total_strength += adjusted_strength
            
            if reliability_modifier >= 0.75:
                num_strong_sources +=1

        if not evidence: # Should be caught earlier, but as a safeguard
             return 0.3

        average_strength = total_strength / len(evidence) if len(evidence) > 0 else 0.3


        corroboration_bonus = 0.0
        if num_strong_sources > 1:
            corroboration_bonus = min(0.1 * (num_strong_sources -1), 0.2)

        final_confidence = average_strength + corroboration_bonus
        
        return min(max(final_confidence, 0.0), 1.0)