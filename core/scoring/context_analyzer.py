from typing import Dict, Any, Optional


class DomainReputationService:
    """
    Provides domain reputation scores.
    Can be initialized with a known set of domains or use fallback logic.
    """
    def __init__(self, known_domains: Optional[Dict[str, float]] = None, default_unknown_score: float = 0.5):
        """
        :param known_domains: A dictionary mapping domain names to reputation scores (0.0 to 1.0).
                              e.g., {"example.com": 0.9, "malicious-site.xyz": 0.1}
        :param default_unknown_score: The reputation score to return for domains not in known_domains
                                     and not matching fallback logic.
        """
        self.known_domains = known_domains if known_domains is not None else {}
        self.default_unknown_score = default_unknown_score
        # Example of how this could be loaded from a config file in the future:
        # self.config_path = "config/domain_reputations.yaml"
        # self._load_reputations_from_config()

    def get_reputation(self, domain: str) -> float:
        """
        Retrieves the reputation score for a given domain.
        Checks known_domains first, then applies fallback logic.
        """
        domain = domain.lower()
        if domain in self.known_domains:
            return self.known_domains[domain]

        # Fallback logic (can be expanded)
        if domain.endswith(".gov") or domain.endswith(".edu") or "internal.company.com" in domain:
            return 0.9 # Generally trusted
        elif domain.endswith(".xyz") or domain.endswith(".top") or "suspicious" in domain or "phish" in domain:
            return 0.2 # Often associated with malicious activities
        elif domain.endswith(".info") or domain.endswith(".biz"):
            return 0.4 # Slightly lower trust by default for some TLDs
        
        # Could add more sophisticated checks here, e.g., regex for known malicious patterns

        return self.default_unknown_score


class ContentPurposeDetector:
    """
    Detects the likely purpose of content (e.g., credential, prompt, code, documentation, sensitive_data, example_code).
    Uses a configurable set of keywords and patterns.
    """
    def __init__(self, purpose_definitions: Optional[Dict[str, Dict[str, Any]]] = None, default_purpose: str = "unknown"):
        """
        :param purpose_definitions: A dictionary where keys are purpose labels (e.g., "credential")
                                   and values are dictionaries containing 'keywords' (list of strings)
                                   and optionally 'patterns' (list of regex strings).
                                   Example:
                                   {
                                       "credential": {"keywords": ["password", "api_key"], "weight": 1.0},
                                       "code": {"keywords": ["def ", "function"], "patterns": [r"class\s+\w+"], "weight": 0.8},
                                       "documentation": {"keywords": ["introduction", "overview"], "weight": 0.6}
                                   }
        :param default_purpose: The purpose to return if no other purpose is detected.
        """
        if purpose_definitions is None:
            # Default definitions if none are provided
            self.purpose_definitions = {
                "credential": {"keywords": ["password", "api_key", "secret_key", "private_key", "token", "auth_token"], "weight": 1.0, "patterns": [r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|ASCA|AIDA)[A-Z0-9]{16}"]}, # AWS key pattern example
                "prompt_material": {"keywords": ["prompt:", "user query:", "llm instruction", "model input:", "system message:"], "weight": 0.9},
                "executable_code": {"keywords": ["def ", "function", "class ", "import ", "require(", "=> {"], "patterns": [r"\b(eval|exec|subprocess|os\.system)\b"], "weight": 0.85},
                "configuration_file": {"keywords": ["config:", "settings:", "connection_string", ".yaml", ".json", ".ini", "environment:"], "weight": 0.75, "patterns": [r"\[\w+\]\s*\n\s*\w+\s*="]}, # INI section
                "documentation_text": {"keywords": ["introduction", "overview", "readme", "tutorial", "how to", "guide", "faq"], "weight": 0.6},
                "example_code": {"keywords": ["example:", "sample code", "demonstration", "test case", "snippet"], "weight": 0.5},
                "sensitive_data_generic": {"keywords": ["ssn:", "credit_card:", "dob:", "patient_id:" ], "weight": 0.95},
                "log_data": {"keywords": ["timestamp:", "error:", "warning:", "info:", "debug:", "trace_id"], "weight": 0.4}
            }
            # print("Using default content purpose definitions.")
        else:
            self.purpose_definitions = purpose_definitions
        
        self.default_purpose = default_purpose
        # In a real scenario, these definitions would ideally be loaded from a config file.
        # self.config_path = "config/content_purposes.yaml"
        # self._load_purpose_definitions_from_config()


    def detect(self, content: str, top_n: int = 1) -> List[str]:
        """
        Detects the most likely purpose(s) of the content.
        Returns a list of detected purposes, sorted by confidence (highest first), limited by top_n.
        """
        content_lower = content.lower()
        detected_purposes_scores = {}

        for purpose, definition in self.purpose_definitions.items():
            score = 0.0
            keyword_hits = 0
            pattern_hits = 0

            # Check keywords
            if "keywords" in definition:
                for kw in definition["keywords"]:
                    if kw.lower() in content_lower:
                        keyword_hits += 1
            
            # Check regex patterns (if any)
            # Ensure 're' module is imported if using regex patterns extensively.
            # For now, assuming simple string checks for patterns for simplicity without adding new imports.
            # To use actual regex: import re; for pat in definition["patterns"]: if re.search(pat, content, re.IGNORECASE): pattern_hits +=1
            if "patterns" in definition:
                import re # Import locally for this method if regex is used
                for pat_str in definition["patterns"]:
                    try:
                        if re.search(pat_str, content, re.IGNORECASE):
                            pattern_hits +=1
                    except re.error:
                        # print(f"Warning: Invalid regex pattern for purpose '{purpose}': {pat_str}")
                        pass


            if keyword_hits > 0 or pattern_hits > 0:
                # Simple scoring: sum of hits, weighted by definition weight
                # More complex scoring could consider TF-IDF, keyword density, etc.
                base_score = keyword_hits + (pattern_hits * 2) # Patterns are stronger indicators
                score = base_score * definition.get("weight", 0.5)
            
            if score > 0:
                detected_purposes_scores[purpose] = score
        
        if not detected_purposes_scores:
            return [self.default_purpose]

        # Sort by score descending
        sorted_purposes = sorted(detected_purposes_scores.items(), key=lambda item: item[1], reverse=True)
        
        return [purpose for purpose, score in sorted_purposes[:top_n]]

    def detect_primary(self, content: str) -> str:
        """Helper to get only the top detected purpose."""
        purposes = self.detect(content, top_n=1)
        return purposes[0] if purposes else self.default_purpose


class BaselineComparator:
    """
    Compares new findings to a pre-established baseline of known findings or system states.
    This helps identify deviations or confirm if a finding is "expected" or "novel".
    """
    def __init__(self, baseline_data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
                 default_similarity_score: float = 0.2):
        """
        :param baseline_data: A dictionary where keys are context identifiers (e.g., 'file_path', 'component_name')
                              and values are lists of baseline finding dictionaries for that context.
                              A baseline finding might include 'type', 'signature', 'severity', 'status' (e.g., 'accepted_risk').
                              Example:
                              {
                                  "src/auth/utils.py": [
                                      {"type": "HardcodedSecret", "signature": "API_KEY_XYZ", "status": "accepted_risk_documented"},
                                      {"type": "WeakHashing", "signature": "md5_used_here", "status": "known_issue_backlog"}
                                  ],
                                  "global_config.json": [
                                      {"type": "PermissiveCORSPolicy", "signature": "*", "status": "mitigated_by_waf"}
                                  ]
                              }
        :param default_similarity_score: Score to return if no direct match or similarity is found.
        """
        self.baseline_data = baseline_data if baseline_data is not None else {}
        self.default_similarity_score = default_similarity_score
        # In a real system, baseline_data might be loaded from a database or a configuration file.
        # self.config_path = "config/baseline_findings.yaml"
        # self._load_baseline_from_config()

    def _calculate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Creates a simple hash or unique identifier for a finding based on key attributes."""
        # This is a simplistic example. A more robust hash would consider more fields
        # and be consistent. For example, sorting dictionary keys before serializing.
        key_elements = [
            finding.get("type", "unknown_type"),
            finding.get("rule_id", "no_rule"),
            str(finding.get("line_number", "na")),
            finding.get("file_path", "no_file")
        ]
        # Consider adding a hash of a snippet of the code/text if available and relevant
        # e.g., hashlib.md5(finding.get("snippet","").encode()).hexdigest()
        return "|".join(key_elements)

    def compare(self, finding: Dict[str, Any], context_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Compares a new finding against the baseline.
        Returns a dictionary containing:
            - 'similarity_score': How similar the finding is to a baseline entry (0.0 to 1.0).
            - 'baseline_status': The status of the matched baseline finding (e.g., 'accepted_risk'), if any.
            - 'is_novel': Boolean indicating if the finding is not found in the baseline for this context.
        """
        finding_hash = self._calculate_finding_hash(finding)
        target_context_id = context_id or finding.get("file_path") # Use file_path as context if no explicit one

        if not target_context_id or target_context_id not in self.baseline_data:
            return {
                "similarity_score": self.default_similarity_score,
                "baseline_status": None,
                "is_novel": True
            }

        baseline_findings_for_context = self.baseline_data[target_context_id]
        
        for baseline_finding in baseline_findings_for_context:
            baseline_hash = self._calculate_finding_hash(baseline_finding)
            if finding_hash == baseline_hash:
                # Exact match based on our simple hash
                return {
                    "similarity_score": 1.0,
                    "baseline_status": baseline_finding.get("status", "unknown_status_in_baseline"),
                    "is_novel": False
                }
            
            # Add more sophisticated partial matching logic here if needed
            # For example, if type and file_path match, but line number is slightly different,
            # or if rule_id matches but specific instance is new.
            # This could involve Jaccard similarity on keywords, etc.
            # For now, we only handle "exact" hash matches.

        # No direct match found in this context
        return {
            "similarity_score": self.default_similarity_score, # Or a slightly higher score if context matches but not exact finding
            "baseline_status": None,
            "is_novel": True
        }

    def update_baseline(self, context_id: str, finding_to_add: Dict[str, Any], status: str = "newly_added_to_baseline"):
        """
        Adds or updates a finding in the baseline for a given context.
        This is a conceptual method; actual baseline management would be more complex.
        """
        if context_id not in self.baseline_data:
            self.baseline_data[context_id] = []
        
        # Check if a similar finding already exists to avoid duplicates or to update status
        finding_hash_to_add = self._calculate_finding_hash(finding_to_add)
        for i, existing_finding in enumerate(self.baseline_data[context_id]):
            if self._calculate_finding_hash(existing_finding) == finding_hash_to_add:
                self.baseline_data[context_id][i]["status"] = status # Update status
                # Potentially update other fields of existing_finding based on finding_to_add
                # print(f"Updated finding in baseline for context '{context_id}'.")
                return

        # If not found, add it
        new_baseline_entry = finding_to_add.copy()
        new_baseline_entry["status"] = status
        self.baseline_data[context_id].append(new_baseline_entry)
        # print(f"Added new finding to baseline for context '{context_id}'.")


class ContextualAdjuster:
    """
    Adjusts an initial score (e.g., risk or confidence) based on various contextual factors.
    These factors can include domain reputation, content purpose, and baseline comparison results.
    Adjustment factors can be made configurable.
    """
    def __init__(self, adjustment_config: Optional[Dict[str, Any]] = None):
        """
        :param adjustment_config: A dictionary defining how different contextual factors influence the score.
                                  Example:
                                  {
                                      "domain_reputation": {
                                          "trusted_threshold": 0.8, "trusted_multiplier": 0.8, # Lower score
                                          "suspicious_threshold": 0.3, "suspicious_multiplier": 1.2 # Increase score
                                      },
                                      "content_purpose_multipliers": {
                                          "credential": 1.5,
                                          "executable_code": 1.2,
                                          "example_code": 0.7,
                                          "documentation_text": 0.5
                                      },
                                      "baseline_comparison": {
                                          "novel_finding_multiplier": 1.1, # If is_novel is true
                                          "accepted_risk_multiplier": 0.3, # If baseline_status is 'accepted_risk'
                                          "high_similarity_threshold": 0.9, "high_similarity_multiplier": 0.8 # If very similar to known good
                                      },
                                      "default_score_multiplier": 1.0
                                  }
        """
        if adjustment_config is None:
            # Default configuration if none is provided
            self.adjustment_config = {
                "domain_reputation": {
                    "trusted_threshold": 0.8, "trusted_multiplier": 0.8,
                    "suspicious_threshold": 0.3, "suspicious_multiplier": 1.25
                },
                "content_purpose_multipliers": {
                    "credential": 1.5,
                    "prompt_material": 1.1,
                    "executable_code": 1.3,
                    "configuration_file": 1.1,
                    "sensitive_data_generic": 1.4,
                    "example_code": 0.7,
                    "documentation_text": 0.6,
                    "log_data": 0.9,
                    "unknown": 1.0
                },
                "baseline_comparison": {
                    "novel_finding_multiplier": 1.15, # For truly new items
                    "status_multipliers": { # Multipliers based on baseline_status
                        "accepted_risk": 0.4,
                        "accepted_risk_documented": 0.3,
                        "known_issue_backlog": 0.6,
                        "mitigated_by_waf": 0.5,
                        "false_positive": 0.1, # Drastically reduce score for known FPs
                        "newly_added_to_baseline": 1.0 # No change if just added
                    },
                    "high_similarity_threshold": 0.9, "high_similarity_multiplier": 0.85 # If similar to something known (not necessarily bad)
                },
                "default_score_multiplier": 1.0
            }
            # print("Using default contextual adjustment config.")
        else:
            self.adjustment_config = adjustment_config
        # Potentially load from a config file like:
        # self.config_path = "config/contextual_adjustments.yaml"
        # self._load_adjustments_from_config()

    def adjust(self, initial_score: float, contextual_info: Dict[str, Any]) -> float:
        """
        Adjusts the initial_score based on the provided contextual_info.

        :param initial_score: The base score to be adjusted (e.g., raw risk score).
        :param contextual_info: A dictionary containing various pieces of context, such as:
                                - 'domain_reputation_score': (float) e.g., 0.9
                                - 'content_purposes': (List[str]) e.g., ['executable_code', 'credential'] (primary purpose first)
                                - 'baseline_info': (Dict) output from BaselineComparator.compare()
                                  e.g., {'similarity_score': 1.0, 'baseline_status': 'accepted_risk', 'is_novel': False}
                                - other relevant finding attributes or environmental factors.
        :return: The adjusted score, clamped between 0.0 and 1.0.
        """
        adjusted_score = initial_score
        
        # Domain Reputation Adjustment
        dr_config = self.adjustment_config.get("domain_reputation", {})
        domain_rep_score = contextual_info.get("domain_reputation_score")
        if domain_rep_score is not None:
            if domain_rep_score >= dr_config.get("trusted_threshold", 0.8):
                adjusted_score *= dr_config.get("trusted_multiplier", 0.8)
            elif domain_rep_score <= dr_config.get("suspicious_threshold", 0.3):
                adjusted_score *= dr_config.get("suspicious_multiplier", 1.2)

        # Content Purpose Adjustment (considers the primary purpose)
        cp_multipliers = self.adjustment_config.get("content_purpose_multipliers", {})
        content_purposes = contextual_info.get("content_purposes", [])
        primary_purpose = content_purposes[0] if content_purposes else "unknown"
        
        multiplier = cp_multipliers.get(primary_purpose, cp_multipliers.get("unknown", 1.0))
        adjusted_score *= multiplier

        # Baseline Comparison Adjustment
        bc_config = self.adjustment_config.get("baseline_comparison", {})
        baseline_info = contextual_info.get("baseline_info")
        if baseline_info:
            if baseline_info.get("is_novel", False):
                adjusted_score *= bc_config.get("novel_finding_multiplier", 1.1)
            
            baseline_status = baseline_info.get("baseline_status")
            if baseline_status:
                status_multipliers = bc_config.get("status_multipliers", {})
                adjusted_score *= status_multipliers.get(baseline_status, 1.0) # Apply status-specific multiplier
            
            similarity_score = baseline_info.get("similarity_score", 0.0)
            if similarity_score >= bc_config.get("high_similarity_threshold", 0.9) and not baseline_status: # If highly similar but not a specific status match
                 adjusted_score *= bc_config.get("high_similarity_multiplier", 0.9)


        # Apply default multiplier if any (usually 1.0)
        adjusted_score *= self.adjustment_config.get("default_score_multiplier", 1.0)

        return min(max(adjusted_score, 0.0), 1.0) # Clamp score between 0 and 1