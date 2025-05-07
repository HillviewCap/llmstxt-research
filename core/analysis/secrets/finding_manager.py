from typing import List, Dict, Any, Optional, Set, Tuple

class SecretFindingManagerError(Exception):
    """Custom exception for SecretFindingManager errors."""
    pass

class SecretFindingManager:
    """
    Manages normalization, deduplication, and storage of secret findings
    from various detectors.
    """
    def __init__(self, file_path: Optional[str] = None, analysis_id: Optional[Any] = None):
        self.findings: List[Dict[str, Any]] = []
        self._dedup_set: Set[Tuple] = set()
        self.file_path = file_path  # Optional path of the content being analyzed
        self.analysis_id = analysis_id # Optional ID for the overall analysis run

    def _classify_severity(self, finding_type_name: str, detector_name: str, details: Dict[str, Any]) -> str:
        """Classifies severity based on finding type name and detector."""
        type_lower = finding_type_name.lower()

        if detector_name == "trufflehog":
            if any(keyword in type_lower for keyword in ["aws", "gcp", "azure", "ssh", "private key", "pkcs8", "putty"]):
                return "High"
            if any(keyword in type_lower for keyword in ["api key", "token", "bearer", "auth", "secret_key", "client_secret"]):
                return "Medium"
            if "password" in type_lower and "example" not in type_lower: # Avoid example passwords
                 return "Medium"
            return "Low"
        elif detector_name == "pattern_library":  # Custom LLM patterns
            # Allow patterns to define their severity, or default
            return details.get("severity", "Medium")
        elif detector_name == "sensitive_detector":
            if any(keyword in type_lower for keyword in ["credit card", "ssn", "bank account", "financial", "password"]):
                return "High"
            if any(keyword in type_lower for keyword in ["email", "phone", "address", "dob", "pii", "ip address", "license key"]):
                return "Medium"
            return "Low"
        return "Medium"  # Default severity

    def _format_location(self, location_details: Optional[Dict[str, Any]]) -> str:
        """Formats location details into a standardized string."""
        if not location_details:
            return "Location unknown"
        
        start = location_details.get('start')
        end = location_details.get('end')
        # line_number = location_details.get('line') # Future: if available from tools

        loc_parts = []
        if self.file_path:
            loc_parts.append(f"file:{self.file_path}")
        
        # if line_number is not None:
        #     loc_parts.append(f"line:{line_number}")

        if start is not None and end is not None:
            # If no file context, 'offset' is primary. If file context, 'span' clarifies it's within that file.
            prefix = "offset" if not self.file_path else "span"
            loc_parts.append(f"{prefix}:{start}-{end}")
        elif start is not None:
            prefix = "offset" if not self.file_path else "pos"
            loc_parts.append(f"{prefix}:{start}")

        return ";".join(loc_parts) if loc_parts else "Content-based finding"

    def normalize_finding(self, raw_finding: Dict[str, Any], detector_name: str) -> Dict[str, Any]:
        """
        Normalizes a raw finding from a specific detector to align with the
        common security_findings schema.
        """
        normalized: Dict[str, Any] = {
            "analysis_id": self.analysis_id,
            "finding_type": "Unknown",
            "severity": "Medium",
            "description": "No description provided.",
            "location": "Unknown",
            "evidence": "",
            "false_positive_likelihood": None, # Placeholder
            "remediation_suggestion": None,   # Placeholder
            "_raw_finding": raw_finding,      # For debugging or extended details
            "_detector": detector_name
        }

        location_info = None
        finding_name_for_severity = "Unknown" # The specific type of secret/pattern/info found

        if detector_name == "trufflehog":
            # Assumes raw_finding is a dict from TruffleHogRunner.run()
            # e.g., {'type': 'AWS Access Key', 'match': 'AKIA...', 'start': 10, 'end': 30, 'raw': 'AKIA...', 'entropy': 4.5}
            finding_name_for_severity = raw_finding.get('type', 'Generic Credential')
            normalized['finding_type'] = "credential_leak" # Aligns with a general category
            normalized['description'] = f"TruffleHog detected: {finding_name_for_severity}."
            normalized['evidence'] = raw_finding.get('match', '')
            location_info = {'start': raw_finding.get('start'), 'end': raw_finding.get('end')}
            if 'entropy' in raw_finding:
                normalized['description'] += f" Entropy: {raw_finding['entropy']:.2f}."
            if raw_finding.get('raw') and raw_finding.get('raw') != raw_finding.get('match'):
                 normalized['description'] += f" Raw data snippet: {str(raw_finding.get('raw'))[:30]}..."


        elif detector_name == "pattern_library":
            # Assumes raw_finding is a dict from PatternLibrary.match()
            # e.g., {'name': 'OpenAI API Key', 'match': 'sk-...', 'start': 5, 'end': 56, 'groups': (...)}
            finding_name_for_severity = raw_finding.get('name', 'Custom LLM Pattern')
            normalized['finding_type'] = "llm_specific_pattern"
            normalized['description'] = f"Custom pattern matched: {finding_name_for_severity}."
            normalized['evidence'] = raw_finding.get('match', '')
            location_info = {'start': raw_finding.get('start'), 'end': raw_finding.get('end')}
            if raw_finding.get('groups'):
                 normalized['description'] += f" Captured groups: {raw_finding.get('groups')}."

        elif detector_name == "sensitive_detector":
            # Assumes raw_finding is a dict from SensitiveDetector.match()
            # e.g., {'name': 'Email Address', 'match': 'a@b.com', 'start': 0, 'end': 7, 'groups': (...)}
            finding_name_for_severity = raw_finding.get('name', 'Sensitive Information')
            normalized['finding_type'] = "sensitive_data_exposure"
            normalized['description'] = f"Sensitive information detected: {finding_name_for_severity}."
            normalized['evidence'] = raw_finding.get('match', '')
            location_info = {'start': raw_finding.get('start'), 'end': raw_finding.get('end')}
            if raw_finding.get('groups'):
                 normalized['description'] += f" Captured groups: {raw_finding.get('groups')}."
        else:
            raise SecretFindingManagerError(f"Unknown detector name: {detector_name}")

        normalized['location'] = self._format_location(location_info)
        normalized['severity'] = self._classify_severity(finding_name_for_severity, detector_name, raw_finding)
        
        # Add a snippet of evidence to description if not already obvious
        evidence_snippet = str(normalized['evidence'])[:30]
        if evidence_snippet and evidence_snippet not in normalized['description']:
            normalized['description'] += f" Evidence snippet: {evidence_snippet}..."

        return normalized

    def store_finding(self, raw_finding: Dict[str, Any], detector_name: str) -> bool:
        """Normalizes and stores a finding, ensuring deduplication."""
        try:
            normalized = self.normalize_finding(raw_finding, detector_name)
        except SecretFindingManagerError as e:
            print(f"Error normalizing finding: {e}. Raw finding: {raw_finding}")
            return False # Failed to normalize

        # Deduplicate based on (finding_type, location, first 64 chars of evidence)
        # This aims to prevent identical findings from the same spot.
        evidence_key_part = str(normalized.get("evidence", ""))[:64]
        key = (
            normalized.get("finding_type"),
            normalized.get("location"), # Standardized location string
            evidence_key_part,
            normalized.get("_detector") # Differentiate if same raw data found by different means (less likely for secrets)
        )
        if key in self._dedup_set:
            # print(f"Duplicate finding skipped: {key}") # Optional: for debugging
            return False  # Duplicate
        
        self._dedup_set.add(key)
        self.findings.append(normalized)
        return True

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Returns all unique, normalized findings."""
        return self.findings

    def clear(self):
        """Clears all stored findings and deduplication data."""
        self.findings.clear()
        self._dedup_set.clear()