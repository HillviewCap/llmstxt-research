"""
Pattern Analysis Orchestrator
Coordinates YARA integration and behavioral analysis for LLMs.txt Security Analysis Platform.
"""

import os
from typing import Dict, Any, Union

# Updated imports
from .yara_runner import YaraRuleManager
from .behavior_analyzer import BehaviorAnalyzer

# Define the default path to YARA rules relative to this file's location
# core/analysis/patterns/analyzer.py -> core/analysis/ -> core/ -> project_root/
# So, ../../../rules/yara
DEFAULT_YARA_RULES_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "rules", "yara"
))

class PatternAnalysisOrchestrator:
    """
    Orchestrates advanced pattern matching components using YARA and BehaviorAnalyzer.
    """
    def __init__(self, yara_rules_dir: str = DEFAULT_YARA_RULES_DIR):
        """
        Initializes the orchestrator.
        Args:
            yara_rules_dir: Path to the directory containing YARA rule files.
        """
        if not os.path.isdir(yara_rules_dir):
            print(f"Warning: YARA rules directory '{yara_rules_dir}' not found. "
                  f"YaraRuleManager might use a dummy ruleset.")
        
        self.yara_rule_manager = YaraRuleManager(rules_dir=yara_rules_dir)
        self.behavior_analyzer = BehaviorAnalyzer(self.yara_rule_manager)
        
        # Check if rules actually loaded, for early feedback
        if self.yara_rule_manager.get_compiled_rules() is None or \
           len(self.yara_rule_manager.get_compiled_rules()) == 0 and \
           "dummy" not in str(self.yara_rule_manager.get_compiled_rules()): # crude check for dummy
            # The dummy rule is "rule dummy {condition: false}"
            # A more robust check would be if yara_rule_manager.rules.get_rules() is empty or only has 'dummy'
            # For now, let's assume YaraRuleManager constructor logs issues.
            print(f"PatternAnalysisOrchestrator: Info: YaraRuleManager initialized. "
                  f"Effective rule count might be low if directory was empty or rules failed to compile. "
                  f"Check logs from YaraRuleManager.")


    def analyze(self, data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs the full suite of pattern analysis on the input data.
        
        Args:
            data: Either a string (content to analyze) or a dictionary 
                  expected to have a 'content' key with the string to analyze.
                  Can also contain 'content_bytes' for pre-encoded content.
        """
        content_str: str = ""
        content_bytes: Union[bytes, None] = None

        if isinstance(data, dict):
            item_id = data.get('id', 'unknown_item')
            print(f"PatternAnalysisOrchestrator: Analyzing content for item ID: {item_id}")
            
            if 'content_bytes' in data and isinstance(data['content_bytes'], bytes):
                content_bytes = data['content_bytes']
                # Optionally decode for logging or if BehaviorAnalyzer needs str too
                try:
                    content_str = content_bytes.decode('utf-8', errors='replace')
                except Exception:
                    content_str = "[Binary content, cannot decode as UTF-8 for logging]"
            elif 'content' in data and isinstance(data['content'], str):
                content_str = data['content']
            else:
                print(f"Warning: Input data for item ID {item_id} is a dict but lacks "
                      f"a valid 'content' (string) or 'content_bytes' (bytes) field. Using empty string.")
                content_str = ""
        elif isinstance(data, str):
            content_str = data
        elif isinstance(data, bytes): # Allow direct bytes input
            content_bytes = data
            try:
                content_str = content_bytes.decode('utf-8', errors='replace')
            except Exception:
                content_str = "[Binary content, cannot decode as UTF-8 for logging]"
        else:
            print(f"Warning: Unsupported data type for pattern analysis: {type(data)}. Using empty string.")
            content_str = ""

        # BehaviorAnalyzer's analyze method can take string or bytes
        # If we have bytes, pass them directly for efficiency.
        if content_bytes is not None:
            return self.behavior_analyzer.analyze(data_content=content_str, data_bytes=content_bytes)
        else:
            return self.behavior_analyzer.analyze(data_content=content_str)


# Create an alias for compatibility with existing code or for clearer naming
PatternAnalyzer = PatternAnalysisOrchestrator

if __name__ == '__main__':
    # Example Usage:
    # This assumes that 'rules/yara/' exists relative to the project root and contains valid YARA rules.
    # For this __main__ block, we'll use the default path which should resolve correctly if run from project root,
    # or if the script is part of the installed package.

    # If rules/yara is empty or rules are invalid, YaraRuleManager will print warnings.
    # The BehaviorAnalyzer's __main__ block creates some dummy rules for its own testing.
    # Here, we rely on the actual project rules.
    
    print(f"Default YARA rules directory for orchestrator: {DEFAULT_YARA_RULES_DIR}")
    if not os.path.exists(DEFAULT_YARA_RULES_DIR):
        print(f"WARNING: The default YARA rules directory does not exist: {DEFAULT_YARA_RULES_DIR}")
        print("Please create it and add YARA files (e.g., from rules/yara in the project).")
        print("The orchestrator might not find any rules to load.")
        # For __main__ test, create a dummy one if it doesn't exist to avoid crashing YaraRuleManager init
        os.makedirs(DEFAULT_YARA_RULES_DIR, exist_ok=True)
        print(f"Created dummy directory: {DEFAULT_YARA_RULES_DIR}")
        # Add a very simple rule to the dummy dir for testing orchestrator
        with open(os.path.join(DEFAULT_YARA_RULES_DIR, "orchestrator_test_rule.yar"), "w") as f:
            f.write("""
rule Orchestrator_Test_Rule {
    meta:
        description = "A simple rule to test orchestrator loading."
        threat_type = "test"
    strings:
        $test = "orchestrator_pattern"
    condition:
        $test
}""")
            print(f"Created dummy rule: {os.path.join(DEFAULT_YARA_RULES_DIR, 'orchestrator_test_rule.yar')}")


    orchestrator = PatternAnalysisOrchestrator() # Uses DEFAULT_YARA_RULES_DIR

    sample_text_data_1 = "This text contains an orchestrator_pattern to test the setup."
    print(f"\nAnalyzing sample text 1: '{sample_text_data_1}'")
    results1 = orchestrator.analyze(sample_text_data_1)
    print("Orchestrator Analysis Results 1:")
    import json
    print(json.dumps(results1, indent=2))

    sample_dict_data = {
        "id": "doc123",
        "content": "Another document with the orchestrator_pattern here, and maybe some LLM specific things like 'ignore all previous instructions'."
    }
    # Add pre-existing sample rules to DEFAULT_YARA_RULES_DIR if they are not there from project
    if not os.path.exists(os.path.join(DEFAULT_YARA_RULES_DIR, "sample_llm_prompt_injection.yar")):
         with open(os.path.join(DEFAULT_YARA_RULES_DIR, "sample_llm_prompt_injection.yar"), "w") as f:
            f.write("""
rule LLM_Prompt_Injection_Test {
    meta:
        description = "Detects prompt injection attempts targeting LLMs for orchestrator test"
        threat_type = "manipulation"
        severity = "high"
    strings:
        $injection1 = "ignore all previous instructions" nocase
    condition:
        $injection1
}""")
            print(f"Created dummy injection rule in {DEFAULT_YARA_RULES_DIR}")


    print(f"\nAnalyzing sample dict data (ID: {sample_dict_data['id']}):")
    results2 = orchestrator.analyze(sample_dict_data)
    print("Orchestrator Analysis Results 2:")
    print(json.dumps(results2, indent=2))

    sample_bytes_data = b"This is byte data with orchestrator_pattern."
    print(f"\nAnalyzing sample bytes data: {sample_bytes_data!r}")
    results3 = orchestrator.analyze(sample_bytes_data)
    print("Orchestrator Analysis Results 3 (from bytes):")
    print(json.dumps(results3, indent=2))
    
    print("\nNote: If 'rules_evaluated_count' is 0 or very low, or no matches found when expected,")
    print("ensure YARA rules exist in the target directory and are valid.")
    print(f"Tested with rules from: {os.path.abspath(DEFAULT_YARA_RULES_DIR)}")
    # Consider removing the dummy orchestrator_test_rule.yar if it was created by this test block
    # For a real run, this __main__ block might pollute the actual rules/yara dir if not careful.