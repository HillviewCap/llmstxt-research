"""
YARA Runner Module
Handles YARA rule management, scanning, and result normalization for LLMs.txt Security Analysis Platform.
"""

import os
import yara
import time
from typing import List, Dict, Any, Optional

class YaraRuleManager:
    """
    Manages YARA rules: loads rules from a directory, compiles them, and provides access.
    """
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules: Optional[yara.Rules] = None
        self._load_and_compile_rules()

    def _load_and_compile_rules(self):
        """
        Loads YARA rules from files in the specified directory and compiles them.
        Rules are expected to be in .yar or .yara files.
        """
        filepaths = {}
        if not os.path.isdir(self.rules_dir):
            # Log or raise an error: rules directory not found
            print(f"Warning: YARA rules directory '{self.rules_dir}' not found.")
            self.rules = yara.compile(source="rule dummy {condition: false}") # Compile empty rule set
            return

        for idx, (dirpath, _, filenames) in enumerate(os.walk(self.rules_dir)):
            for filename in filenames:
                if filename.endswith((".yar", ".yara")):
                    rule_path = os.path.join(dirpath, filename)
                    # Use a unique namespace for each file to avoid rule name collisions
                    # Or, ensure rule names are unique across files if not using namespaces
                    namespace = f"ns_{idx}_{os.path.splitext(filename)[0]}"
                    filepaths[namespace] = rule_path
        
        if not filepaths:
            print(f"Warning: No YARA rules found in '{self.rules_dir}'.")
            self.rules = yara.compile(source="rule dummy {condition: false}") # Compile empty rule set
            return

        try:
            self.rules = yara.compile(filepaths=filepaths)
            print(f"Successfully compiled {len(filepaths)} YARA rule files.")
        except yara.Error as e:
            # Log or raise a more specific error
            print(f"Error compiling YARA rules: {e}")
            self.rules = yara.compile(source="rule dummy {condition: false}") # Fallback to empty ruleset

    def get_compiled_rules(self) -> Optional[yara.Rules]:
        return self.rules

    def list_rules(self) -> List[str]:
        """Lists the names of all compiled rules."""
        if not self.rules:
            return []
        
        # Yara rules object doesn't directly expose a list of rule names in a simple way.
        # This is a workaround to get rule names.
        # A better way might involve iterating through a dummy scan or parsing sources if needed.
        # For now, we'll rely on the fact that matches will contain rule names.
        # Or, if yara.Rules had a direct attribute for this, that would be used.
        # This is a limitation of the yara-python library's direct API for listing rules.
        # Typically, you know the rules you've compiled.
        # For now, returning a placeholder or indicating this needs a different approach.
        
        # A common way to get rule names is to iterate through a dummy scan result or
        # keep track of them during compilation if not using filepaths dict keys as namespaces.
        # For now, let's assume we can't easily list them without scanning.
        # This method might need to be re-thought or rely on rule file parsing.
        
        # If we used `sources` for yara.compile, we could get keys from that.
        # With `filepaths`, the namespaces are keys, not individual rule names.
        
        # This is a placeholder. A more robust solution would parse rule files
        # or use a different compilation strategy if a list of all rule *names* is critical.
        # For now, the primary use is scanning, where match objects give rule names.
        return ["List of rule names not directly available from compiled yara.Rules object without scanning or parsing sources."]


class YaraRunner:
    """
    Handles scanning data with YARA rules and normalizing results.
    """
    def __init__(self, rule_manager: YaraRuleManager):
        self.rule_manager = rule_manager
        self.compiled_rules: Optional[yara.Rules] = self.rule_manager.get_compiled_rules()

    def scan(self, data: bytes, timeout: int = 60) -> Dict[str, Any]:
        """
        Scans the input data (bytes) with all loaded YARA rules.
        Returns a dictionary containing matches, scan time, and rule count.
        """
        start_time = time.time()
        matches_details = []
        
        if not self.compiled_rules:
            elapsed_time = time.time() - start_time
            return {
                "matches": [],
                "scan_time_ms": int(elapsed_time * 1000),
                "rule_count": 0, # Or reflect the number of attempted rule files
                "error": "No YARA rules compiled or available for scanning."
            }

        try:
            # Ensure data is bytes
            if isinstance(data, str):
                data_bytes = data.encode('utf-8', errors='ignore')
            else:
                data_bytes = data

            matches = self.compiled_rules.match(data=data_bytes, timeout=timeout)
            for match in matches:
                matches_details.append(self._normalize_result(match, data_bytes))
        except yara.TimeoutError:
            elapsed_time = time.time() - start_time
            return {
                "matches": matches_details, # include any matches found before timeout
                "scan_time_ms": int(elapsed_time * 1000),
                "rule_count": self._get_rule_count(),
                "error": "YARA scan timed out."
            }
        except yara.Error as e:
            elapsed_time = time.time() - start_time
            return {
                "matches": [],
                "scan_time_ms": int(elapsed_time * 1000),
                "rule_count": self._get_rule_count(),
                "error": f"YARA scan error: {e}"
            }

        elapsed_time = time.time() - start_time
        return {
            "matches": matches_details,
            "scan_time_ms": int(elapsed_time * 1000),
            "rule_count": self._get_rule_count()
        }

    def _get_rule_count(self) -> int:
        """
        Attempts to get the count of individual rules.
        This is non-trivial with yara.Rules compiled from filepaths.
        A placeholder or approximation might be needed.
        """
        # This is an estimation. `yara.Rules` doesn't directly expose total rule count.
        # We could count rules if we compiled them one by one or parsed files,
        # but `compile(filepaths=...)` is efficient.
        # For now, returning number of rule *files* or a marker.
        if self.compiled_rules:
             # This is a rough heuristic. It iterates over the internal structure.
             # This is not a documented API feature and might break.
             # A more stable way would be to parse rule files.
            try:
                count = 0
                # Iterate over namespaces (which were our file identifiers)
                for _ in self.compiled_rules: # Iterating over yara.Rules gives Rule objects
                    count +=1
                return count
            except Exception:
                 # If iterating directly doesn't work as expected across yara-python versions.
                 # The number of keys in the filepaths dict used for compilation is a proxy for rule *files*.
                 # This is not the count of *individual rules* if files contain multiple rules.
                 if hasattr(self.rule_manager, 'rules_dir'): # Check if rule_manager is fully initialized
                    filepaths = {}
                    if os.path.isdir(self.rule_manager.rules_dir):
                        for dirpath, _, filenames in os.walk(self.rule_manager.rules_dir):
                            for filename in filenames:
                                if filename.endswith((".yar", ".yara")):
                                    filepaths[os.path.join(dirpath, filename)] = True # just need keys
                    return len(filepaths) # Number of rule files
        return 0


    def _normalize_result(self, match: yara.Match, data: bytes) -> Dict[str, Any]:
        """
        Normalizes the result of a YARA rule match.
        A yara.Match object has attributes: rule, namespace, tags, meta, strings.
        'strings' is a list of tuples: (offset, identifier, data)
        """
        normalized_strings = []
        for s_offset, s_identifier, s_data in match.strings:
            try:
                # Attempt to decode s_data, but it might be raw bytes that aren't valid UTF-8
                matched_str_data = s_data.decode('utf-8', errors='replace')
            except AttributeError: # s_data might already be a string in some yara versions/contexts
                matched_str_data = str(s_data)

            normalized_strings.append({
                "offset": s_offset,
                "identifier": s_identifier, # e.g., $string1
                "data": matched_str_data,   # The matched string data itself
                "excerpt": self._extract_excerpt(data, s_offset, len(s_data))
            })

        return {
            "rule_name": match.rule,
            "namespace": match.namespace,
            "tags": match.tags,
            "meta": match.meta, # Meta fields from the rule
            "strings": normalized_strings, # Detailed info about matched strings
        }

    @staticmethod
    def _extract_excerpt(data: bytes, match_offset: int, match_length: int, context: int = 30) -> str:
        """
        Extracts an excerpt of the data around the matched string.
        Data is bytes, excerpt should be string.
        """
        start = max(0, match_offset - context)
        end = min(len(data), match_offset + match_length + context)
        excerpt_bytes = data[start:end]
        return excerpt_bytes.decode('utf-8', errors='replace')

if __name__ == '__main__':
    # Example Usage (requires a 'rules/yara_test' directory with some .yar files)
    # Create a dummy rule file for testing: rules/yara_test/test_rule.yar
    # rule example_rule {
    #   meta:
    #     description = "This is a test rule"
    #     severity = "Medium"
    #   strings:
    #     $text_string = "example"
    #     $hex_string = { 48 65 6C 6C 6F } // "Hello"
    #   condition:
    #     $text_string or $hex_string
    # }

    RULES_DIR_EXAMPLE = "rules/yara_test_runner_dir" # Create this directory
    os.makedirs(RULES_DIR_EXAMPLE, exist_ok=True)
    
    # Create a dummy rule file
    dummy_rule_content = """
rule example_rule {
  meta:
    description = "This is a test rule"
    severity = "Medium"
    author = "Test User"
  strings:
    $text_string = "example_keyword"
    $hex_string = { 45 78 61 6D 70 6C 65 } // "Example"
  condition:
    $text_string or $hex_string
}

rule another_rule {
    strings:
        $specific_pattern = "unique_pattern_123"
    condition:
        $specific_pattern
}
    """
    with open(os.path.join(RULES_DIR_EXAMPLE, "test_rules.yar"), "w") as f:
        f.write(dummy_rule_content)

    print(f"Attempting to load rules from: {os.path.abspath(RULES_DIR_EXAMPLE)}")

    rule_manager = YaraRuleManager(rules_dir=RULES_DIR_EXAMPLE)
    compiled_rules = rule_manager.get_compiled_rules()

    if compiled_rules:
        print(f"Rules compiled successfully.")
        # The list_rules method is a placeholder, actual rule names come from matches
        # print(f"Available rule namespaces/files: {rule_manager.list_rules()}")
        
        runner = YaraRunner(rule_manager)
        
        test_data_str = "This is some test data with an example_keyword and also another unique_pattern_123 here."
        test_data_bytes = test_data_str.encode('utf-8')
        
        print(f"\nScanning data: '{test_data_str}'")
        results = runner.scan(test_data_bytes)
        
        print("\nScan Results:")
        print(f"  Scan Time: {results.get('scan_time_ms')} ms")
        print(f"  Rule Count (files/namespaces): {results.get('rule_count')}")
        if results.get('error'):
            print(f"  Error: {results.get('error')}")
        
        if results.get("matches"):
            for match_info in results["matches"]:
                print(f"  Match Found:")
                print(f"    Rule Name: {match_info['rule_name']}")
                print(f"    Namespace: {match_info['namespace']}")
                print(f"    Tags: {match_info['tags']}")
                print(f"    Meta: {match_info['meta']}")
                for str_match in match_info['strings']:
                    print(f"      String Matched:")
                    print(f"        Identifier: {str_match['identifier']}")
                    print(f"        Offset: {str_match['offset']}")
                    print(f"        Data: '{str_match['data']}'")
                    print(f"        Excerpt: '{str_match['excerpt']}'")
        else:
            print("  No matches found.")

        # Test with data that doesn't match
        non_matching_data = "This string has nothing relevant.".encode('utf-8')
        print(f"\nScanning non-matching data: '{non_matching_data.decode()}'")
        results_no_match = runner.scan(non_matching_data)
        print("\nScan Results (no match):")
        print(f"  Scan Time: {results_no_match.get('scan_time_ms')} ms")
        if not results_no_match.get("matches"):
            print("  No matches found, as expected.")

    else:
        print("Failed to compile YARA rules. Check logs.")

    # Clean up dummy directory and file
    # import shutil
    # shutil.rmtree(RULES_DIR_EXAMPLE)
    print(f"\nNote: Test rule directory '{RULES_DIR_EXAMPLE}' was created. You may want to remove it manually if not needed.")