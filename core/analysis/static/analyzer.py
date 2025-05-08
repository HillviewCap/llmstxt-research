import os
from typing import List, Dict, Any, Optional

from .semgrep_runner import SemgrepRunner, SemgrepRunnerError
from .rule_manager import RuleManager, RuleManagerError
from .finding_manager import FindingManager, FindingManagerError

class StaticAnalyzerError(Exception):
    pass

class StaticAnalyzer:
    def __init__(self, rules_path: str = "rules/semgrep"):
        print(f"StaticAnalyzer initialized with rules_path: {rules_path}")
        self.rules_path = rules_path
        self.rule_manager = RuleManager(rules_path)
        # Add Semgrep registry rulesets for gitleaks and OWASP Top Ten
        self.registry_rulesets = ["p/gitleaks", "p/owasp-top-ten"]
        self.semgrep_runner = SemgrepRunner(rules_path, registry_rulesets=self.registry_rulesets)
        self.finding_manager = FindingManager()

    def analyze(self, data: Any, language: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            findings: List[Dict[str, Any]] = []

            if isinstance(data, dict):
                content_to_scan = data.get('content')
                # Use language from dict first, fallback to method's language parameter
                lang_for_scan = data.get('language', language)

                item_id = data.get('id', 'unknown') # For logging

                if content_to_scan and lang_for_scan:
                    # Check if the language is supported by semgrep
                    supported_languages = [
                        "apex", "bash", "c", "c#", "c++", "cairo", "circom", "clojure",
                        "cpp", "csharp", "dart", "docker", "dockerfile", "elixir", "ex",
                        "generic", "go", "golang", "hack", "hcl", "html", "java",
                        "javascript", "js", "json", "jsonnet", "julia", "kotlin", "kt",
                        "lisp", "lua", "move_on_aptos", "move_on_sui", "none", "ocaml",
                        "php", "promql", "proto", "proto3", "protobuf", "py", "python",
                        "python2", "python3", "ql", "r", "regex", "ruby", "rust", "scala",
                        "scheme", "sh", "sol", "solidity", "swift", "terraform", "tf",
                        "ts", "typescript", "vue", "xml", "yaml"
                    ]
                    
                    # If language is markdown, use 'generic' instead
                    effective_language = lang_for_scan
                    if lang_for_scan.lower() == 'markdown' or lang_for_scan.lower() == 'md':
                        effective_language = 'generic'
                        print(f"Converting markdown language to 'generic' for semgrep compatibility. ID: {item_id}")
                    
                    # If language is not supported, use 'generic'
                    if effective_language.lower() not in [lang.lower() for lang in supported_languages]:
                        print(f"Language '{lang_for_scan}' not supported by semgrep, using 'generic' instead. ID: {item_id}")
                        effective_language = 'generic'
                    
                    print(f"Static analyzing in-memory content (lang: {effective_language}). ID: {item_id}")
                    findings = self.semgrep_runner.run(content=content_to_scan, language=effective_language)
                elif content_to_scan and not lang_for_scan:
                    # Default to generic for content without a specified language
                    print(f"No language specified for content analysis, using 'generic'. ID: {item_id}")
                    findings = self.semgrep_runner.run(content=content_to_scan, language='generic')
                elif not content_to_scan:
                    raise StaticAnalyzerError(
                        f"Input dictionary for analysis is missing 'content' key. ID: {item_id}"
                    )
                else:
                    # This case implies data is a dict, but not actionable (e.g. empty content after checks)
                    # This path should ideally not be hit if the above conditions are exhaustive.
                    print(f"Warning: Static analysis received a dictionary that could not be processed. ID: {item_id}, Keys: {list(data.keys())}")
                    # Default to empty findings for this case, or raise specific error if preferred.
                    # Given the checks, this implies an unexpected dict structure or empty content that wasn't caught.

            elif isinstance(data, str):  # Assumed to be a file path
                target_path = data
                print(f"Static analyzing file: {target_path} (lang hint: {language})")
                # The 'language' parameter here is a hint for Semgrep.
                # If None, Semgrep will attempt to auto-detect the language.
                findings = self.semgrep_runner.run(target_path=target_path, language=language)
            else:
                raise StaticAnalyzerError(f"Unsupported data type for analysis: {type(data)}. Must be dict or str.")

            for finding in findings:
                self.finding_manager.store_finding(finding)
            
            # As per original logic, return all findings managed by finding_manager.
            # If only findings from *this* run were needed, one would return the `findings` list directly.
            return self.finding_manager.get_all_findings()
        except (SemgrepRunnerError, RuleManagerError, FindingManagerError) as e:
            # Log more specific error to help diagnose
            error_type = type(e).__name__
            print(f"Error during static analysis pipeline ({error_type}): {e}")
            raise StaticAnalyzerError(f"Static analysis failed due to {error_type}: {e}")
        except Exception as e:  # Catch any other unexpected errors
            error_type = type(e).__name__
            # Consider logging the stack trace here for better debugging in a real system
            # import traceback; traceback.print_exc();
            print(f"Unexpected error during static analysis ({error_type}): {e}")
            raise StaticAnalyzerError(f"An unexpected error ({error_type}) occurred during static analysis: {e}")

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.semgrep_runner.list_rules()

    def clear_findings(self):
        self.finding_manager.clear()