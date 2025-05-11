import os
import time
import logging
from typing import List, Dict, Any, Optional

from .semgrep_runner import SemgrepRunner, SemgrepRunnerError
from .rule_manager import RuleManager, RuleManagerError
from .finding_manager import FindingManager, FindingManagerError

# Configure logger
logger = logging.getLogger(__name__)

class StaticAnalyzerError(Exception):
    pass

class StaticAnalyzer:
    def __init__(self, rules_path: str = "rules/semgrep"):
        logger.info(f"StaticAnalyzer initialized with rules_path: {rules_path}")
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
                        logger.info(f"Converting markdown language to 'generic' for semgrep compatibility. ID: {item_id}")
                    
                    # If language is not supported, use 'generic'
                    if effective_language.lower() not in [lang.lower() for lang in supported_languages]:
                        logger.info(f"Language '{lang_for_scan}' not supported by semgrep, using 'generic' instead. ID: {item_id}")
                        effective_language = 'generic'
                    
                    logger.info(f"Static analyzing in-memory content (lang: {effective_language}). ID: {item_id}")
                    
                    # Log semgrep execution start
                    logger.info(f"Starting semgrep execution for ID: {item_id}")
                    
                    # Check for semgrep processes before execution
                    self._log_semgrep_processes("before")
                    
                    # Run semgrep
                    findings = self.semgrep_runner.run(content=content_to_scan, language=effective_language)
                    
                    # Check for semgrep processes after execution
                    self._log_semgrep_processes("after")
                    
                    logger.info(f"Completed semgrep execution for ID: {item_id}")
                elif content_to_scan and not lang_for_scan:
                    # Default to generic for content without a specified language
                    logger.info(f"No language specified for content analysis, using 'generic'. ID: {item_id}")
                    findings = self.semgrep_runner.run(content=content_to_scan, language='generic')
                elif not content_to_scan:
                    raise StaticAnalyzerError(
                        f"Input dictionary for analysis is missing 'content' key. ID: {item_id}"
                    )
                else:
                    # This case implies data is a dict, but not actionable (e.g. empty content after checks)
                    # This path should ideally not be hit if the above conditions are exhaustive.
                    logger.warning(f"Static analysis received a dictionary that could not be processed. ID: {item_id}, Keys: {list(data.keys())}")
                    # Default to empty findings for this case, or raise specific error if preferred.
                    # Given the checks, this implies an unexpected dict structure or empty content that wasn't caught.

            elif isinstance(data, str):  # Assumed to be a file path
                target_path = data
                logger.info(f"Static analyzing file: {target_path} (lang hint: {language})")
                # The 'language' parameter here is a hint for Semgrep.
                # If None, Semgrep will attempt to auto-detect the language.
                
                # Log semgrep execution start
                logger.info(f"Starting semgrep execution for file: {target_path}")
                
                # Check for semgrep processes before execution
                self._log_semgrep_processes("before")
                
                # Run semgrep
                findings = self.semgrep_runner.run(target_path=target_path, language=language)
                
                # Check for semgrep processes after execution
                self._log_semgrep_processes("after")
                
                logger.info(f"Completed semgrep execution for file: {target_path}")
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
            logger.error(f"Error during static analysis pipeline ({error_type}): {e}")
            raise StaticAnalyzerError(f"Static analysis failed due to {error_type}: {e}")
        except Exception as e:  # Catch any other unexpected errors
            error_type = type(e).__name__
            # Log the stack trace for better debugging
            logger.exception(f"Unexpected error during static analysis ({error_type}): {e}")
            raise StaticAnalyzerError(f"An unexpected error ({error_type}) occurred during static analysis: {e}")

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.semgrep_runner.list_rules()

    def clear_findings(self):
        self.finding_manager.clear()
        
    def _log_semgrep_processes(self, stage):
        """Log information about running semgrep processes"""
        try:
            import psutil
            
            # Find all semgrep processes
            semgrep_processes = []
            total_memory_percent = 0.0
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'cpu_percent']):
                try:
                    # Check if this is a semgrep process
                    if proc.info['name'] == 'semgrep' or (
                        proc.info['cmdline'] and
                        any('semgrep' in cmd for cmd in proc.info['cmdline'] if cmd)
                    ):
                        # Get detailed process info
                        proc_info = {
                            'pid': proc.info['pid'],
                            'memory_percent': proc.info['memory_percent'],
                            'cpu_percent': proc.info['cpu_percent'] or proc.cpu_percent(interval=0.1),
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                            'create_time': proc.create_time(),
                            'running_time': time.time() - proc.create_time()
                        }
                        semgrep_processes.append(proc_info)
                        total_memory_percent += proc.info['memory_percent']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            if semgrep_processes:
                logger.warning(
                    f"Semgrep processes {stage} execution: count={len(semgrep_processes)}, "
                    f"memory={total_memory_percent:.2f}%, "
                    f"pids={[p['pid'] for p in semgrep_processes]}"
                )
                
                # Log detailed info about long-running processes
                long_running = [p for p in semgrep_processes if p['running_time'] > 60]  # > 1 minute
                if long_running:
                    for proc in long_running:
                        logger.warning(
                            f"Long-running semgrep process: pid={proc['pid']}, "
                            f"running_time={proc['running_time']:.1f}s, "
                            f"memory={proc['memory_percent']:.2f}%, "
                            f"cmd={proc['cmdline']}"
                        )
            else:
                logger.info(f"No semgrep processes found {stage} execution")
                
        except ImportError:
            logger.debug("psutil not installed, cannot check semgrep processes")
        except Exception as e:
            logger.error(f"Error checking semgrep processes: {e}")