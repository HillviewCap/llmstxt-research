import subprocess
import json
import os
import signal
import tempfile
import shutil
import time
import logging
import psutil
from typing import List, Dict, Any, Optional, Tuple

# Configure logger
logger = logging.getLogger(__name__)


class SemgrepRunnerError(Exception):
    pass


class SemgrepRunner:
    # List of supported languages by semgrep
    SUPPORTED_LANGUAGES = {
        "apex",
        "bash",
        "c",
        "c#",
        "c++",
        "cairo",
        "circom",
        "clojure",
        "cpp",
        "csharp",
        "dart",
        "docker",
        "dockerfile",
        "elixir",
        "ex",
        "generic",
        "go",
        "golang",
        "hack",
        "hcl",
        "html",
        "java",
        "javascript",
        "js",
        "json",
        "jsonnet",
        "julia",
        "kotlin",
        "kt",
        "lisp",
        "lua",
        "move_on_aptos",
        "move_on_sui",
        "none",
        "ocaml",
        "php",
        "promql",
        "proto",
        "proto3",
        "protobuf",
        "py",
        "python",
        "python2",
        "python3",
        "ql",
        "r",
        "regex",
        "ruby",
        "rust",
        "scala",
        "scheme",
        "sh",
        "sol",
        "solidity",
        "swift",
        "terraform",
        "tf",
        "ts",
        "typescript",
        "vue",
        "xml",
        "yaml",
    }

    # Language aliases mapping
    LANGUAGE_ALIASES = {
        "markdown": "generic",
        "md": "generic",
        "js": "javascript",
        "py": "python",
        "cpp": "c++",
        "ts": "typescript",
    }

    def __init__(
        self,
        rules_path: str,
        config: Optional[Dict[str, Any]] = None,
        registry_rulesets: Optional[List[str]] = None,
    ):
        self.rules_path = rules_path
        self.config = config or {}
        self.registry_rulesets = registry_rulesets or []
        self.rules = self._load_rules()
        self.rule_metadata = self._extract_rule_metadata()
        # Maximum content size for direct analysis (in bytes)
        self.max_content_size = self.config.get(
            "max_content_size", 1024 * 1024
        )  # Default 1MB

    def _load_rules(self) -> List[str]:
        if not os.path.isdir(self.rules_path):
            raise SemgrepRunnerError(f"Rules path does not exist: {self.rules_path}")
        rules = []
        for file in os.listdir(self.rules_path):
            if file.endswith(".yml") or file.endswith(".yaml"):
                rules.append(os.path.join(self.rules_path, file))
        if not rules:
            raise SemgrepRunnerError(
                "No Semgrep rules found in the specified directory."
            )
        return rules

    def _extract_rule_metadata(self) -> Dict[str, Dict[str, Any]]:
        # Extracts priority and category from rule YAML headers (simple parsing)
        metadata = {}
        for rule_file in self.rules:
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                rule_id, category, priority = None, "Uncategorized", "Medium"
                for line in lines:
                    if line.strip().startswith("id:"):
                        rule_id = line.split(":", 1)[1].strip()
                    if line.strip().startswith("category:"):
                        category = line.split(":", 1)[1].strip()
                    if line.strip().startswith("priority:"):
                        priority = line.split(":", 1)[1].strip()
                    if rule_id and category and priority:
                        break
                if rule_id:
                    metadata[rule_id] = {
                        "category": category,
                        "priority": priority,
                        "file": rule_file,
                    }
            except Exception:
                continue
        return metadata

    def run(
        self,
        target_path: Optional[str] = None,
        content: Optional[str] = None,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if not content and not target_path:
            raise SemgrepRunnerError("Either target_path or content must be provided.")
        if content and not language:
            # If content is provided, language is essential for creating a correctly suffixed temp file
            # and for semgrep to know how to parse it.
            raise SemgrepRunnerError("Language must be provided when scanning content.")

        # Normalize and validate language
        if language:
            language = language.lower()
            # Check for language aliases
            language = self.LANGUAGE_ALIASES.get(language, language)
            # Validate language is supported
            if language not in self.SUPPORTED_LANGUAGES:
                logger.warning(
                    f"Language '{language}' not supported by semgrep, using 'generic' instead."
                )
                language = "generic"

        # Check content size before processing
        if content and len(content) > self.max_content_size:
            print(
                f"Content size ({len(content)} bytes) exceeds maximum allowed size ({self.max_content_size} bytes)"
            )
            return [
                {
                    "rule_id": "content_too_large",
                    "path": "in-memory-content",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 1},
                    "extra": {
                        "message": f"Content size ({len(content)} bytes) exceeds maximum allowed size"
                    },
                    "category": "Performance",
                    "priority": "Medium",
                }
            ]

        # Skip semgrep for generic/markdown content that's too complex
        if language == "generic" and content and self._is_complex_content(content):
            print(
                f"Skipping semgrep for complex generic content ({len(content)} bytes, {content.count('\\n')} lines)"
            )
            return [
                {
                    "rule_id": "complex_generic_content",
                    "path": "in-memory-content",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 1},
                    "extra": {
                        "message": "Content too complex for generic language analysis"
                    },
                    "category": "Performance",
                    "priority": "Low",
                }
            ]

        actual_scan_path = None
        temp_file_path_for_cleanup = None  # Store path for cleanup

        try:
            if content:
                # Ensure language is valid for a file extension, e.g. "python" -> ".py"
                # Basic sanitization for file extension.
                safe_lang_suffix = "".join(c for c in language if c.isalnum()) or "tmp"

                # Create a temporary file
                # delete=False is used because we need to close it before semgrep can use it (on some OS),
                # and then manually delete it.
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=f".{safe_lang_suffix}",  # e.g. .py, .js
                    delete=False,
                    encoding="utf-8",
                ) as temp_file_handle:
                    temp_file_handle.write(content)
                    temp_file_handle.flush()  # Ensure content is written to disk
                    actual_scan_path = temp_file_handle.name
                    temp_file_path_for_cleanup = actual_scan_path
                # temp_file_handle is now closed here after exiting the 'with' block.
                # Semgrep can now access the file.
            else:  # target_path must be provided
                if not target_path or not os.path.exists(
                    target_path
                ):  # Check existence if target_path is used
                    raise SemgrepRunnerError(
                        f"Target path does not exist or not provided: {target_path}"
                    )
                actual_scan_path = target_path

            # Construct Semgrep command
            cmd = [
                "semgrep",
                "--json",  # Output in JSON format
            ]

            # For generic language, use a different approach
            if language == "generic":
                # For generic content, still use local rules but with additional safeguards
                cmd.extend(
                    [
                        "--config",
                        self.rules_path,  # Use local rules
                        "--max-memory",
                        "1024",  # Limit memory usage
                        "--max-target-bytes",
                        str(self.max_content_size),  # Limit file size
                        "--timeout",
                        "15",  # Shorter timeout for generic content
                        actual_scan_path,
                    ]
                )
            else:
                # Normal rules-based scanning
                # Add each individual rule file instead of the directory
                # This ensures Semgrep can find and load the rules properly
                if self.rules:
                    for rule_file in self.rules:
                        cmd.extend(["--config", rule_file])
                else:
                    logger.warning("No Semgrep rules found to apply")

                # Add registry rulesets if specified
                for ruleset in self.registry_rulesets:
                    cmd.extend(["--config", ruleset])

                # Add target file
                cmd.append(actual_scan_path)

                # If language is specified (especially for content scanning, or to override auto-detection)
                if language:
                    cmd.extend(["--lang", language])

            # Check if semgrep executable is available
            if not shutil.which("semgrep"):
                raise SemgrepRunnerError(
                    "Semgrep executable not found. Please ensure it is installed and in PATH."
                )

            # Calculate dynamic timeout based on content size
            timeout = self._calculate_timeout(
                len(content) if content else os.path.getsize(actual_scan_path)
            )
            print(
                f"Running semgrep with {timeout}s timeout for {len(content) if content else 'file'} bytes"
            )

            # Execute Semgrep with dynamic timeout
            process = self.run_with_process_group_timeout(cmd, timeout=timeout)

            # Semgrep exit codes:
            # 0: No findings
            # 1: Findings found
            # >1: Error (e.g., 2 for CLI parsing error, rule error, etc.)
            if process.returncode > 1:
                error_output = (
                    process.stderr if process.stderr.strip() else process.stdout
                )
                raise SemgrepRunnerError(
                    f"Semgrep execution failed with code {process.returncode}: {error_output}"
                )

            # Even with return code 0 or 1, stdout might be empty if semgrep had an issue
            # that didn't result in a >1 exit code (e.g. some misconfigurations).
            # The parse_results method should handle empty or invalid JSON.
            return self.parse_results(process.stdout)

        finally:
            # Cleanup: Remove the temporary file if it was created
            if temp_file_path_for_cleanup and os.path.exists(
                temp_file_path_for_cleanup
            ):
                try:
                    os.remove(temp_file_path_for_cleanup)
                except OSError as e:
                    # Log this error (e.g., using a proper logger if available in the project)
                    # For now, print a warning. This should not stop the program.
                    print(
                        f"Warning: Failed to remove temporary file {temp_file_path_for_cleanup}: {e}"
                    )

    def parse_results(self, output: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(output)
            findings = []
            for result in data.get("results", []):
                rule_id = result.get("check_id")
                finding = {
                    "rule_id": rule_id,
                    "path": result.get("path"),
                    "start": result.get("start"),
                    "end": result.get("end"),
                    "extra": result.get("extra", {}),
                    "category": self.rule_metadata.get(rule_id, {}).get(
                        "category", "Uncategorized"
                    ),
                    "priority": self.rule_metadata.get(rule_id, {}).get(
                        "priority", "Medium"
                    ),
                }
                findings.append(finding)
            return findings
        except Exception as e:
            raise SemgrepRunnerError(f"Failed to parse Semgrep output: {e}")

    def list_rules(self) -> List[Dict[str, Any]]:
        return [{"id": rule_id, **meta} for rule_id, meta in self.rule_metadata.items()]

    def _get_process_resource_usage(self, pid):
        """Get memory and CPU usage for a process and its children"""
        try:
            process = psutil.Process(pid)
            children = process.children(recursive=True)

            # Get main process info
            main_process_info = {
                "pid": pid,
                "memory_percent": process.memory_percent(),
                "cpu_percent": process.cpu_percent(interval=0.1),
                "status": process.status(),
            }

            # Get children info
            children_info = []
            for child in children:
                try:
                    children_info.append(
                        {
                            "pid": child.pid,
                            "memory_percent": child.memory_percent(),
                            "cpu_percent": child.cpu_percent(interval=0.1),
                            "status": child.status(),
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass  # Child process may have terminated

            return {
                "main": main_process_info,
                "children": children_info,
                "total_processes": 1 + len(children),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"error": f"Could not access process {pid}"}

    def _verify_process_termination(self, pid):
        """Verify that a process and all its children are terminated"""
        try:
            process = psutil.Process(pid)
            children = process.children(recursive=True)

            # If we can get the process, it's still running
            running_processes = [pid]
            for child in children:
                running_processes.append(child.pid)

            return False, running_processes
        except psutil.NoSuchProcess:
            # Process is gone, which is what we want
            return True, []

    def _terminate_process_group_with_verification(self, pid, max_attempts=3):
        """
        Terminate a process group with multiple attempts and verification
        Returns a tuple of (success, remaining_pids)
        """
        logger.info(f"Attempting to terminate process group with PID {pid}")

        # First, log the process tree before termination
        resource_info = self._get_process_resource_usage(pid)
        logger.info(f"Process tree before termination: {resource_info}")

        # Try to terminate the process group with increasing force
        for attempt in range(max_attempts):
            try:
                if attempt == 0:
                    # First attempt: SIGTERM
                    logger.info(
                        f"Sending SIGTERM to process group {pid} (attempt {attempt+1}/{max_attempts})"
                    )
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                else:
                    # Subsequent attempts: SIGKILL
                    logger.info(
                        f"Sending SIGKILL to process group {pid} (attempt {attempt+1}/{max_attempts})"
                    )
                    os.killpg(os.getpgid(pid), signal.SIGKILL)

                # Wait a bit for processes to terminate
                wait_time = 2 * (attempt + 1)  # Increase wait time with each attempt
                logger.info(f"Waiting {wait_time} seconds for processes to terminate")
                time.sleep(wait_time)

                # Verify termination
                terminated, remaining_pids = self._verify_process_termination(pid)
                if terminated:
                    logger.info(
                        f"Process group {pid} successfully terminated on attempt {attempt+1}"
                    )
                    return True, []
                else:
                    logger.warning(
                        f"Process group {pid} still has running processes after attempt {attempt+1}: {remaining_pids}"
                    )

                    # For remaining processes, try to kill them individually
                    if attempt > 0:  # Only on second+ attempts
                        for remaining_pid in remaining_pids:
                            try:
                                logger.info(
                                    f"Attempting to kill individual process {remaining_pid}"
                                )
                                os.kill(remaining_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass  # Process already gone

            except ProcessLookupError:
                # Process group already gone
                logger.info(f"Process group {pid} already terminated")
                return True, []

        # Final verification
        terminated, remaining_pids = self._verify_process_termination(pid)
        if terminated:
            return True, []
        else:
            logger.error(
                f"Failed to terminate all processes in group {pid} after {max_attempts} attempts. Remaining PIDs: {remaining_pids}"
            )
            return False, remaining_pids

    def _is_complex_content(self, content: str) -> bool:
        """
        Determine if content is too complex for generic language analysis
        """
        # Check content size
        if len(content) > 100000:  # 100KB
            return True

        # Check line count
        if content.count("\n") > 1000:  # More than 1000 lines
            return True

        # Check for complex patterns that might cause semgrep to hang
        complex_patterns = [
            r"```",  # Code blocks in markdown
            r"\[\[",  # Wiki-style links
            r"\{\{",  # Template syntax
        ]

        for pattern in complex_patterns:
            if content.count(pattern) > 10:  # More than 10 occurrences
                return True

        return False

    def _calculate_timeout(self, content_size: int) -> int:
        """
        Calculate appropriate timeout based on content size
        """
        # Base timeout
        base_timeout = 30

        # Add 1 second for each 10KB of content, up to a maximum
        size_factor = min(content_size / 10240, 30)  # Cap at 30 seconds additional

        return int(base_timeout + size_factor)

    def run_with_process_group_timeout(self, cmd, timeout=60):
        """Run command with timeout, ensuring all child processes are terminated"""
        start_time = time.time()
        logger.info(f"Starting command with {timeout}s timeout: {' '.join(cmd)}")

        # Start process in new process group
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid,  # Create new process group
        )

        # Log initial process info
        logger.info(f"Started process with PID {process.pid}")

        # Monitor resource usage in a non-blocking way
        try:
            # Get initial resource usage
            initial_resources = self._get_process_resource_usage(process.pid)
            logger.info(f"Initial resource usage: {initial_resources}")
        except Exception as e:
            logger.warning(f"Failed to get initial resource usage: {e}")

        try:
            stdout, stderr = process.communicate(timeout=timeout)

            # Log successful completion
            execution_time = time.time() - start_time
            logger.info(
                f"Command completed successfully in {execution_time:.2f}s with return code {process.returncode}"
            )

            # Construct a result object similar to subprocess.CompletedProcess
            # to maintain compatibility with existing code
            return type(
                "CompletedProcess",
                (),
                {
                    "returncode": process.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "args": cmd,
                    "execution_time": execution_time,
                },
            )
        except subprocess.TimeoutExpired:
            # Log timeout
            elapsed_time = time.time() - start_time
            logger.warning(f"Command timed out after {elapsed_time:.2f}s")

            # Get resource usage before termination
            try:
                timeout_resources = self._get_process_resource_usage(process.pid)
                logger.info(f"Resource usage at timeout: {timeout_resources}")
            except Exception as e:
                logger.warning(f"Failed to get resource usage at timeout: {e}")

            # Enhanced process group termination with verification
            success, remaining_pids = self._terminate_process_group_with_verification(
                process.pid
            )

            if not success:
                logger.error(
                    f"Failed to terminate all processes. Remaining PIDs: {remaining_pids}"
                )

                # Additional cleanup for stubborn processes
                try:
                    # Find child processes that might still be running
                    ps_cmd = [
                        "ps",
                        "-o",
                        "pid",
                        "--ppid",
                        str(process.pid),
                        "--noheaders",
                    ]
                    child_pids = (
                        subprocess.check_output(ps_cmd, text=True).strip().split("\n")
                    )

                    # Kill any remaining children
                    for pid in child_pids:
                        if pid.strip():
                            try:
                                os.kill(int(pid.strip()), signal.SIGKILL)
                                logger.info(f"Killed child process {pid}")
                            except (ProcessLookupError, ValueError):
                                pass
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass  # Ignore if ps command fails
            # Raise an error to indicate timeout
            raise SemgrepRunnerError(
                f"Semgrep analysis timed out after {timeout} seconds for command: {' '.join(cmd)}"
            )
        except Exception as e:
            # Log other errors
            elapsed_time = time.time() - start_time
            logger.error(f"Command failed after {elapsed_time:.2f}s with error: {e}")

            # Try to terminate the process group
            try:
                success, remaining_pids = (
                    self._terminate_process_group_with_verification(process.pid)
                )
                if not success:
                    logger.error(
                        f"Failed to terminate all processes after error. Remaining PIDs: {remaining_pids}"
                    )
            except Exception as term_error:
                logger.error(f"Error while terminating process group: {term_error}")

            # Catch other potential errors during Popen or communicate
            print(f"ERROR: Semgrep execution failed: {e}")
            raise SemgrepRunnerError(
                f"Error during semgrep execution: {e} for command: {' '.join(cmd)}"
            )
