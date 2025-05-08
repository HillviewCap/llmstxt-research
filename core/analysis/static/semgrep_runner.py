import subprocess
import json
import os
import signal
import tempfile
import shutil
from typing import List, Dict, Any, Optional

class SemgrepRunnerError(Exception):
    pass

class SemgrepRunner:
    def __init__(self, rules_path: str, config: Optional[Dict[str, Any]] = None, registry_rulesets: Optional[List[str]] = None):
        self.rules_path = rules_path
        self.config = config or {}
        self.registry_rulesets = registry_rulesets or []
        self.rules = self._load_rules()
        self.rule_metadata = self._extract_rule_metadata()
        # Maximum content size for direct analysis (in bytes)
        self.max_content_size = self.config.get("max_content_size", 1024 * 1024)  # Default 1MB

    def _load_rules(self) -> List[str]:
        if not os.path.isdir(self.rules_path):
            raise SemgrepRunnerError(f"Rules path does not exist: {self.rules_path}")
        rules = []
        for file in os.listdir(self.rules_path):
            if file.endswith(".yml") or file.endswith(".yaml"):
                rules.append(os.path.join(self.rules_path, file))
        if not rules:
            raise SemgrepRunnerError("No Semgrep rules found in the specified directory.")
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
                    metadata[rule_id] = {"category": category, "priority": priority, "file": rule_file}
            except Exception:
                continue
        return metadata

    def run(self,
            target_path: Optional[str] = None,
            content: Optional[str] = None,
            language: Optional[str] = None) -> List[Dict[str, Any]]:
        if not content and not target_path:
            raise SemgrepRunnerError("Either target_path or content must be provided.")
        if content and not language:
            # If content is provided, language is essential for creating a correctly suffixed temp file
            # and for semgrep to know how to parse it.
            raise SemgrepRunnerError("Language must be provided when scanning content.")

        # Check content size before processing
        if content and len(content) > self.max_content_size:
            print(f"Content size ({len(content)} bytes) exceeds maximum allowed size ({self.max_content_size} bytes)")
            return [{"rule_id": "content_too_large",
                     "path": "in-memory-content",
                     "start": {"line": 1, "col": 1},
                     "end": {"line": 1, "col": 1},
                     "extra": {"message": f"Content size ({len(content)} bytes) exceeds maximum allowed size"},
                     "category": "Performance",
                     "priority": "Medium"}]

        # Skip semgrep for generic/markdown content that's too complex
        if language == 'generic' and content and self._is_complex_content(content):
            print(f"Skipping semgrep for complex generic content ({len(content)} bytes, {content.count('\\n')} lines)")
            return [{"rule_id": "complex_generic_content",
                     "path": "in-memory-content",
                     "start": {"line": 1, "col": 1},
                     "end": {"line": 1, "col": 1},
                     "extra": {"message": "Content too complex for generic language analysis"},
                     "category": "Performance",
                     "priority": "Low"}]

        actual_scan_path = None
        temp_file_path_for_cleanup = None # Store path for cleanup

        try:
            if content:
                # Ensure language is valid for a file extension, e.g. "python" -> ".py"
                # Basic sanitization for file extension.
                safe_lang_suffix = "".join(c for c in language if c.isalnum()) or "tmp"
                
                # Create a temporary file
                # delete=False is used because we need to close it before semgrep can use it (on some OS),
                # and then manually delete it.
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix=f".{safe_lang_suffix}", # e.g. .py, .js
                    delete=False,
                    encoding='utf-8'
                ) as temp_file_handle:
                    temp_file_handle.write(content)
                    temp_file_handle.flush() # Ensure content is written to disk
                    actual_scan_path = temp_file_handle.name
                    temp_file_path_for_cleanup = actual_scan_path
                # temp_file_handle is now closed here after exiting the 'with' block.
                # Semgrep can now access the file.
            else: # target_path must be provided
                if not target_path or not os.path.exists(target_path): # Check existence if target_path is used
                    raise SemgrepRunnerError(f"Target path does not exist or not provided: {target_path}")
                actual_scan_path = target_path
            
            # Construct Semgrep command
            cmd = [
                "semgrep",
                "--json", # Output in JSON format
                "--timeout", "30", # Set explicit timeout for semgrep itself
            ]
            
            # For generic language, use a different approach
            if language == 'generic':
                # Use a more efficient approach for generic content
                # Instead of a pattern that might cause timeouts, use a simple rule
                # that's less likely to hang
                cmd.extend([
                    "--config", "r2c-ci",  # Use a lightweight ruleset
                    "--max-memory", "1024",  # Limit memory usage
                    "--max-target-bytes", str(self.max_content_size),  # Limit file size
                    actual_scan_path
                ])
            else:
                # Normal rules-based scanning
                # Add local rules path
                cmd.extend(["--config", self.rules_path])
                
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
                raise SemgrepRunnerError("Semgrep executable not found. Please ensure it is installed and in PATH.")

            # Calculate dynamic timeout based on content size
            timeout = self._calculate_timeout(content if content else os.path.getsize(actual_scan_path))
            print(f"Running semgrep with {timeout}s timeout for {len(content) if content else 'file'} bytes")
            
            # Execute Semgrep with dynamic timeout
            process = self.run_with_process_group_timeout(cmd, timeout=timeout)

            # Semgrep exit codes:
            # 0: No findings
            # 1: Findings found
            # >1: Error (e.g., 2 for CLI parsing error, rule error, etc.)
            if process.returncode > 1:
                error_output = process.stderr if process.stderr.strip() else process.stdout
                raise SemgrepRunnerError(
                    f"Semgrep execution failed with code {process.returncode}: {error_output}"
                )
            
            # Even with return code 0 or 1, stdout might be empty if semgrep had an issue
            # that didn't result in a >1 exit code (e.g. some misconfigurations).
            # The parse_results method should handle empty or invalid JSON.
            return self.parse_results(process.stdout)

        finally:
            # Cleanup: Remove the temporary file if it was created
            if temp_file_path_for_cleanup and os.path.exists(temp_file_path_for_cleanup):
                try:
                    os.remove(temp_file_path_for_cleanup)
                except OSError as e:
                    # Log this error (e.g., using a proper logger if available in the project)
                    # For now, print a warning. This should not stop the program.
                    print(f"Warning: Failed to remove temporary file {temp_file_path_for_cleanup}: {e}")

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
                    "category": self.rule_metadata.get(rule_id, {}).get("category", "Uncategorized"),
                    "priority": self.rule_metadata.get(rule_id, {}).get("priority", "Medium"),
                }
                findings.append(finding)
            return findings
        except Exception as e:
            raise SemgrepRunnerError(f"Failed to parse Semgrep output: {e}")

    def list_rules(self) -> List[Dict[str, Any]]:
        return [
            {"id": rule_id, **meta}
            for rule_id, meta in self.rule_metadata.items()
        ]
        
    def _is_complex_content(self, content: str) -> bool:
        """
        Determine if content is too complex for generic language analysis
        """
        # Check content size
        if len(content) > 100000:  # 100KB
            return True
            
        # Check line count
        if content.count('\n') > 1000:  # More than 1000 lines
            return True
            
        # Check for complex patterns that might cause semgrep to hang
        complex_patterns = [
            r'```',  # Code blocks in markdown
            r'\[\[',  # Wiki-style links
            r'\{\{',  # Template syntax
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
        # Start process in new process group
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid  # Create new process group
        )
        
        # Track resource usage
        start_time = time.time()
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            # Log execution time for monitoring
            execution_time = time.time() - start_time
            print(f"Semgrep execution completed in {execution_time:.2f}s")
            
            # Construct a result object similar to subprocess.CompletedProcess
            # to maintain compatibility with existing code
            return type('CompletedProcess', (), {
                'returncode': process.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'args': cmd,
                'execution_time': execution_time
            })
        except subprocess.TimeoutExpired:
            # Log timeout with detailed information
            print(f"TIMEOUT: Semgrep process timed out after {timeout}s for command: {' '.join(cmd)}")
            
            # Kill entire process group more aggressively
            try:
                # First try SIGTERM
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                
                # Wait briefly for termination
                termination_timeout = min(5, timeout * 0.1)  # 10% of original timeout or 5s max
                termination_start = time.time()
                
                # Poll until process terminates or timeout
                while time.time() - termination_start < termination_timeout:
                    if process.poll() is not None:
                        print(f"Process terminated with SIGTERM in {time.time() - termination_start:.2f}s")
                        break
                    time.sleep(0.1)
                
                # If still running, use SIGKILL
                if process.poll() is None:
                    print("Process still running after SIGTERM, sending SIGKILL")
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    process.wait(timeout=2)  # Short wait for SIGKILL
            except (subprocess.TimeoutExpired, ProcessLookupError) as e:
                print(f"Error during process termination: {e}")
                # Final attempt with SIGKILL if process still exists
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Process already gone
                    
            # Check for any remaining processes and kill them
            try:
                # Find child processes that might still be running
                ps_cmd = ["ps", "-o", "pid", "--ppid", str(process.pid), "--noheaders"]
                child_pids = subprocess.check_output(ps_cmd, text=True).strip().split('\n')
                
                # Kill any remaining children
                for pid in child_pids:
                    if pid.strip():
                        try:
                            os.kill(int(pid.strip()), signal.SIGKILL)
                            print(f"Killed child process {pid}")
                        except (ProcessLookupError, ValueError):
                            pass
            except (subprocess.SubprocessError, FileNotFoundError):
                pass  # Ignore if ps command fails
                
            # Raise an error to indicate timeout
            raise SemgrepRunnerError(f"Semgrep analysis timed out after {timeout} seconds for command: {' '.join(cmd)}")
        except Exception as e:
            # Catch other potential errors during Popen or communicate
            print(f"ERROR: Semgrep execution failed: {e}")
            raise SemgrepRunnerError(f"Error during semgrep execution: {e} for command: {' '.join(cmd)}")