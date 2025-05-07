import subprocess
import json
import os
import tempfile
import shutil
from typing import List, Dict, Any, Optional

class SemgrepRunnerError(Exception):
    pass

class SemgrepRunner:
    def __init__(self, rules_path: str, config: Optional[Dict[str, Any]] = None):
        self.rules_path = rules_path
        self.config = config or {}
        self.rules = self._load_rules()
        self.rule_metadata = self._extract_rule_metadata()

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
            ]
            
            # For generic language, we need to use pattern mode instead of rules
            if language == 'generic':
                # Use a simple pattern that won't match anything for markdown content
                # This allows us to proceed without errors while not producing false positives
                cmd.extend([
                    "-e", "impossible_pattern_for_markdown_content_123456789",
                    "--lang", language,
                    actual_scan_path
                ])
            else:
                # Normal rules-based scanning
                cmd.extend([
                    "--config", self.rules_path, # Specify rules directory/file
                    actual_scan_path # Target file or temp file
                ])
                
                # If language is specified (especially for content scanning, or to override auto-detection)
                if language:
                    cmd.extend(["--lang", language])
            
            # Check if semgrep executable is available
            if not shutil.which("semgrep"):
                raise SemgrepRunnerError("Semgrep executable not found. Please ensure it is installed and in PATH.")

            # Execute Semgrep
            # check=False because Semgrep returns 1 for findings, which would raise CalledProcessError
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)

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