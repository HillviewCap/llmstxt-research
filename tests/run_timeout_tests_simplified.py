#!/usr/bin/env python3
"""
Simplified script to run tests for the static analysis timeout fix.

This script:
1. Runs tests with the current (fixed) implementation
2. Temporarily modifies the code to simulate the original behavior
3. Runs tests with the simulated original implementation
4. Compares the results

Usage:
    python tests/run_timeout_tests_simplified.py
"""

import os
import sys
import time
import logging
import subprocess
import shutil
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TimeoutTest")

# Paths to relevant files
SEMGREP_RUNNER_PATH = "core/analysis/static/semgrep_runner.py"
STATIC_ANALYZER_PATH = "core/analysis/static/analyzer.py"
TEST_FILE_PATH = "tests/test_static_analysis_timeout_simplified.py"

def run_tests():
    """Run the timeout tests."""
    logger.info("Running timeout tests...")
    result = subprocess.run(
        ["python3", "-m", "pytest", TEST_FILE_PATH, "-v"],
        capture_output=True,
        text=True
    )
    
    logger.info(f"Test exit code: {result.returncode}")
    logger.info(f"Test output:\n{result.stdout}")
    
    if result.stderr:
        logger.error(f"Test errors:\n{result.stderr}")
    
    return result.returncode == 0, result.stdout, result.stderr

@contextmanager
def backup_and_restore_files(files):
    """Backup files and restore them after the context block."""
    backup_files = {}
    try:
        # Backup files
        for file_path in files:
            backup_path = f"{file_path}.bak"
            shutil.copy2(file_path, backup_path)
            backup_files[file_path] = backup_path
        
        yield
    finally:
        # Restore files
        for file_path, backup_path in backup_files.items():
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, file_path)
                os.remove(backup_path)

def simulate_original_behavior():
    """
    Modify the code to simulate the original behavior before the timeout fix.
    
    This function:
    1. Disables content size checks
    2. Disables complex content detection
    3. Uses fixed timeouts instead of dynamic ones
    4. Simplifies process termination
    """
    # Modify semgrep_runner.py
    with open(SEMGREP_RUNNER_PATH, 'r') as f:
        semgrep_runner_content = f.read()
    
    # Disable content size checks
    semgrep_runner_content = semgrep_runner_content.replace(
        "if content and len(content) > self.max_content_size:",
        "if False:  # Disabled content size check"
    )
    
    # Disable complex content detection
    semgrep_runner_content = semgrep_runner_content.replace(
        "if language == 'generic' and content and self._is_complex_content(content):",
        "if False:  # Disabled complex content detection"
    )
    
    # Use fixed timeout instead of dynamic
    semgrep_runner_content = semgrep_runner_content.replace(
        "timeout = self._calculate_timeout(content if content else os.path.getsize(actual_scan_path))",
        "timeout = 30  # Fixed timeout to simulate original behavior"
    )
    
    # Simplify process termination (simulate original behavior)
    semgrep_runner_content = semgrep_runner_content.replace(
        "def run_with_process_group_timeout(self, cmd, timeout=60):",
        """def run_with_process_group_timeout(self, cmd, timeout=60):
        \"\"\"Simplified version to simulate original behavior\"\"\"
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return type('CompletedProcess', (), {
                'returncode': process.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'args': cmd,
                'execution_time': 0
            })
        except subprocess.TimeoutExpired:
            process.kill()
            raise SemgrepRunnerError(f"Semgrep analysis timed out after {timeout} seconds")"""
    )
    
    # Write modified content back
    with open(SEMGREP_RUNNER_PATH, 'w') as f:
        f.write(semgrep_runner_content)
    
    # Modify static_analyzer.py
    with open(STATIC_ANALYZER_PATH, 'r') as f:
        static_analyzer_content = f.read()
    
    # Disable content size and line count checks
    static_analyzer_content = static_analyzer_content.replace(
        "if content_to_scan and content_size > self.max_content_size:",
        "if False:  # Disabled content size check"
    )
    
    static_analyzer_content = static_analyzer_content.replace(
        "if content_to_scan and content_lines > self.max_content_lines:",
        "if False:  # Disabled line count check"
    )
    
    # Disable complex content detection
    static_analyzer_content = static_analyzer_content.replace(
        "if effective_language == 'generic' and self._is_complex_generic_content(content_to_scan):",
        "if False:  # Disabled complex content detection"
    )
    
    static_analyzer_content = static_analyzer_content.replace(
        "if self._is_complex_generic_content(content_to_scan):",
        "if False:  # Disabled complex content detection"
    )
    
    # Write modified content back
    with open(STATIC_ANALYZER_PATH, 'w') as f:
        f.write(static_analyzer_content)

def main():
    """Main function to run the tests."""
    # Create a results directory
    results_dir = "test_results"
    os.makedirs(results_dir, exist_ok=True)
    
    # Run tests with current (fixed) implementation
    logger.info("Running tests with current implementation (with fixes)...")
    current_success, current_stdout, current_stderr = run_tests()
    
    with open(os.path.join(results_dir, "fixed_implementation_results.txt"), 'w') as f:
        f.write(f"Success: {current_success}\n\n")
        f.write("STDOUT:\n")
        f.write(current_stdout)
        f.write("\n\nSTDERR:\n")
        f.write(current_stderr)
    
    # Modify code to simulate original behavior
    with backup_and_restore_files([SEMGREP_RUNNER_PATH, STATIC_ANALYZER_PATH]):
        logger.info("Simulating original behavior (without fixes)...")
        simulate_original_behavior()
        
        # Run tests with simulated original implementation
        logger.info("Running tests with simulated original implementation...")
        original_success, original_stdout, original_stderr = run_tests()
        
        with open(os.path.join(results_dir, "original_implementation_results.txt"), 'w') as f:
            f.write(f"Success: {original_success}\n\n")
            f.write("STDOUT:\n")
            f.write(original_stdout)
            f.write("\n\nSTDERR:\n")
            f.write(original_stderr)
    
    # Compare results
    logger.info("\n\n=== TEST RESULTS COMPARISON ===")
    logger.info(f"Current implementation (with fixes): {'PASSED' if current_success else 'FAILED'}")
    logger.info(f"Original implementation (simulated): {'PASSED' if original_success else 'FAILED'}")
    
    if current_success and not original_success:
        logger.info("✅ IMPROVEMENT CONFIRMED: The fixes successfully resolved the timeout issues!")
    elif current_success and original_success:
        logger.info("⚠️ INCONCLUSIVE: Both implementations passed the tests. The test cases might not be challenging enough.")
    elif not current_success and not original_success:
        logger.info("❌ NO IMPROVEMENT: Both implementations failed the tests.")
    else:  # not current_success and original_success
        logger.info("❌ REGRESSION: The original implementation passed but the current one failed!")
    
    logger.info(f"Detailed test results saved to {results_dir}/")
    
    return 0 if current_success else 1

if __name__ == "__main__":
    sys.exit(main())