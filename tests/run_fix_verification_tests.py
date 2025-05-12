#!/usr/bin/env python3
"""
Script to run tests verifying the fixes for static analysis timeout issues.

This script:
1. Runs the tests for the static analysis timeout fixes
2. Captures the output and results
3. Generates a detailed report

Usage:
    python tests/run_fix_verification_tests.py
"""

import os
import sys
import time
import logging
import subprocess
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FixVerification")

# Paths to relevant files
TEST_FILE_PATH = "tests/test_static_analysis_fixes.py"
REPORT_DIR = "test_results"
REPORT_FILE = os.path.join(REPORT_DIR, "fix_verification_report.md")

def run_tests():
    """Run the fix verification tests and capture the output."""
    logger.info("Running fix verification tests...")
    
    start_time = time.time()
    result = subprocess.run(
        ["python3", "-m", "pytest", TEST_FILE_PATH, "-v"],
        capture_output=True,
        text=True
    )
    execution_time = time.time() - start_time
    
    logger.info(f"Tests completed in {execution_time:.2f}s with exit code: {result.returncode}")
    
    if result.stderr:
        logger.warning(f"Test errors:\n{result.stderr}")
    
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "execution_time": execution_time
    }

def parse_test_results(stdout):
    """Parse the pytest output to extract test results."""
    test_results = []
    
    # Split the output by test
    test_lines = stdout.split("\n")
    current_test = None
    
    for line in test_lines:
        if "test_" in line and "::" in line:
            # This is a test result line
            parts = line.strip().split(" ")
            test_name = parts[0]
            result = "PASSED" if "PASSED" in line else "FAILED" if "FAILED" in line else "ERROR" if "ERROR" in line else "SKIPPED"
            
            test_results.append({
                "name": test_name,
                "result": result,
                "details": line
            })
    
    return test_results

def generate_report(test_results, execution_data):
    """Generate a detailed report of the test results."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    
    with open(REPORT_FILE, "w") as f:
        f.write("# Static Analysis Timeout Fix Verification Report\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Summary\n\n")
        f.write(f"- **Overall Result**: {'✅ PASSED' if execution_data['success'] else '❌ FAILED'}\n")
        f.write(f"- **Execution Time**: {execution_data['execution_time']:.2f}s\n")
        f.write(f"- **Total Tests**: {len(test_results)}\n")
        
        passed = sum(1 for t in test_results if t['result'] == 'PASSED')
        failed = sum(1 for t in test_results if t['result'] == 'FAILED')
        error = sum(1 for t in test_results if t['result'] == 'ERROR')
        skipped = sum(1 for t in test_results if t['result'] == 'SKIPPED')
        
        f.write(f"- **Passed**: {passed}\n")
        f.write(f"- **Failed**: {failed}\n")
        f.write(f"- **Error**: {error}\n")
        f.write(f"- **Skipped**: {skipped}\n\n")
        
        f.write("## Fix Verification\n\n")
        
        # Check for specific tests that verify the fixes
        type_error_tests = [t for t in test_results if "test_calculate_timeout_with_string_content" in t['name'] or "test_run_method_content_size_handling" in t['name']]
        markdown_timeout_tests = [t for t in test_results if "test_markdown_analyzer_size_check" in t['name'] or "test_content_scanner_size_check" in t['name']]
        size_limit_tests = [t for t in test_results if "test_static_analyzer_size_check" in t['name'] or "test_various_content_sizes" in t['name']]
        complex_content_tests = [t for t in test_results if "test_complex_markdown_handling" in t['name'] or "test_extremely_large_content" in t['name']]
        
        # Report on TypeError fix
        f.write("### 1. TypeError Fix in Semgrep Runner\n\n")
        if all(t['result'] == 'PASSED' for t in type_error_tests):
            f.write("✅ **VERIFIED**: The fix for the TypeError in semgrep_runner is working correctly.\n\n")
            f.write("The system now properly converts content size to an integer before performing calculations.\n\n")
        else:
            f.write("❌ **NOT VERIFIED**: The fix for the TypeError in semgrep_runner could not be verified.\n\n")
            f.write("Some tests failed. See the detailed results section for more information.\n\n")
        
        # Report on Markdown Timeout fix
        f.write("### 2. Markdown Analyzer Timeout Fix\n\n")
        if all(t['result'] == 'PASSED' for t in markdown_timeout_tests):
            f.write("✅ **VERIFIED**: The fix for the markdown analyzer timeout is working correctly.\n\n")
            f.write("The system now properly checks content size and exits early for large content.\n\n")
        else:
            f.write("❌ **NOT VERIFIED**: The fix for the markdown analyzer timeout could not be verified.\n\n")
            f.write("Some tests failed. See the detailed results section for more information.\n\n")
        
        # Report on Size Limit Enforcement
        f.write("### 3. Size Limit Enforcement\n\n")
        if all(t['result'] == 'PASSED' for t in size_limit_tests):
            f.write("✅ **VERIFIED**: All analyzers correctly respect their size limits.\n\n")
            f.write("The system properly enforces size limits and exits early for oversized content.\n\n")
        else:
            f.write("❌ **NOT VERIFIED**: Size limit enforcement could not be verified.\n\n")
            f.write("Some tests failed. See the detailed results section for more information.\n\n")
        
        # Report on Complex Content Handling
        f.write("### 4. Complex Content Handling\n\n")
        if all(t['result'] == 'PASSED' for t in complex_content_tests):
            f.write("✅ **VERIFIED**: The system correctly handles complex content without timeouts.\n\n")
            f.write("Complex and extremely large content is properly detected and handled with appropriate strategies.\n\n")
        else:
            f.write("❌ **NOT VERIFIED**: Complex content handling could not be verified.\n\n")
            f.write("Some tests failed. See the detailed results section for more information.\n\n")
        
        # Overall assessment
        f.write("## Overall Assessment\n\n")
        if execution_data['success']:
            f.write("✅ **FIXES VERIFIED**: All tests passed, confirming that the fixes for the static analysis timeout issues are working correctly.\n\n")
            f.write("The system now properly:\n")
            f.write("1. Converts content size to an integer before calculations\n")
            f.write("2. Checks content size and exits early for large content\n")
            f.write("3. Respects size limits across all analyzers\n")
            f.write("4. Handles a variety of content sizes appropriately\n")
            f.write("5. Processes complex content without timeouts\n\n")
        else:
            f.write("❌ **FIXES NOT FULLY VERIFIED**: Some tests failed, indicating that the fixes may not be completely effective.\n\n")
            f.write("See the detailed results section for more information on which aspects need attention.\n\n")
        
        # Detailed results
        f.write("## Detailed Test Results\n\n")
        f.write("| Test | Result | Details |\n")
        f.write("|------|--------|--------|\n")
        
        for test in test_results:
            result_icon = "✅" if test['result'] == 'PASSED' else "❌" if test['result'] == 'FAILED' else "⚠️" if test['result'] == 'ERROR' else "⏩"
            f.write(f"| {test['name']} | {result_icon} {test['result']} | {test['details']} |\n")
        
        f.write("\n## Raw Test Output\n\n")
        f.write("```\n")
        f.write(execution_data['stdout'])
        f.write("\n```\n\n")
        
        if execution_data['stderr']:
            f.write("## Errors\n\n")
            f.write("```\n")
            f.write(execution_data['stderr'])
            f.write("\n```\n")
    
    logger.info(f"Report generated: {REPORT_FILE}")
    return REPORT_FILE

def main():
    """Main function to run the tests and generate a report."""
    logger.info("Starting fix verification...")
    
    # Run the tests
    execution_data = run_tests()
    
    # Parse the test results
    test_results = parse_test_results(execution_data['stdout'])
    
    # Generate a report
    report_file = generate_report(test_results, execution_data)
    
    logger.info(f"Fix verification completed. Report saved to {report_file}")
    
    # Print a summary to the console
    passed = sum(1 for t in test_results if t['result'] == 'PASSED')
    total = len(test_results)
    
    print("\n=== FIX VERIFICATION SUMMARY ===")
    print(f"Tests: {passed}/{total} passed")
    print(f"Overall result: {'PASSED' if execution_data['success'] else 'FAILED'}")
    print(f"Execution time: {execution_data['execution_time']:.2f}s")
    print(f"Detailed report: {report_file}")
    
    return 0 if execution_data['success'] else 1

if __name__ == "__main__":
    sys.exit(main())