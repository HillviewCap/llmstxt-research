#!/usr/bin/env python3
"""
Test Runner for LLMs.txt Security Analysis Platform

This script provides a unified interface to run all system tests, including:
- System tests (end-to-end pipeline tests)
- Performance benchmarks
- Accuracy tests
- System validation tests

It can be used to run individual test suites or all tests at once.
"""

import os
import sys
import argparse
import logging
import time
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TestRunner")

def run_system_tests():
    """Run the system tests."""
    logger.info("Running system tests...")
    import pytest
    
    # Run pytest with the system_test.py file
    result = pytest.main(["-v", "tests/system_test.py"])
    
    return result == 0  # Return True if tests passed

def run_performance_benchmarks(iterations=3, max_multiplier=10):
    """Run performance benchmarks."""
    logger.info("Running performance benchmarks...")
    from tests.performance_benchmark import PerformanceBenchmark
    
    benchmark = PerformanceBenchmark()
    
    # Run all benchmark types
    pipeline_results = benchmark.benchmark_pipeline(iterations=iterations)
    component_results = benchmark.benchmark_components(iterations=iterations)
    scaling_results = benchmark.benchmark_scaling(max_multiplier=max_multiplier)
    
    return {
        "pipeline": pipeline_results,
        "components": component_results,
        "scaling": scaling_results
    }

def run_accuracy_tests():
    """Run accuracy tests."""
    logger.info("Running accuracy tests...")
    from tests.accuracy_test import AccuracyTest
    
    accuracy_test = AccuracyTest()
    results = accuracy_test.run_accuracy_test()
    
    return results

def run_system_validation():
    """Run system validation tests."""
    logger.info("Running system validation tests...")
    from tests.system_validation import SystemValidation
    
    validation = SystemValidation()
    results = validation.run_all_validations()
    
    return results

def generate_summary_report(results, output_dir="test_results"):
    """Generate a summary report of all test results."""
    logger.info("Generating summary report...")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Create summary report
    summary = {
        "timestamp": datetime.now().isoformat(),
        "results": results
    }
    
    # Calculate overall pass/fail status
    system_tests_passed = results.get("system_tests", {}).get("passed", False)
    
    # For performance benchmarks, check if any tests failed
    performance_passed = True
    if "performance" in results:
        # No specific pass/fail criteria for performance, just check if it ran
        performance_passed = "pipeline" in results["performance"]
    
    # For accuracy tests, check overall metrics
    accuracy_passed = True
    if "accuracy" in results:
        # Consider passed if F1 score is above 0.7
        f1_score = results["accuracy"].get("overall", {}).get("f1_score", 0)
        accuracy_passed = f1_score > 0.7
    
    # For system validation, check if all tests passed
    validation_passed = True
    if "validation" in results:
        # Check if any validation tests failed
        for test_name, test_result in results["validation"].items():
            if not test_result.get("passed", False):
                validation_passed = False
                break
    
    # Overall status
    summary["overall_status"] = {
        "passed": system_tests_passed and performance_passed and accuracy_passed and validation_passed,
        "system_tests_passed": system_tests_passed,
        "performance_passed": performance_passed,
        "accuracy_passed": accuracy_passed,
        "validation_passed": validation_passed
    }
    
    # Save summary report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_file = os.path.join(output_dir, f"test_summary_{timestamp}.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"Summary report saved to {summary_file}")
    
    # Also create a simple text report
    text_report = os.path.join(output_dir, f"test_summary_{timestamp}.txt")
    with open(text_report, 'w') as f:
        f.write(f"LLMs.txt Security Analysis Platform - Test Summary\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
        
        f.write("Overall Status: ")
        if summary["overall_status"]["passed"]:
            f.write("PASSED\n\n")
        else:
            f.write("FAILED\n\n")
        
        f.write("System Tests: ")
        f.write("PASSED\n" if summary["overall_status"]["system_tests_passed"] else "FAILED\n")
        
        f.write("Performance Benchmarks: ")
        f.write("PASSED\n" if summary["overall_status"]["performance_passed"] else "FAILED\n")
        
        f.write("Accuracy Tests: ")
        f.write("PASSED\n" if summary["overall_status"]["accuracy_passed"] else "FAILED\n")
        
        f.write("System Validation: ")
        f.write("PASSED\n" if summary["overall_status"]["validation_passed"] else "FAILED\n")
        
        if "accuracy" in results:
            f.write("\nAccuracy Metrics:\n")
            overall = results["accuracy"].get("overall", {})
            f.write(f"  Precision: {overall.get('precision', 0):.4f}\n")
            f.write(f"  Recall: {overall.get('recall', 0):.4f}\n")
            f.write(f"  F1 Score: {overall.get('f1_score', 0):.4f}\n")
        
        if "performance" in results and "pipeline" in results["performance"]:
            f.write("\nPerformance Summary:\n")
            for file, metrics in results["performance"]["pipeline"].items():
                if file != "overall":
                    f.write(f"  {file}: {metrics.get('avg_time', 0):.4f}s\n")
    
    logger.info(f"Text report saved to {text_report}")
    
    return summary

def run_advanced_tests():
    """Run advanced tests including sandbox tests."""
    logger.info("Running advanced tests...")
    
    import unittest
    import tests.advanced.test_sandbox
    
    # Create test suite for advanced tests
    suite = unittest.TestLoader().loadTestsFromModule(tests.advanced.test_sandbox)
    
    # Run tests
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    
    # Return True if all tests passed
    return result.wasSuccessful()

def run_sandbox_tests():
    """Run sandbox-specific tests."""
    logger.info("Running sandbox tests...")
    
    import unittest
    import tests.advanced.test_sandbox
    
    # Create test suite for sandbox tests
    suite = unittest.TestLoader().loadTestsFromModule(tests.advanced.test_sandbox)
    
    # Run tests
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    
    # Return True if all tests passed
    return result.wasSuccessful()

def main():
    """Main function to parse arguments and run tests."""
    parser = argparse.ArgumentParser(
        description="Test Runner for LLMs.txt Security Analysis Platform",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--tests",
        choices=["system", "performance", "accuracy", "validation", "advanced", "sandbox", "all"],
        default="all",
        help="Which tests to run"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="test_results",
        help="Directory to save test results"
    )
    
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations for performance benchmarks"
    )
    
    parser.add_argument(
        "--max-multiplier",
        type=int,
        default=10,
        help="Maximum size multiplier for scaling benchmark"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize results dictionary
    results = {}
    
    # Run selected tests
    if args.tests in ["system", "all"]:
        results["system_tests"] = {"passed": run_system_tests()}
    
    if args.tests in ["performance", "all"]:
        results["performance"] = run_performance_benchmarks(
            iterations=args.iterations,
            max_multiplier=args.max_multiplier
        )
    
    if args.tests in ["accuracy", "all"]:
        results["accuracy"] = run_accuracy_tests()
    
    if args.tests in ["validation", "all"]:
        results["validation"] = run_system_validation()
    
    if args.tests in ["advanced", "all"]:
        results["advanced_tests"] = {"passed": run_advanced_tests()}
    
    if args.tests in ["sandbox", "all"]:
        results["sandbox_tests"] = {"passed": run_sandbox_tests()}
    
    # Generate summary report
    summary = generate_summary_report(results, output_dir=args.output_dir)
    
    # Print final status
    if summary["overall_status"]["passed"]:
        logger.info("All tests PASSED!")
        return 0
    else:
        logger.warning("Some tests FAILED. See summary report for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())