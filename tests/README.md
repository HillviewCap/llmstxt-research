# System Testing Framework for LLMs.txt Security Analysis Platform

This directory contains a comprehensive testing framework for the LLMs.txt Security Analysis Platform, focusing on system-level testing, performance benchmarking, accuracy testing, and system validation.

## Overview

The testing framework consists of several components:

1. **System Tests** (`system_test.py`): End-to-end tests that verify the interaction and data flow between all major components.
2. **Performance Benchmarking** (`performance_benchmark.py`): Tools to measure execution time of the full pipeline and critical sub-components.
3. **Accuracy Testing** (`accuracy_test.py`): Framework to measure true positives, false positives, and false negatives against known vulnerabilities.
4. **System Validation** (`system_validation.py`): Tests that validate system behavior under various conditions, including handling of malformed inputs.
5. **Test Runner** (`run_tests.py`): Unified interface to run all tests and generate summary reports.

## Test Data

The `data/` directory contains sample LLMs.txt files with known characteristics:

- `sample_clean.llms.txt`: A clean file with no security issues
- `sample_prompt_injection.llms.txt`: Contains prompt injection vulnerabilities
- `sample_secrets.llms.txt`: Contains API keys and credentials
- `sample_malicious_code.llms.txt`: Contains malicious code patterns
- `sample_malformed.llms.txt`: A malformed file with structural issues

## Running Tests

### Running All Tests

To run all tests and generate a comprehensive report:

```bash
python tests/run_tests.py --tests all --output-dir test_results
```

### Running Specific Test Suites

To run only specific test suites:

```bash
# Run only system tests
python tests/run_tests.py --tests system

# Run only performance benchmarks
python tests/run_tests.py --tests performance --iterations 5

# Run only accuracy tests
python tests/run_tests.py --tests accuracy

# Run only system validation tests
python tests/run_tests.py --tests validation
```

### Running Individual Test Files

You can also run individual test files directly:

```bash
# Run system tests with pytest
pytest -v tests/system_test.py

# Run performance benchmarks
python tests/performance_benchmark.py

# Run accuracy tests
python tests/accuracy_test.py

# Run system validation tests
python tests/system_validation.py
```

## Test Results

Test results are saved in the specified output directory (default: `test_results/`). The results include:

- JSON files with detailed test results
- Text reports with summary information
- Visualizations of performance and accuracy metrics (saved as PNG files)

## Extending the Framework

### Adding New Test Cases

To add new test cases:

1. For system tests, add new test methods to the existing classes in `system_test.py`
2. For accuracy tests, update the ground truth data in `accuracy_test.py`
3. For system validation, add new validation methods in `system_validation.py`

### Adding New Test Data

To add new test data:

1. Create new LLMs.txt files in the `data/` directory
2. Update the ground truth data in `accuracy_test.py` to include expected findings

## Performance Benchmarking

The performance benchmarking framework measures:

- Total pipeline execution time
- Component-level execution times
- Scaling performance with increasing input size

Results are saved as JSON files and visualizations.

## Accuracy Testing

The accuracy testing framework calculates:

- True positives: Vulnerabilities correctly identified
- False positives: Incorrectly identified vulnerabilities
- False negatives: Missed vulnerabilities
- Precision, recall, and F1 score

Results are saved as JSON files, CSV reports, and visualizations.

## System Validation

The system validation framework tests:

- Empty input handling
- Malformed input handling
- Large input handling
- Special characters handling
- Concurrent execution
- Error recovery capabilities

Results indicate whether each test passed or failed, along with detailed information.