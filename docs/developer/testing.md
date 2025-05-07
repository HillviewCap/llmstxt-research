# LLMs.txt Security Analysis Platform: Testing Guide

This guide provides comprehensive information on testing the LLMs.txt Security Analysis Platform, including unit testing, integration testing, system testing, and performance testing.

## Testing Framework Overview

The platform uses a comprehensive testing framework located in the `tests/` directory. The framework includes:

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test interactions between components
3. **System Tests**: Test the entire system end-to-end
4. **Performance Tests**: Measure system performance
5. **Accuracy Tests**: Evaluate detection accuracy

## Test Directory Structure

```
tests/
├── unit/                 # Unit tests
├── integration/          # Integration tests
├── data/                 # Test data files
│   ├── sample_clean.llms.txt
│   ├── sample_malformed.llms.txt
│   ├── sample_malicious_code.llms.txt
│   ├── sample_prompt_injection.llms.txt
│   └── sample_secrets.llms.txt
├── system_test.py        # System-level tests
├── performance_benchmark.py  # Performance tests
├── accuracy_test.py      # Accuracy evaluation
├── system_validation.py  # System validation tests
├── run_tests.py          # Test runner
└── README.md             # Testing documentation
```

## Setting Up the Test Environment

### Prerequisites

- Python 3.11+
- UV package manager
- Test dependencies

### Installing Test Dependencies

```bash
uv pip install -r tests/requirements-test.txt
```

The `requirements-test.txt` file includes:

```
pytest==7.4.0
pytest-cov==4.1.0
pytest-benchmark==4.0.0
pytest-mock==3.11.1
```

### Test Configuration

Tests use a separate configuration file to avoid affecting the production environment:

```yaml
# tests/test_config.yaml
db:
  path: ":memory:"  # Use in-memory SQLite database for testing

pipeline_workers: 2  # Reduce workers for testing

# Other test-specific configurations
```

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

### Running Unit Tests

To run unit tests:

```bash
pytest -v tests/unit/
```

### Running Integration Tests

To run integration tests:

```bash
pytest -v tests/integration/
```

## Writing Tests

### Unit Tests

Unit tests focus on testing individual components in isolation. They should be:

- Fast
- Independent
- Focused on a single component
- Use mocks for dependencies

Example unit test for the `ContentProcessor`:

```python
# tests/unit/content/test_processor.py
import pytest
from core.content.processor import ContentProcessor

def test_process_extracts_code_blocks():
    """Test that the processor correctly extracts code blocks."""
    processor = ContentProcessor()
    
    # Sample content with a code block
    content_item = {
        "content": "# Sample\n\n```python\nprint('hello')\n```\n"
    }
    
    processed = processor.process(content_item)
    
    assert "structure" in processed
    assert "code_blocks" in processed["structure"]
    assert len(processed["structure"]["code_blocks"]) == 1
    assert processed["structure"]["code_blocks"][0]["language"] == "python"
    assert processed["structure"]["code_blocks"][0]["content"] == "print('hello')"
```

### Integration Tests

Integration tests focus on testing interactions between components. They should:

- Test component interactions
- Use minimal mocking
- Focus on interfaces between components

Example integration test for the database and content retriever:

```python
# tests/integration/test_content_retrieval.py
import pytest
import sqlite3
import tempfile
from core.database.connector import DatabaseConnector
from core.content.retriever import ContentRetriever

@pytest.fixture
def test_db():
    """Create a temporary test database."""
    # Create a temporary database file
    db_file = tempfile.NamedTemporaryFile(delete=False)
    db_path = db_file.name
    db_file.close()
    
    # Create test schema and insert test data
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE domains (
        id INTEGER PRIMARY KEY,
        domain TEXT UNIQUE
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        domain_id INTEGER,
        url TEXT UNIQUE,
        FOREIGN KEY (domain_id) REFERENCES domains(id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE url_text_content (
        id INTEGER PRIMARY KEY,
        url_id INTEGER UNIQUE,
        text_content TEXT,
        FOREIGN KEY (url_id) REFERENCES urls(id)
    )
    ''')
    
    # Insert test data
    cursor.execute("INSERT INTO domains (domain) VALUES ('example.com')")
    domain_id = cursor.lastrowid
    
    cursor.execute("INSERT INTO urls (domain_id, url) VALUES (?, 'https://example.com/llms.txt')", (domain_id,))
    url_id = cursor.lastrowid
    
    cursor.execute("INSERT INTO url_text_content (url_id, text_content) VALUES (?, 'Test content')", (url_id,))
    
    conn.commit()
    conn.close()
    
    yield db_path
    
    # Clean up
    import os
    os.unlink(db_path)

def test_content_retrieval(test_db):
    """Test that content retriever correctly fetches content from the database."""
    # Initialize components with test database
    db_config = {"path": test_db}
    db = DatabaseConnector(db_config)
    retriever = ContentRetriever(db)
    
    # Retrieve content
    content_items = retriever.retrieve()
    
    # Verify results
    assert len(content_items) == 1
    assert content_items[0]["url"] == "https://example.com/llms.txt"
    assert content_items[0]["content"] == "Test content"
```

### System Tests

System tests focus on testing the entire system end-to-end. They should:

- Test complete workflows
- Use real components (minimal mocking)
- Verify end-to-end functionality

Example system test:

```python
# tests/system_test.py
import pytest
import tempfile
import os
from core.pipeline import Pipeline

class TestSystemEndToEnd:
    """End-to-end system tests for the pipeline."""
    
    @pytest.fixture
    def test_config(self):
        """Create a test configuration."""
        # Create a temporary directory for test outputs
        output_dir = tempfile.mkdtemp()
        
        # Create test configuration
        config = {
            "db": {"path": ":memory:"},  # Use in-memory database
            "pipeline_workers": 2,
            "output_dir": output_dir
        }
        
        yield config
        
        # Clean up
        import shutil
        shutil.rmtree(output_dir)
    
    @pytest.fixture
    def sample_content(self):
        """Create sample content for testing."""
        return [
            {
                "id": "test-1",
                "url": "https://example.com/llms.txt",
                "domain": "example.com",
                "content": "# Test\n\n```python\neval(user_input)\n```\n"
            }
        ]
    
    def test_full_pipeline(self, test_config, sample_content, monkeypatch):
        """Test the full pipeline from content to report."""
        # Mock the content retriever to return sample content
        from core.content.retriever import ContentRetriever
        
        original_retrieve = ContentRetriever.retrieve
        
        def mock_retrieve(self, query=None):
            return sample_content
            
        monkeypatch.setattr(ContentRetriever, "retrieve", mock_retrieve)
        
        # Initialize and run the pipeline
        pipeline = Pipeline(config=test_config)
        report = pipeline.run()
        
        # Verify results
        assert report is not None
        
        # Check performance metrics
        metrics = pipeline.get_performance_metrics()
        assert "total" in metrics
        
        # Restore original method
        monkeypatch.setattr(ContentRetriever, "retrieve", original_retrieve)
```

### Performance Tests

Performance tests measure the system's performance characteristics. They should:

- Measure execution time
- Test with varying input sizes
- Identify bottlenecks

Example performance test:

```python
# tests/performance_benchmark.py
import time
import json
import matplotlib.pyplot as plt
from core.pipeline import Pipeline

def run_performance_benchmark(iterations=3, input_sizes=[1, 10, 50, 100]):
    """
    Run performance benchmarks with different input sizes.
    
    Args:
        iterations (int): Number of iterations for each input size
        input_sizes (list): List of input sizes to test
    
    Returns:
        dict: Performance results
    """
    results = {
        "input_sizes": input_sizes,
        "total_times": [],
        "component_times": {
            "content_retrieval": [],
            "content_processing": [],
            "analysis": [],
            "scoring": [],
            "reporting": []
        }
    }
    
    for size in input_sizes:
        print(f"Benchmarking with input size: {size}")
        
        # Generate test data of specified size
        test_data = generate_test_data(size)
        
        # Initialize pipeline with in-memory database
        config = {"db": {"path": ":memory:"}}
        pipeline = Pipeline(config=config)
        
        # Mock content retriever to return test data
        pipeline.content_retriever.retrieve = lambda query=None: test_data
        
        # Run multiple iterations and average results
        size_total_times = []
        size_component_times = {
            "content_retrieval": [],
            "content_processing": [],
            "analysis": [],
            "scoring": [],
            "reporting": []
        }
        
        for i in range(iterations):
            print(f"  Iteration {i+1}/{iterations}")
            
            # Reset pipeline for clean run
            pipeline.reset()
            
            # Run pipeline
            start_time = time.time()
            pipeline.run()
            total_time = time.time() - start_time
            
            # Record times
            size_total_times.append(total_time)
            
            metrics = pipeline.get_performance_metrics()
            for component in size_component_times.keys():
                if component in metrics:
                    size_component_times[component].append(metrics[component])
        
        # Calculate averages
        results["total_times"].append(sum(size_total_times) / len(size_total_times))
        
        for component in results["component_times"].keys():
            if size_component_times[component]:
                avg = sum(size_component_times[component]) / len(size_component_times[component])
                results["component_times"][component].append(avg)
            else:
                results["component_times"][component].append(0)
    
    # Save results
    with open("performance_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Generate visualizations
    generate_performance_charts(results)
    
    return results

def generate_test_data(size):
    """Generate test data of specified size."""
    test_data = []
    for i in range(size):
        test_data.append({
            "id": f"test-{i}",
            "url": f"https://example.com/llms{i}.txt",
            "domain": "example.com",
            "content": f"# Test {i}\n\n```python\nprint('hello {i}')\n```\n"
        })
    return test_data

def generate_performance_charts(results):
    """Generate performance visualization charts."""
    # Total execution time chart
    plt.figure(figsize=(10, 6))
    plt.plot(results["input_sizes"], results["total_times"], marker='o')
    plt.title("Total Execution Time vs. Input Size")
    plt.xlabel("Input Size (number of items)")
    plt.ylabel("Execution Time (seconds)")
    plt.grid(True)
    plt.savefig("total_execution_time.png")
    
    # Component execution times
    plt.figure(figsize=(12, 8))
    for component, times in results["component_times"].items():
        if any(times):  # Only plot if there are non-zero values
            plt.plot(results["input_sizes"], times, marker='o', label=component)
    plt.title("Component Execution Times vs. Input Size")
    plt.xlabel("Input Size (number of items)")
    plt.ylabel("Execution Time (seconds)")
    plt.legend()
    plt.grid(True)
    plt.savefig("component_execution_times.png")

if __name__ == "__main__":
    run_performance_benchmark()
```

### Accuracy Tests

Accuracy tests evaluate the system's detection accuracy. They should:

- Use known-good and known-bad samples
- Calculate precision, recall, and F1 score
- Compare against ground truth

Example accuracy test:

```python
# tests/accuracy_test.py
import json
import matplotlib.pyplot as plt
from core.pipeline import Pipeline

def run_accuracy_test():
    """
    Run accuracy tests using known samples.
    
    Returns:
        dict: Accuracy metrics
    """
    # Load test data
    test_data = load_test_data()
    
    # Load ground truth
    ground_truth = load_ground_truth()
    
    # Initialize pipeline with in-memory database
    config = {"db": {"path": ":memory:"}}
    pipeline = Pipeline(config=config)
    
    # Process each test file
    results = {}
    
    for file_id, content in test_data.items():
        print(f"Processing {file_id}")
        
        # Mock content retriever to return this file
        pipeline.content_retriever.retrieve = lambda query=None: [{
            "id": file_id,
            "url": f"https://example.com/{file_id}",
            "domain": "example.com",
            "content": content
        }]
        
        # Reset pipeline for clean run
        pipeline.reset()
        
        # Run pipeline
        pipeline.run()
        
        # Get analysis results
        # For simplicity, we're assuming the results are stored in the pipeline
        # In a real implementation, you might need to extract them from the report
        analysis_results = extract_analysis_results(pipeline)
        
        # Store results
        results[file_id] = analysis_results
    
    # Calculate accuracy metrics
    metrics = calculate_accuracy_metrics(results, ground_truth)
    
    # Save results
    with open("accuracy_results.json", "w") as f:
        json.dump(metrics, f, indent=2)
    
    # Generate visualizations
    generate_accuracy_charts(metrics)
    
    return metrics

def load_test_data():
    """Load test data from files."""
    test_files = [
        "sample_clean.llms.txt",
        "sample_malformed.llms.txt",
        "sample_malicious_code.llms.txt",
        "sample_prompt_injection.llms.txt",
        "sample_secrets.llms.txt"
    ]
    
    test_data = {}
    
    for file_name in test_files:
        file_path = f"tests/data/{file_name}"
        with open(file_path, "r") as f:
            test_data[file_name] = f.read()
    
    return test_data

def load_ground_truth():
    """Load ground truth data."""
    # In a real implementation, this would load from a JSON file
    # For this example, we'll define it inline
    return {
        "sample_clean.llms.txt": [],
        "sample_malformed.llms.txt": [
            {"type": "markdown_structure", "severity": "LOW"}
        ],
        "sample_malicious_code.llms.txt": [
            {"type": "code_injection", "severity": "HIGH"},
            {"type": "eval_usage", "severity": "CRITICAL"}
        ],
        "sample_prompt_injection.llms.txt": [
            {"type": "prompt_injection", "severity": "HIGH"}
        ],
        "sample_secrets.llms.txt": [
            {"type": "api_key", "severity": "HIGH"},
            {"type": "password", "severity": "MEDIUM"}
        ]
    }

def extract_analysis_results(pipeline):
    """Extract analysis results from the pipeline."""
    # This is a simplified example
    # In a real implementation, you would extract the actual findings
    findings = []
    
    # Example: extract findings from the last analysis result
    if hasattr(pipeline, "_last_analysis_results") and pipeline._last_analysis_results:
        for analyzer_results in pipeline._last_analysis_results:
            for analyzer, results in analyzer_results.items():
                if "findings" in results:
                    findings.extend(results["findings"])
    
    return findings

def calculate_accuracy_metrics(results, ground_truth):
    """Calculate accuracy metrics."""
    metrics = {
        "overall": {
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0
        },
        "by_file": {},
        "by_finding_type": {}
    }
    
    for file_id, findings in results.items():
        file_metrics = {
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0
        }
        
        # Get ground truth for this file
        file_ground_truth = ground_truth.get(file_id, [])
        
        # Check each finding
        for finding in findings:
            finding_type = finding.get("type")
            
            # Check if this finding matches any ground truth item
            matched = False
            for gt_item in file_ground_truth:
                if gt_item.get("type") == finding_type:
                    matched = True
                    break
            
            if matched:
                file_metrics["true_positives"] += 1
                metrics["overall"]["true_positives"] += 1
                
                # Update by_finding_type metrics
                if finding_type not in metrics["by_finding_type"]:
                    metrics["by_finding_type"][finding_type] = {
                        "true_positives": 0,
                        "false_positives": 0,
                        "false_negatives": 0
                    }
                metrics["by_finding_type"][finding_type]["true_positives"] += 1
            else:
                file_metrics["false_positives"] += 1
                metrics["overall"]["false_positives"] += 1
                
                # Update by_finding_type metrics
                if finding_type not in metrics["by_finding_type"]:
                    metrics["by_finding_type"][finding_type] = {
                        "true_positives": 0,
                        "false_positives": 0,
                        "false_negatives": 0
                    }
                metrics["by_finding_type"][finding_type]["false_positives"] += 1
        
        # Check for false negatives (ground truth items not found)
        for gt_item in file_ground_truth:
            gt_type = gt_item.get("type")
            
            # Check if this ground truth item matches any finding
            matched = False
            for finding in findings:
                if finding.get("type") == gt_type:
                    matched = True
                    break
            
            if not matched:
                file_metrics["false_negatives"] += 1
                metrics["overall"]["false_negatives"] += 1
                
                # Update by_finding_type metrics
                if gt_type not in metrics["by_finding_type"]:
                    metrics["by_finding_type"][gt_type] = {
                        "true_positives": 0,
                        "false_positives": 0,
                        "false_negatives": 0
                    }
                metrics["by_finding_type"][gt_type]["false_negatives"] += 1
        
        # Calculate precision, recall, F1 for this file
        if file_metrics["true_positives"] + file_metrics["false_positives"] > 0:
            file_metrics["precision"] = file_metrics["true_positives"] / (file_metrics["true_positives"] + file_metrics["false_positives"])
        else:
            file_metrics["precision"] = 0
            
        if file_metrics["true_positives"] + file_metrics["false_negatives"] > 0:
            file_metrics["recall"] = file_metrics["true_positives"] / (file_metrics["true_positives"] + file_metrics["false_negatives"])
        else:
            file_metrics["recall"] = 0
            
        if file_metrics["precision"] + file_metrics["recall"] > 0:
            file_metrics["f1"] = 2 * (file_metrics["precision"] * file_metrics["recall"]) / (file_metrics["precision"] + file_metrics["recall"])
        else:
            file_metrics["f1"] = 0
        
        metrics["by_file"][file_id] = file_metrics
    
    # Calculate overall precision, recall, F1
    if metrics["overall"]["true_positives"] + metrics["overall"]["false_positives"] > 0:
        metrics["overall"]["precision"] = metrics["overall"]["true_positives"] / (metrics["overall"]["true_positives"] + metrics["overall"]["false_positives"])
    else:
        metrics["overall"]["precision"] = 0
        
    if metrics["overall"]["true_positives"] + metrics["overall"]["false_negatives"] > 0:
        metrics["overall"]["recall"] = metrics["overall"]["true_positives"] / (metrics["overall"]["true_positives"] + metrics["overall"]["false_negatives"])
    else:
        metrics["overall"]["recall"] = 0
        
    if metrics["overall"]["precision"] + metrics["overall"]["recall"] > 0:
        metrics["overall"]["f1"] = 2 * (metrics["overall"]["precision"] * metrics["overall"]["recall"]) / (metrics["overall"]["precision"] + metrics["overall"]["recall"])
    else:
        metrics["overall"]["f1"] = 0
    
    # Calculate by_finding_type precision, recall, F1
    for finding_type, type_metrics in metrics["by_finding_type"].items():
        if type_metrics["true_positives"] + type_metrics["false_positives"] > 0:
            type_metrics["precision"] = type_metrics["true_positives"] / (type_metrics["true_positives"] + type_metrics["false_positives"])
        else:
            type_metrics["precision"] = 0
            
        if type_metrics["true_positives"] + type_metrics["false_negatives"] > 0:
            type_metrics["recall"] = type_metrics["true_positives"] / (type_metrics["true_positives"] + type_metrics["false_negatives"])
        else:
            type_metrics["recall"] = 0
            
        if type_metrics["precision"] + type_metrics["recall"] > 0:
            type_metrics["f1"] = 2 * (type_metrics["precision"] * type_metrics["recall"]) / (type_metrics["precision"] + type_metrics["recall"])
        else:
            type_metrics["f1"] = 0
    
    return metrics

def generate_accuracy_charts(metrics):
    """Generate accuracy visualization charts."""
    # Overall metrics chart
    plt.figure(figsize=(8, 6))
    metrics_values = [metrics["overall"]["precision"], metrics["overall"]["recall"], metrics["overall"]["f1"]]
    plt.bar(["Precision", "Recall", "F1 Score"], metrics_values)
    plt.title("Overall Accuracy Metrics")
    plt.ylim(0, 1)
    plt.grid(axis='y')
    plt.savefig("overall_accuracy.png")
    
    # By finding type chart
    if metrics["by_finding_type"]:
        plt.figure(figsize=(12, 8))
        finding_types = list(metrics["by_finding_type"].keys())
        precision_values = [metrics["by_finding_type"][t]["precision"] for t in finding_types]
        recall_values = [metrics["by_finding_type"][t]["recall"] for t in finding_types]
        f1_values = [metrics["by_finding_type"][t]["f1"] for t in finding_types]
        
        x = range(len(finding_types))
        width = 0.25
        
        plt.bar([i - width for i in x], precision_values, width, label='Precision')
        plt.bar(x, recall_values, width, label='Recall')
        plt.bar([i + width for i in x], f1_values, width, label='F1 Score')
        
        plt.xlabel('Finding Type')
        plt.ylabel('Score')
        plt.title('Accuracy Metrics by Finding Type')
        plt.xticks(x, finding_types, rotation=45)
        plt.ylim(0, 1)
        plt.legend()
        plt.tight_layout()
        plt.savefig("accuracy_by_finding_type.png")

if __name__ == "__main__":
    run_accuracy_test()
```

## Test Coverage

The project aims for high test coverage to ensure code quality and reliability.

### Measuring Coverage

To measure test coverage:

```bash
pytest --cov=core tests/
```

To generate a coverage report:

```bash
pytest --cov=core --cov-report=html tests/
```

This will generate an HTML coverage report in the `htmlcov/` directory.

### Coverage Targets

The project has the following coverage targets:

- Overall: >80%
- Core components: >90%
- Utility functions: >70%

## Continuous Integration

The project uses continuous integration to run tests automatically on code changes.

### CI Configuration

The CI pipeline runs:

1. Linting and style checks
2. Unit tests
3. Integration tests
4. System tests
5. Coverage reporting

### CI Best Practices

- Keep CI builds fast
- Fix failing tests immediately
- Don't commit code that breaks tests
- Review test results regularly

## Mocking

The project uses mocking to isolate components during testing.

### Mocking Database

```python
# Mock database connector
@pytest.fixture
def mock_db():
    """Create a mock database connector."""
    mock_db = MagicMock()
    mock_db.execute_query.return_value = [
        {"id": 1, "url": "https://example.com/llms.txt", "content": "Test content"}
    ]
    return mock_db
```

### Mocking External Tools

```python
# Mock Semgrep runner
@pytest.fixture
def mock_semgrep():
    """Create a mock Semgrep runner."""
    mock_runner = MagicMock()
    mock_runner.run.return_value = {
        "results": [
            {
                "check_id": "test-rule",
                "severity": "ERROR",
                "message": "Test finding"
            }
        ]
    }
    return mock_runner
```

## Test Data

The project includes sample test data in the `tests/data/` directory:

- `sample_clean.llms.txt`: A clean file with no security issues
- `sample_malformed.llms.txt`: A malformed file with structural issues
- `sample_malicious_code.llms.txt`: Contains malicious code patterns
- `sample_prompt_injection.llms.txt`: Contains prompt injection vulnerabilities
- `sample_secrets.llms.txt`: Contains API keys and credentials

### Creating Test Data

When creating new test data:

1. Include a variety of cases (positive and negative)
2. Document the expected findings
3. Keep files small and focused
4. Include edge cases

## Test Results

Test results are saved in the specified output directory (default: `test_results/`). The results include:

- JSON files with detailed test results
- Text reports with summary information
- Visualizations of performance and accuracy metrics (saved as PNG files)

### Interpreting Results

- **Unit test results**: Check for passing/failing tests
- **Integration test results**: Verify component interactions
- **System test results**: Ensure end-to-end functionality
- **Performance results**: Look for performance regressions
- **Accuracy results**: Evaluate detection effectiveness

## Debugging Tests

### Common Issues

- **Database errors**: Check database configuration and connections
- **Path issues**: Ensure file paths are correct
- **Configuration issues**: Verify test configuration
- **Timing issues**: Add delays or use appropriate synchronization

### Debugging Techniques

- Use `pytest -v` for verbose output
- Use `pytest --pdb` to drop into debugger on failure
- Add print statements for debugging
- Check logs for error messages

## Best Practices

1. **Write tests first**: Follow test-driven development
2. **Keep tests simple**: Each test should verify one thing
3. **Use descriptive names**: Test names should describe what they test
4. **Isolate tests**: Tests should not depend on each other
5. **Use fixtures**: Reuse setup code with fixtures
6. **Test edge cases**: Include boundary conditions and error cases
7. **Keep tests fast**: Optimize for quick feedback
8. **Maintain tests**: Update tests when code changes

## Conclusion

Testing is a critical part of the LLMs.txt Security Analysis Platform development process. By following the guidelines in this document, you can ensure that the platform is reliable, performant, and accurate in detecting security issues in LLMs.txt files.

## References

- [Pytest Documentation](https://docs.pytest.org/)
- [Test-Driven Development](https://en.wikipedia.org/wiki/Test-driven_development)
- [Code Coverage](https://en.wikipedia.org/wiki/Code_coverage)
- [System Testing](https://en.wikipedia.org/wiki/System_testing)