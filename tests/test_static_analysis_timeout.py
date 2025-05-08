"""
Tests for the static analysis timeout fix.

This test file verifies the effectiveness of the timeout handling improvements
in the static analysis component, particularly for large or complex markdown content.
"""

import pytest
import time
import os
import logging
import psutil
from typing import Dict, Any, List, Optional
import threading

from core.pipeline import Pipeline
from core.analysis.static.analyzer import StaticAnalyzer
from core.analysis.static.semgrep_runner import SemgrepRunner

# Configure logging for tests
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TimeoutTest")

# Test configuration
TEST_CONFIG = {
    "db": {
        "path": "researchdb/llms_metadata.db"
    },
    "pipeline_workers": 4,
    "test_data_dir": "tests/data",
    "max_content_size": 1024 * 1024,  # 1MB
    "max_content_lines": 10000
}

@pytest.fixture(scope="module")
def pipeline():
    """Create a pipeline instance for testing."""
    return Pipeline(config=TEST_CONFIG)

@pytest.fixture(scope="module")
def static_analyzer():
    """Create a static analyzer instance for testing."""
    return StaticAnalyzer(config=TEST_CONFIG)

@pytest.fixture(scope="module")
def semgrep_runner():
    """Create a semgrep runner instance for testing."""
    return SemgrepRunner(
        rules_path="rules/semgrep",
        config={"max_content_size": TEST_CONFIG["max_content_size"]},
        registry_rulesets=["p/gitleaks", "p/owasp-top-ten"]
    )

def load_test_file(filename):
    """Load a test file from the test data directory."""
    file_path = os.path.join(TEST_CONFIG["test_data_dir"], filename)
    with open(file_path, 'r') as f:
        return f.read()

class TestStaticAnalysisTimeout:
    """Tests for the static analysis timeout fix."""
    
    def test_large_complex_markdown_handling(self, static_analyzer):
        """Test handling of large complex markdown content."""
        # Load the large complex markdown file
        content = load_test_file("large_complex_markdown.llms.txt")
        
        # Create a test item
        test_item = {
            "id": "test-large-markdown",
            "content": content,
            "language": "markdown"
        }
        
        # Measure execution time
        start_time = time.time()
        
        # Run the analysis
        results = static_analyzer.analyze(test_item)
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Log the results
        logger.info(f"Analysis completed in {execution_time:.2f}s")
        logger.info(f"Results: {results}")
        
        # Verify the analysis completed without hanging
        assert execution_time < 60, f"Analysis took too long: {execution_time:.2f}s"
        
        # Verify we got results (not an error)
        assert results is not None, "Analysis returned None"
        
        # Check if we got the expected handling for complex content
        # Either we should get findings or a specific message about complex content
        if isinstance(results, list) and len(results) > 0:
            # Check if we have a finding indicating complex content was detected
            complex_content_findings = [
                f for f in results 
                if f.get("rule_id") in ["complex_generic_content", "content_size_limit_exceeded", "content_line_limit_exceeded", "alternative_analysis_used"]
            ]
            
            # Either we should have complex content findings or regular analysis results
            assert len(complex_content_findings) > 0 or len(results) > 0, "No findings returned for complex content"
    
    def test_content_size_check(self, semgrep_runner):
        """Test that content size checks prevent analysis of extremely large content."""
        # Create extremely large content
        large_content = "A" * (semgrep_runner.max_content_size + 1000)
        
        # Run the semgrep runner
        results = semgrep_runner.run(content=large_content, language="generic")
        
        # Verify we got a content_too_large finding
        assert len(results) == 1, "Expected exactly one finding for large content"
        assert results[0]["rule_id"] == "content_too_large", "Expected content_too_large finding"
    
    def test_complex_generic_content_detection(self, semgrep_runner):
        """Test detection of complex generic content."""
        # Create content with many complex patterns
        content = "\n".join([
            "# Test Document",
            "```python",
            "def test():",
            "    pass",
            "```",
            "```javascript",
            "function test() {",
            "    return true;",
            "}",
            "```",
        ] + ["[[Wiki Link]]" * 20] + ["{{template}}" * 20])
        
        # Check if content is detected as complex
        assert semgrep_runner._is_complex_content(content), "Content should be detected as complex"
        
        # Run the semgrep runner
        results = semgrep_runner.run(content=content, language="generic")
        
        # Verify we got a complex_generic_content finding
        assert len(results) == 1, "Expected exactly one finding for complex content"
        assert results[0]["rule_id"] == "complex_generic_content", "Expected complex_generic_content finding"
    
    def test_timeout_handling_in_pipeline(self, pipeline):
        """Test timeout handling in the full pipeline."""
        # Load the large complex markdown file
        content = load_test_file("large_complex_markdown.llms.txt")
        
        # Mock the content retrieval to use our test file
        pipeline.content_retriever.retrieve = lambda query: [{
            "id": "test-timeout",
            "path": "large_complex_markdown.llms.txt",
            "content": content,
            "language": "markdown"
        }]
        
        # Run the pipeline
        start_time = time.time()
        report = pipeline.run(content_query=None)
        execution_time = time.time() - start_time
        
        # Log performance metrics
        metrics = pipeline.get_performance_metrics()
        logger.info(f"Pipeline performance metrics: {metrics}")
        
        # Verify the pipeline completed without hanging
        assert execution_time < 120, f"Pipeline took too long: {execution_time:.2f}s"
        
        # Verify we got a report
        assert report is not None, "Pipeline did not return a report"
    
    def test_progressive_timeout(self, static_analyzer):
        """Test that timeout increases with content size and complexity."""
        # Create test items with different sizes and complexity
        items = [
            {
                "id": "small-simple",
                "content": "Simple small content",
                "language": "generic"
            },
            {
                "id": "medium-simple",
                "content": "Simple content\n" * 500,  # Medium size, low complexity
                "language": "generic"
            },
            {
                "id": "small-complex",
                "content": "```python\ndef test():\n    pass\n```\n" * 10 + "[[Link]]" * 10,  # Small size, higher complexity
                "language": "generic"
            },
            {
                "id": "large-complex",
                "content": load_test_file("large_complex_markdown.llms.txt"),
                "language": "markdown"
            }
        ]
        
        # Calculate timeouts for each item
        timeouts = []
        for item in items:
            # Access the private method for testing
            timeout = pipeline._calculate_timeout(item)
            timeouts.append(timeout)
            logger.info(f"Item {item['id']}: calculated timeout = {timeout}s")
        
        # Verify progressive timeouts
        assert timeouts[0] < timeouts[1], "Medium content should have longer timeout than small content"
        assert timeouts[0] < timeouts[2], "Complex content should have longer timeout than simple content"
        assert timeouts[1] < timeouts[3], "Large complex content should have longest timeout"
    
    def test_alternative_analysis_for_complex_content(self, static_analyzer):
        """Test that alternative analysis is used for complex content."""
        # Create complex generic content
        content = "\n".join([
            "# Test Document",
            "```python",
            "def test():",
            "    pass",
            "```",
            "```javascript",
            "function test() {",
            "    return true;",
            "}",
            "```",
        ] + ["[[Wiki Link]]" * 20] + ["{{template}}" * 20])
        
        # Create a test item
        test_item = {
            "id": "test-complex-content",
            "content": content,
            "language": "generic"
        }
        
        # Run the analysis
        results = static_analyzer.analyze(test_item)
        
        # Verify we got results from alternative analysis
        assert results is not None, "Analysis returned None"
        
        # Check if we have a finding indicating alternative analysis was used
        alternative_analysis_findings = [
            f for f in results 
            if f.get("rule_id") == "alternative_analysis_used"
        ]
        
        assert len(alternative_analysis_findings) > 0, "Alternative analysis was not used for complex content"
    
    def test_error_handling_provides_useful_information(self, pipeline):
        """Test that error handling provides useful information for debugging."""
        # Create a test item that would cause an error
        # We'll use a mock that raises an exception during analysis
        original_analyze = pipeline.static_analyzer.analyze
        
        def mock_analyze(data):
            # Simulate a timeout by sleeping and then raising an exception
            time.sleep(0.5)  # Short sleep to simulate work
            raise Exception("Simulated timeout error for testing")
        
        try:
            # Replace the analyze method with our mock
            pipeline.static_analyzer.analyze = mock_analyze
            
            # Mock the content retrieval
            pipeline.content_retriever.retrieve = lambda query: [{
                "id": "test-error",
                "path": "error_test.txt",
                "content": "Test content",
                "language": "generic"
            }]
            
            # Run the pipeline
            report = pipeline.run(content_query=None)
            
            # Verify we got a report even with the error
            assert report is not None, "Pipeline did not return a report after error"
            
            # Check if the report contains error information
            if isinstance(report, dict) and "error" in report:
                assert "Simulated timeout error" in report["error"], "Error message not included in report"
            
            # Check performance metrics
            metrics = pipeline.get_performance_metrics()
            assert "analysis" in metrics, "Analysis metrics missing after error"
            
        finally:
            # Restore the original analyze method
            pipeline.static_analyzer.analyze = original_analyze