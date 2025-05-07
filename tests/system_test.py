"""
System Integration and Performance Tests for LLMs.txt Security Analysis Platform
"""

import pytest
import time
import os
import json
import logging
from typing import Dict, Any, List, Optional

from core.pipeline import Pipeline
from core.content.retriever import ContentRetriever
from core.content.processor import ContentProcessor
from core.analysis.markdown.analyzer import MarkdownAnalyzer
from core.analysis.patterns.analyzer import PatternAnalyzer
from core.analysis.secrets.analyzer import SecretsAnalyzer
from core.analysis.static.analyzer import StaticAnalyzer
from core.scoring.scoring_model import ScoringModel
from core.scoring.risk_assessor import RiskAssessor
from core.reporting.reporting_manager import ReportingManager

# Configure logging for tests
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SystemTest")

# Test configuration
TEST_CONFIG = {
    "db": {
        "path": "researchdb/llms_metadata.db"
    },
    "pipeline_workers": 4,
    "test_data_dir": "tests/data"
}

# Expected findings for accuracy testing
EXPECTED_FINDINGS = {
    "sample_clean.llms.txt": {
        "total_findings": 0,
        "severity_high": 0,
        "severity_medium": 0,
        "severity_low": 0
    },
    "sample_prompt_injection.llms.txt": {
        "total_findings": 3,  # At least 3 prompt injection issues
        "severity_high": 1,   # At least 1 high severity
        "patterns": ["prompt_injection", "instruction_override"]
    },
    "sample_secrets.llms.txt": {
        "total_findings": 6,  # At least 6 secrets
        "severity_high": 3,   # At least 3 high severity
        "patterns": ["api_key", "password", "private_key"]
    },
    "sample_malicious_code.llms.txt": {
        "total_findings": 4,  # At least 4 code issues
        "severity_high": 2,   # At least 2 high severity
        "patterns": ["eval", "document.write", "os.popen", "fetch"]
    },
    "sample_malformed.llms.txt": {
        "total_findings": 2,  # At least 2 structural issues
        "severity_medium": 1, # At least 1 medium severity
        "patterns": ["malformed", "structure"]
    }
}

@pytest.fixture(scope="module")
def pipeline():
    """Create a pipeline instance for testing."""
    return Pipeline(config=TEST_CONFIG)

@pytest.fixture(scope="module")
def test_files():
    """Get list of test files."""
    test_dir = TEST_CONFIG["test_data_dir"]
    return [f for f in os.listdir(test_dir) if f.endswith(".llms.txt")]

def count_findings_by_severity(findings: List[Dict[str, Any]], severity: str) -> int:
    """Helper function to count findings by severity."""
    return sum(1 for f in findings if f.get("severity") == severity)

def has_pattern_in_findings(findings: List[Dict[str, Any]], pattern: str) -> bool:
    """Helper function to check if a pattern exists in findings."""
    for finding in findings:
        if pattern.lower() in finding.get("description", "").lower() or \
           pattern.lower() in finding.get("type", "").lower() or \
           pattern.lower() in finding.get("details", {}).get("pattern", "").lower():
            return True
    return False

def get_findings_from_report(report: Any) -> List[Dict[str, Any]]:
    """Extract findings from a report object."""
    if hasattr(report, "findings"):
        return report.findings
    elif isinstance(report, dict) and "findings" in report:
        return report["findings"]
    return []

class TestEndToEndPipeline:
    """End-to-end pipeline tests."""
    
    def test_pipeline_end_to_end(self, pipeline):
        """System validation: Pipeline runs end-to-end and produces a report."""
        report = pipeline.run(content_query=None)
        assert report is not None, "Pipeline did not return a report"
    
    def test_pipeline_with_test_files(self, pipeline, test_files):
        """Test pipeline with each test file individually."""
        for test_file in test_files:
            logger.info(f"Testing pipeline with file: {test_file}")
            file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
            
            # Mock the content retrieval to use our test file
            pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
            
            # Run the pipeline
            report = pipeline.run(content_query=None)
            
            # Verify report was generated
            assert report is not None, f"Pipeline did not return a report for {test_file}"
            
            # Log performance metrics
            metrics = pipeline.get_performance_metrics()
            logger.info(f"Performance metrics for {test_file}: {metrics}")

class TestPerformanceBenchmarking:
    """Performance benchmarking tests."""
    
    def test_pipeline_performance(self, pipeline):
        """Performance benchmarking: Pipeline completes within reasonable time."""
        start = time.time()
        pipeline.run(content_query=None)
        elapsed = time.time() - start
        # Set a reasonable upper bound for test data (adjust as needed)
        assert elapsed < 30, f"Pipeline took too long: {elapsed:.2f}s"
    
    def test_component_performance(self, pipeline, test_files):
        """Benchmark performance of individual pipeline components."""
        # Select a test file
        test_file = "sample_malicious_code.llms.txt"  # This file has multiple types of issues
        file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
        content = open(file_path).read()
        
        # Benchmark content processing
        start = time.time()
        processed_content = pipeline.content_processor.process({"path": file_path, "content": content})
        content_processing_time = time.time() - start
        logger.info(f"Content processing time: {content_processing_time:.4f}s")
        
        # Benchmark markdown analysis
        start = time.time()
        markdown_results = pipeline.markdown_analyzer.analyze(processed_content)
        markdown_time = time.time() - start
        logger.info(f"Markdown analysis time: {markdown_time:.4f}s")
        
        # Benchmark pattern analysis
        start = time.time()
        pattern_results = pipeline.pattern_analyzer.analyze(processed_content)
        pattern_time = time.time() - start
        logger.info(f"Pattern analysis time: {pattern_time:.4f}s")
        
        # Benchmark secrets analysis
        start = time.time()
        secrets_results = pipeline.secrets_analyzer.analyze(processed_content)
        secrets_time = time.time() - start
        logger.info(f"Secrets analysis time: {secrets_time:.4f}s")
        
        # Benchmark static analysis
        start = time.time()
        static_results = pipeline.static_analyzer.analyze(processed_content)
        static_time = time.time() - start
        logger.info(f"Static analysis time: {static_time:.4f}s")
        
        # Verify all components completed in reasonable time
        assert content_processing_time < 5, f"Content processing took too long: {content_processing_time:.2f}s"
        assert markdown_time < 5, f"Markdown analysis took too long: {markdown_time:.2f}s"
        assert pattern_time < 5, f"Pattern analysis took too long: {pattern_time:.2f}s"
        assert secrets_time < 5, f"Secrets analysis took too long: {secrets_time:.2f}s"
        assert static_time < 5, f"Static analysis took too long: {static_time:.2f}s"
    
    def test_pipeline_performance_metrics(self, pipeline):
        """Performance metrics: Pipeline exposes detailed timing information."""
        pipeline.run(content_query=None)
        metrics = pipeline.get_performance_metrics()
        
        # Verify metrics structure
        assert "total" in metrics and metrics["total"] > 0, "Total performance metric missing or invalid"
        assert "content_retrieval" in metrics, "Content retrieval metric missing"
        assert "content_processing" in metrics, "Content processing metric missing"
        assert "analysis" in metrics, "Analysis metric missing"
        assert "scoring" in metrics, "Scoring metric missing"
        assert "reporting" in metrics, "Reporting metric missing"
        
        # Verify metrics make sense (each component time should be less than total time)
        for component, time_value in metrics.items():
            if component != "total":
                assert time_value < metrics["total"], f"Component {component} time ({time_value}) exceeds total time"

class TestAccuracyFramework:
    """Accuracy testing framework."""
    
    def test_accuracy_with_known_samples(self, pipeline):
        """Test accuracy against samples with known issues."""
        for test_file, expected in EXPECTED_FINDINGS.items():
            logger.info(f"Testing accuracy with file: {test_file}")
            file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
            
            # Mock the content retrieval to use our test file
            pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
            
            # Run the pipeline
            report = pipeline.run(content_query=None)
            
            # Extract findings from report
            findings = get_findings_from_report(report)
            
            # Verify total findings count
            if "total_findings" in expected:
                assert len(findings) >= expected["total_findings"], \
                    f"Expected at least {expected['total_findings']} findings in {test_file}, got {len(findings)}"
            
            # Verify findings by severity
            for severity in ["high", "medium", "low"]:
                key = f"severity_{severity}"
                if key in expected:
                    count = count_findings_by_severity(findings, severity)
                    assert count >= expected[key], \
                        f"Expected at least {expected[key]} {severity} severity findings in {test_file}, got {count}"
            
            # Verify specific patterns are detected
            if "patterns" in expected:
                for pattern in expected["patterns"]:
                    assert has_pattern_in_findings(findings, pattern), \
                        f"Expected to find pattern '{pattern}' in {test_file} findings"
    
    def test_false_positives(self, pipeline):
        """Test for false positives in clean samples."""
        # Use the clean sample
        test_file = "sample_clean.llms.txt"
        file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
        
        # Mock the content retrieval to use our test file
        pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
        
        # Run the pipeline
        report = pipeline.run(content_query=None)
        
        # Extract findings from report
        findings = get_findings_from_report(report)
        
        # Verify no high severity findings in clean file (false positives)
        high_severity_count = count_findings_by_severity(findings, "high")
        assert high_severity_count == 0, \
            f"Found {high_severity_count} high severity findings in clean file (false positives)"

class TestSystemValidation:
    """System validation tests."""
    
    def test_malformed_input_handling(self, pipeline):
        """Test system handling of malformed inputs."""
        test_file = "sample_malformed.llms.txt"
        file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
        
        # Mock the content retrieval to use our test file
        pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
        
        # Run the pipeline - it should not crash with malformed input
        try:
            report = pipeline.run(content_query=None)
            assert report is not None, "Pipeline did not return a report for malformed input"
        except Exception as e:
            pytest.fail(f"Pipeline crashed with malformed input: {e}")
    
    def test_empty_input_handling(self, pipeline):
        """Test system handling of empty input."""
        # Mock the content retrieval to return empty content
        pipeline.content_retriever.retrieve = lambda query: [{"path": "empty.txt", "content": ""}]
        
        # Run the pipeline - it should handle empty input gracefully
        try:
            report = pipeline.run(content_query=None)
            # Pipeline might return None or an empty report for empty input
            # The important thing is that it doesn't crash
        except Exception as e:
            pytest.fail(f"Pipeline crashed with empty input: {e}")
    
    def test_large_input_handling(self, pipeline):
        """Test system handling of large input."""
        # Create a large input by repeating a sample file
        test_file = "sample_malicious_code.llms.txt"
        file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Repeat content to make it larger (adjust multiplier as needed)
        large_content = content * 10
        
        # Mock the content retrieval to use our large content
        pipeline.content_retriever.retrieve = lambda query: [{"path": "large.txt", "content": large_content}]
        
        # Run the pipeline with timeout
        start = time.time()
        try:
            report = pipeline.run(content_query=None)
            elapsed = time.time() - start
            assert report is not None, "Pipeline did not return a report for large input"
            assert elapsed < 60, f"Pipeline took too long with large input: {elapsed:.2f}s"
        except Exception as e:
            pytest.fail(f"Pipeline crashed with large input: {e}")
    
    def test_concurrent_runs(self):
        """Test system handling of concurrent pipeline runs."""
        # Create multiple pipeline instances
        pipelines = [Pipeline(config=TEST_CONFIG) for _ in range(3)]
        
        # Run pipelines concurrently
        import threading
        threads = []
        results = [None] * len(pipelines)
        
        def run_pipeline(idx):
            try:
                results[idx] = pipelines[idx].run(content_query=None)
            except Exception as e:
                logger.error(f"Pipeline {idx} failed: {e}")
        
        for i in range(len(pipelines)):
            thread = threading.Thread(target=run_pipeline, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all pipelines completed successfully
        for i, result in enumerate(results):
            assert result is not None, f"Pipeline {i} did not return a result"

def test_pipeline_end_to_end(pipeline):
    """System validation: Pipeline runs end-to-end and produces a report."""
    report = pipeline.run(content_query=None)
    assert report is not None, "Pipeline did not return a report"

def test_pipeline_performance(pipeline):
    """Performance benchmarking: Pipeline completes within reasonable time."""
    start = time.time()
    pipeline.run(content_query=None)
    elapsed = time.time() - start
    # Set a reasonable upper bound for test data (adjust as needed)
    assert elapsed < 30, f"Pipeline took too long: {elapsed:.2f}s"

def test_pipeline_accuracy(pipeline):
    """Accuracy testing: Check that pipeline detects known issues in test data."""
    # Use a file with known issues
    test_file = "sample_malicious_code.llms.txt"
    file_path = os.path.join(TEST_CONFIG["test_data_dir"], test_file)
    
    # Mock the content retrieval to use our test file
    pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
    
    # Run the pipeline
    report = pipeline.run(content_query=None)
    
    # Extract findings from report
    findings = get_findings_from_report(report)
    
    # Verify findings exist
    assert len(findings) > 0, "No findings detected in file with known issues"
    
    # Verify at least one high severity finding
    high_severity_count = count_findings_by_severity(findings, "high")
    assert high_severity_count > 0, "No high severity findings detected in file with known issues"

def test_pipeline_performance_metrics(pipeline):
    """Performance metrics: Pipeline exposes detailed timing information."""
    pipeline.run(content_query=None)
    metrics = pipeline.get_performance_metrics()
    assert "total" in metrics and metrics["total"] > 0, "Performance metrics missing or invalid"