"""
System Validation Tests for LLMs.txt Security Analysis Platform

This module provides tests to validate the overall system behavior under various conditions,
including handling of malformed inputs, edge cases, and problematic content.
"""

import os
import json
import logging
import time
import random
import string
import tempfile
from typing import Dict, Any, List, Optional
import concurrent.futures

from core.pipeline import Pipeline
from core.content.processor import ContentProcessor

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SystemValidation")

class SystemValidation:
    """System validation tests for the security analysis pipeline."""
    
    def __init__(self, config=None):
        """Initialize the system validation with configuration."""
        self.config = config or {
            "db": {
                "path": "researchdb/llms_metadata.db"
            },
            "pipeline_workers": 4,
            "test_data_dir": "tests/data"
        }
        self.pipeline = Pipeline(config=self.config)
        self.results_dir = "validation_results"
        os.makedirs(self.results_dir, exist_ok=True)
    
    def run_all_validations(self):
        """Run all system validation tests."""
        logger.info("Running all system validation tests...")
        
        results = {}
        
        # Run each validation test
        results["empty_input"] = self.validate_empty_input()
        results["malformed_input"] = self.validate_malformed_input()
        results["large_input"] = self.validate_large_input()
        results["special_characters"] = self.validate_special_characters()
        results["concurrent_execution"] = self.validate_concurrent_execution()
        results["error_recovery"] = self.validate_error_recovery()
        
        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(self.results_dir, f"system_validation_{timestamp}.json")
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"System validation results saved to {result_file}")
        
        # Print summary
        logger.info("System Validation Summary:")
        for test_name, test_result in results.items():
            status = "PASSED" if test_result.get("passed", False) else "FAILED"
            logger.info(f"  {test_name}: {status}")
        
        return results
    
    def validate_empty_input(self):
        """Validate system handling of empty input."""
        logger.info("Validating empty input handling...")
        
        # Reset pipeline
        self.pipeline.reset()
        
        # Mock the content retrieval to return empty content
        self.pipeline.content_retriever.retrieve = lambda query: [{"path": "empty.txt", "content": ""}]
        
        # Run the pipeline
        start_time = time.time()
        try:
            report = self.pipeline.run(content_query=None)
            elapsed = time.time() - start_time
            
            # Check if pipeline handled empty input gracefully
            if report is None:
                logger.info("Pipeline returned None for empty input (expected behavior).")
                passed = True
                error = None
            elif isinstance(report, dict) and report.get("status") == "failed":
                logger.info(f"Pipeline returned failure status for empty input: {report.get('error')}")
                # This might be acceptable depending on how the pipeline is designed to handle empty input
                passed = True
                error = report.get("error")
            else:
                logger.info("Pipeline processed empty input and returned a report.")
                passed = True
                error = None
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Pipeline crashed with empty input: {e}")
            passed = False
            error = str(e)
        
        result = {
            "passed": passed,
            "elapsed_time": elapsed,
            "error": error
        }
        
        return result
    
    def validate_malformed_input(self):
        """Validate system handling of malformed input."""
        logger.info("Validating malformed input handling...")
        
        # Test with the malformed sample
        test_file = "sample_malformed.llms.txt"
        file_path = os.path.join(self.config["test_data_dir"], test_file)
        
        # Reset pipeline
        self.pipeline.reset()
        
        # Mock the content retrieval to use our malformed file
        self.pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
        
        # Run the pipeline
        start_time = time.time()
        try:
            report = self.pipeline.run(content_query=None)
            elapsed = time.time() - start_time
            
            # Check if pipeline handled malformed input gracefully
            if report is None:
                logger.warning("Pipeline returned None for malformed input.")
                passed = False
                error = "Pipeline returned None for malformed input"
            elif isinstance(report, dict) and report.get("status") == "failed":
                logger.warning(f"Pipeline returned failure status for malformed input: {report.get('error')}")
                passed = False
                error = report.get("error")
            else:
                logger.info("Pipeline processed malformed input and returned a report.")
                passed = True
                error = None
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Pipeline crashed with malformed input: {e}")
            passed = False
            error = str(e)
        
        result = {
            "passed": passed,
            "elapsed_time": elapsed,
            "error": error
        }
        
        return result
    
    def validate_large_input(self):
        """Validate system handling of large input."""
        logger.info("Validating large input handling...")
        
        # Create a large input by repeating content
        test_file = "sample_malicious_code.llms.txt"
        file_path = os.path.join(self.config["test_data_dir"], test_file)
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Repeat content to make it larger (adjust multiplier as needed)
        large_content = content * 20
        
        # Reset pipeline
        self.pipeline.reset()
        
        # Mock the content retrieval to use our large content
        self.pipeline.content_retriever.retrieve = lambda query: [{"path": "large.txt", "content": large_content}]
        
        # Run the pipeline with timeout
        start_time = time.time()
        try:
            report = self.pipeline.run(content_query=None)
            elapsed = time.time() - start_time
            
            # Check if pipeline handled large input within reasonable time
            if elapsed > 120:  # 2 minutes is too long
                logger.warning(f"Pipeline took too long with large input: {elapsed:.2f}s")
                passed = False
                error = f"Pipeline took too long: {elapsed:.2f}s"
            elif report is None:
                logger.warning("Pipeline returned None for large input.")
                passed = False
                error = "Pipeline returned None for large input"
            elif isinstance(report, dict) and report.get("status") == "failed":
                logger.warning(f"Pipeline returned failure status for large input: {report.get('error')}")
                passed = False
                error = report.get("error")
            else:
                logger.info(f"Pipeline processed large input in {elapsed:.2f}s and returned a report.")
                passed = True
                error = None
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Pipeline crashed with large input: {e}")
            passed = False
            error = str(e)
        
        result = {
            "passed": passed,
            "elapsed_time": elapsed,
            "error": error,
            "content_size": len(large_content)
        }
        
        return result
    
    def validate_special_characters(self):
        """Validate system handling of special characters and unusual content."""
        logger.info("Validating special characters handling...")
        
        # Create content with special characters and unusual patterns
        special_content = """
# LLMs.txt with Special Characters

## System Instructions

You are a helpful assistant that provides information about programming languages.

## User Queries

When users ask about programming languages, provide factual information about their history, features, and common use cases.

## Special Characters Test

• Unicode characters: 你好，世界! Привет, мир! مرحبا بالعالم! こんにちは世界!
• Emojis: 😀 🚀 🔥 💻 🤖 🧠
• Control characters: \x00\x01\x02\x03\x04\x05
• HTML entities: &lt;script&gt;alert("XSS");&lt;/script&gt;
• SQL injection: '; DROP TABLE users; --
• Zero-width spaces: here​is​a​test​with​zero​width​spaces
• Very long line without breaks: """ + "x" * 1000 + """
• Nested quotes: "He said 'Look at this "nested" quote' and walked away"
• Backslashes and escapes: C:\\Program Files\\App\\bin\\"quoted"\\path
"""
        
        # Reset pipeline
        self.pipeline.reset()
        
        # Mock the content retrieval to use our special content
        self.pipeline.content_retriever.retrieve = lambda query: [{"path": "special.txt", "content": special_content}]
        
        # Run the pipeline
        start_time = time.time()
        try:
            report = self.pipeline.run(content_query=None)
            elapsed = time.time() - start_time
            
            # Check if pipeline handled special characters gracefully
            if report is None:
                logger.warning("Pipeline returned None for special characters input.")
                passed = False
                error = "Pipeline returned None for special characters input"
            elif isinstance(report, dict) and report.get("status") == "failed":
                logger.warning(f"Pipeline returned failure status for special characters: {report.get('error')}")
                passed = False
                error = report.get("error")
            else:
                logger.info("Pipeline processed special characters and returned a report.")
                passed = True
                error = None
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Pipeline crashed with special characters: {e}")
            passed = False
            error = str(e)
        
        result = {
            "passed": passed,
            "elapsed_time": elapsed,
            "error": error
        }
        
        return result
    
    def validate_concurrent_execution(self):
        """Validate system handling of concurrent pipeline executions."""
        logger.info("Validating concurrent execution handling...")
        
        # Get list of test files
        test_files = [f for f in os.listdir(self.config["test_data_dir"]) if f.endswith(".llms.txt")]
        
        # Create multiple pipeline instances
        num_pipelines = min(3, len(test_files))  # Use up to 3 concurrent pipelines
        pipelines = [Pipeline(config=self.config) for _ in range(num_pipelines)]
        
        # Prepare content for each pipeline
        contents = []
        for i in range(num_pipelines):
            file_path = os.path.join(self.config["test_data_dir"], test_files[i])
            with open(file_path, 'r') as f:
                contents.append({"path": file_path, "content": f.read()})
        
        # Run pipelines concurrently
        results = [None] * num_pipelines
        errors = [None] * num_pipelines
        elapsed_times = [0] * num_pipelines
        
        def run_pipeline(idx):
            # Mock content retrieval for this pipeline
            pipelines[idx].content_retriever.retrieve = lambda query: [contents[idx]]
            
            start_time = time.time()
            try:
                results[idx] = pipelines[idx].run(content_query=None)
                elapsed_times[idx] = time.time() - start_time
            except Exception as e:
                elapsed_times[idx] = time.time() - start_time
                errors[idx] = str(e)
        
        # Use ThreadPoolExecutor to run pipelines concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_pipelines) as executor:
            futures = [executor.submit(run_pipeline, i) for i in range(num_pipelines)]
            concurrent.futures.wait(futures)
        
        # Check results
        all_passed = True
        for i in range(num_pipelines):
            if errors[i] is not None:
                logger.error(f"Pipeline {i} failed: {errors[i]}")
                all_passed = False
            elif results[i] is None:
                logger.warning(f"Pipeline {i} returned None")
                all_passed = False
            elif isinstance(results[i], dict) and results[i].get("status") == "failed":
                logger.warning(f"Pipeline {i} returned failure status: {results[i].get('error')}")
                all_passed = False
        
        if all_passed:
            logger.info("All concurrent pipelines completed successfully.")
        
        result = {
            "passed": all_passed,
            "num_pipelines": num_pipelines,
            "elapsed_times": elapsed_times,
            "errors": errors
        }
        
        return result
    
    def validate_error_recovery(self):
        """Validate system error recovery capabilities."""
        logger.info("Validating error recovery capabilities...")
        
        # Create a processor that will raise an exception during processing
        class ErrorProcessor(ContentProcessor):
            def process(self, content_item):
                # Process normally for a while, then fail
                if random.random() < 0.5:
                    raise RuntimeError("Simulated processing error")
                return super().process(content_item)
        
        # Reset pipeline
        self.pipeline.reset()
        
        # Replace the content processor with our error-generating one
        self.pipeline.content_processor = ErrorProcessor()
        
        # Use multiple test files
        test_files = [f for f in os.listdir(self.config["test_data_dir"]) if f.endswith(".llms.txt")]
        content_items = []
        for test_file in test_files:
            file_path = os.path.join(self.config["test_data_dir"], test_file)
            with open(file_path, 'r') as f:
                content_items.append({"path": file_path, "content": f.read()})
        
        # Mock the content retrieval to return multiple items
        self.pipeline.content_retriever.retrieve = lambda query: content_items
        
        # Run the pipeline
        start_time = time.time()
        try:
            report = self.pipeline.run(content_query=None)
            elapsed = time.time() - start_time
            
            # Check if pipeline handled errors gracefully
            if report is None:
                logger.warning("Pipeline returned None when encountering errors.")
                passed = False
                error = "Pipeline returned None when encountering errors"
            elif isinstance(report, dict) and report.get("status") == "failed":
                # This is expected - the pipeline should return a failure status
                logger.info(f"Pipeline correctly returned failure status: {report.get('error')}")
                # Check if performance metrics are still available
                if "performance" in report and report["performance"]:
                    logger.info("Pipeline provided performance metrics despite failure.")
                    passed = True
                    error = report.get("error")
                else:
                    logger.warning("Pipeline failed but did not provide performance metrics.")
                    passed = False
                    error = "No performance metrics in failure report"
            else:
                # The pipeline might have recovered from errors
                logger.info("Pipeline recovered from errors and returned a report.")
                passed = True
                error = None
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Pipeline crashed completely when encountering errors: {e}")
            passed = False
            error = str(e)
        
        result = {
            "passed": passed,
            "elapsed_time": elapsed,
            "error": error
        }
        
        return result
    
    def generate_random_content(self, size_kb=100):
        """Generate random content of specified size for testing."""
        chars = string.ascii_letters + string.digits + string.punctuation + ' \n\t'
        content_size = size_kb * 1024  # Convert KB to bytes
        
        # Generate random content with some structure
        content = "# Random LLMs.txt File for Testing\n\n"
        content += "## System Instructions\n\n"
        
        # Fill with random paragraphs to reach desired size
        while len(content) < content_size:
            paragraph_length = random.randint(50, 200)
            paragraph = ''.join(random.choice(chars) for _ in range(paragraph_length))
            content += paragraph + "\n\n"
        
        return content

def main():
    """Run system validation tests when script is executed directly."""
    import argparse
    
    parser = argparse.ArgumentParser(description="System Validation Tests for LLMs.txt Security Analysis Platform")
    parser.add_argument("--test", choices=["empty", "malformed", "large", "special", "concurrent", "error", "all"],
                        default="all", help="Specific test to run")
    parser.add_argument("--output-dir", type=str, default="validation_results",
                        help="Directory to save results")
    
    args = parser.parse_args()
    
    validation = SystemValidation()
    validation.results_dir = args.output_dir
    
    if args.test == "all":
        validation.run_all_validations()
    elif args.test == "empty":
        result = validation.validate_empty_input()
        print(f"Empty input test {'PASSED' if result['passed'] else 'FAILED'}")
    elif args.test == "malformed":
        result = validation.validate_malformed_input()
        print(f"Malformed input test {'PASSED' if result['passed'] else 'FAILED'}")
    elif args.test == "large":
        result = validation.validate_large_input()
        print(f"Large input test {'PASSED' if result['passed'] else 'FAILED'}")
    elif args.test == "special":
        result = validation.validate_special_characters()
        print(f"Special characters test {'PASSED' if result['passed'] else 'FAILED'}")
    elif args.test == "concurrent":
        result = validation.validate_concurrent_execution()
        print(f"Concurrent execution test {'PASSED' if result['passed'] else 'FAILED'}")
    elif args.test == "error":
        result = validation.validate_error_recovery()
        print(f"Error recovery test {'PASSED' if result['passed'] else 'FAILED'}")

if __name__ == "__main__":
    main()