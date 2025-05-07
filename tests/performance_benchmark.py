"""
Performance Benchmarking for LLMs.txt Security Analysis Platform

This module provides tools for benchmarking the performance of the security analysis pipeline
and its individual components. It can be used to identify bottlenecks and track performance
improvements over time.
"""

import time
import os
import json
import logging
import statistics
from typing import Dict, Any, List, Optional
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

from core.pipeline import Pipeline
from core.content.processor import ContentProcessor
from core.analysis.markdown.analyzer import MarkdownAnalyzer
from core.analysis.patterns.analyzer import PatternAnalyzer
from core.analysis.secrets.analyzer import SecretsAnalyzer
from core.analysis.static.analyzer import StaticAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PerformanceBenchmark")

class PerformanceBenchmark:
    """Performance benchmarking for the security analysis pipeline."""
    
    def __init__(self, config=None):
        """Initialize the benchmark with configuration."""
        self.config = config or {
            "db": {
                "path": "researchdb/llms_metadata.db"
            },
            "pipeline_workers": 4,
            "test_data_dir": "tests/data"
        }
        self.pipeline = Pipeline(config=self.config)
        self.results_dir = "benchmark_results"
        os.makedirs(self.results_dir, exist_ok=True)
    
    def benchmark_pipeline(self, iterations=3):
        """Benchmark the full pipeline execution."""
        logger.info(f"Benchmarking full pipeline with {iterations} iterations...")
        
        # Get list of test files
        test_files = [f for f in os.listdir(self.config["test_data_dir"]) if f.endswith(".llms.txt")]
        
        results = {}
        for test_file in test_files:
            file_path = os.path.join(self.config["test_data_dir"], test_file)
            
            # Mock the content retrieval to use our test file
            self.pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
            
            # Run multiple iterations
            file_times = []
            component_times = []
            
            for i in range(iterations):
                logger.info(f"Running iteration {i+1}/{iterations} for {test_file}...")
                
                # Reset pipeline state
                self.pipeline.reset()
                
                # Run the pipeline and measure time
                start = time.time()
                self.pipeline.run(content_query=None)
                elapsed = time.time() - start
                
                file_times.append(elapsed)
                component_times.append(self.pipeline.get_performance_metrics())
            
            # Calculate statistics
            avg_time = statistics.mean(file_times)
            min_time = min(file_times)
            max_time = max(file_times)
            std_dev = statistics.stdev(file_times) if len(file_times) > 1 else 0
            
            # Calculate component averages
            avg_components = {}
            for component in component_times[0].keys():
                avg_components[component] = statistics.mean([run[component] for run in component_times if component in run])
            
            results[test_file] = {
                "avg_time": avg_time,
                "min_time": min_time,
                "max_time": max_time,
                "std_dev": std_dev,
                "component_times": avg_components
            }
            
            logger.info(f"Results for {test_file}: avg={avg_time:.4f}s, min={min_time:.4f}s, max={max_time:.4f}s, std_dev={std_dev:.4f}s")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(self.results_dir, f"pipeline_benchmark_{timestamp}.json")
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Benchmark results saved to {result_file}")
        
        # Generate visualization
        self._visualize_results(results, os.path.join(self.results_dir, f"pipeline_benchmark_{timestamp}.png"))
        
        return results
    
    def benchmark_components(self, iterations=3):
        """Benchmark individual components with various input sizes."""
        logger.info(f"Benchmarking individual components with {iterations} iterations...")
        
        # Get list of test files
        test_files = [f for f in os.listdir(self.config["test_data_dir"]) if f.endswith(".llms.txt")]
        
        # Initialize components
        content_processor = ContentProcessor()
        markdown_analyzer = MarkdownAnalyzer()
        pattern_analyzer = PatternAnalyzer()
        secrets_analyzer = SecretsAnalyzer()
        static_analyzer = StaticAnalyzer()
        
        results = {}
        for test_file in test_files:
            file_path = os.path.join(self.config["test_data_dir"], test_file)
            with open(file_path, 'r') as f:
                content = f.read()
            
            file_size = len(content)
            file_results = {
                "file_size": file_size,
                "components": {}
            }
            
            # Process content once
            processed_content = content_processor.process({"path": file_path, "content": content})
            
            # Benchmark each component
            components = {
                "content_processor": (content_processor.process, {"path": file_path, "content": content}),
                "markdown_analyzer": (markdown_analyzer.analyze, processed_content),
                "pattern_analyzer": (pattern_analyzer.analyze, processed_content),
                "secrets_analyzer": (secrets_analyzer.analyze, processed_content),
                "static_analyzer": (static_analyzer.analyze, processed_content)
            }
            
            for component_name, (func, arg) in components.items():
                component_times = []
                
                for i in range(iterations):
                    start = time.time()
                    func(arg)
                    elapsed = time.time() - start
                    component_times.append(elapsed)
                
                avg_time = statistics.mean(component_times)
                min_time = min(component_times)
                max_time = max(component_times)
                std_dev = statistics.stdev(component_times) if len(component_times) > 1 else 0
                
                file_results["components"][component_name] = {
                    "avg_time": avg_time,
                    "min_time": min_time,
                    "max_time": max_time,
                    "std_dev": std_dev
                }
                
                logger.info(f"{component_name} on {test_file}: avg={avg_time:.4f}s")
            
            results[test_file] = file_results
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(self.results_dir, f"component_benchmark_{timestamp}.json")
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Component benchmark results saved to {result_file}")
        
        # Generate visualization
        self._visualize_component_results(results, os.path.join(self.results_dir, f"component_benchmark_{timestamp}.png"))
        
        return results
    
    def benchmark_scaling(self, max_multiplier=10, step=2):
        """Benchmark how performance scales with input size."""
        logger.info(f"Benchmarking scaling performance up to {max_multiplier}x input size...")
        
        # Use a single test file as the base
        test_file = "sample_malicious_code.llms.txt"  # This has a mix of issues
        file_path = os.path.join(self.config["test_data_dir"], test_file)
        with open(file_path, 'r') as f:
            base_content = f.read()
        
        base_size = len(base_content)
        
        # Test with increasing content sizes
        results = {}
        multipliers = list(range(1, max_multiplier + 1, step))
        
        for multiplier in multipliers:
            content = base_content * multiplier
            content_size = len(content)
            
            # Mock the content retrieval
            self.pipeline.content_retriever.retrieve = lambda query: [{"path": "scaled.txt", "content": content}]
            
            # Reset pipeline
            self.pipeline.reset()
            
            # Run the pipeline and measure time
            start = time.time()
            self.pipeline.run(content_query=None)
            elapsed = time.time() - start
            
            component_times = self.pipeline.get_performance_metrics()
            
            results[f"{multiplier}x"] = {
                "content_size": content_size,
                "total_time": elapsed,
                "component_times": component_times
            }
            
            logger.info(f"Size {multiplier}x ({content_size} bytes): {elapsed:.4f}s")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(self.results_dir, f"scaling_benchmark_{timestamp}.json")
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Scaling benchmark results saved to {result_file}")
        
        # Generate visualization
        self._visualize_scaling_results(results, os.path.join(self.results_dir, f"scaling_benchmark_{timestamp}.png"))
        
        return results
    
    def _visualize_results(self, results, output_path):
        """Generate visualization of pipeline benchmark results."""
        plt.figure(figsize=(12, 8))
        
        # Plot total execution time by file
        plt.subplot(2, 1, 1)
        files = list(results.keys())
        avg_times = [results[f]["avg_time"] for f in files]
        std_devs = [results[f]["std_dev"] for f in files]
        
        x = np.arange(len(files))
        plt.bar(x, avg_times, yerr=std_devs, capsize=5)
        plt.xticks(x, files, rotation=45, ha="right")
        plt.ylabel("Time (seconds)")
        plt.title("Total Pipeline Execution Time by File")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Plot component breakdown for each file
        plt.subplot(2, 1, 2)
        components = ["content_retrieval", "content_processing", "analysis", "scoring", "reporting"]
        
        bar_width = 0.15
        x = np.arange(len(files))
        
        for i, component in enumerate(components):
            component_times = []
            for file in files:
                component_times.append(results[file]["component_times"].get(component, 0))
            
            plt.bar(x + i*bar_width - bar_width*2, component_times, width=bar_width, label=component)
        
        plt.xticks(x, files, rotation=45, ha="right")
        plt.ylabel("Time (seconds)")
        plt.title("Pipeline Component Execution Times by File")
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        plt.savefig(output_path)
        logger.info(f"Visualization saved to {output_path}")
    
    def _visualize_component_results(self, results, output_path):
        """Generate visualization of component benchmark results."""
        plt.figure(figsize=(12, 8))
        
        # Plot component execution times by file
        files = list(results.keys())
        components = ["content_processor", "markdown_analyzer", "pattern_analyzer", "secrets_analyzer", "static_analyzer"]
        
        bar_width = 0.15
        x = np.arange(len(files))
        
        for i, component in enumerate(components):
            component_times = []
            for file in files:
                component_times.append(results[file]["components"].get(component, {}).get("avg_time", 0))
            
            plt.bar(x + i*bar_width - bar_width*2, component_times, width=bar_width, label=component)
        
        plt.xticks(x, files, rotation=45, ha="right")
        plt.ylabel("Time (seconds)")
        plt.title("Component Execution Times by File")
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        plt.savefig(output_path)
        logger.info(f"Component visualization saved to {output_path}")
    
    def _visualize_scaling_results(self, results, output_path):
        """Generate visualization of scaling benchmark results."""
        plt.figure(figsize=(12, 8))
        
        # Plot total time vs content size
        plt.subplot(2, 1, 1)
        multipliers = list(results.keys())
        sizes = [results[m]["content_size"] for m in multipliers]
        times = [results[m]["total_time"] for m in multipliers]
        
        plt.plot(sizes, times, 'o-', linewidth=2)
        plt.xlabel("Content Size (bytes)")
        plt.ylabel("Time (seconds)")
        plt.title("Pipeline Execution Time vs Content Size")
        plt.grid(linestyle='--', alpha=0.7)
        
        # Plot component times vs content size
        plt.subplot(2, 1, 2)
        components = ["content_retrieval", "content_processing", "analysis", "scoring", "reporting"]
        
        for component in components:
            component_times = []
            for m in multipliers:
                component_times.append(results[m]["component_times"].get(component, 0))
            
            plt.plot(sizes, component_times, 'o-', linewidth=2, label=component)
        
        plt.xlabel("Content Size (bytes)")
        plt.ylabel("Time (seconds)")
        plt.title("Component Execution Times vs Content Size")
        plt.legend()
        plt.grid(linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        plt.savefig(output_path)
        logger.info(f"Scaling visualization saved to {output_path}")

def main():
    """Run benchmarks when script is executed directly."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Performance Benchmarking for LLMs.txt Security Analysis Platform")
    parser.add_argument("--benchmark", choices=["pipeline", "components", "scaling", "all"], default="all",
                        help="Benchmark type to run")
    parser.add_argument("--iterations", type=int, default=3,
                        help="Number of iterations for each benchmark")
    parser.add_argument("--max-multiplier", type=int, default=10,
                        help="Maximum size multiplier for scaling benchmark")
    
    args = parser.parse_args()
    
    benchmark = PerformanceBenchmark()
    
    if args.benchmark == "pipeline" or args.benchmark == "all":
        benchmark.benchmark_pipeline(iterations=args.iterations)
    
    if args.benchmark == "components" or args.benchmark == "all":
        benchmark.benchmark_components(iterations=args.iterations)
    
    if args.benchmark == "scaling" or args.benchmark == "all":
        benchmark.benchmark_scaling(max_multiplier=args.max_multiplier)

if __name__ == "__main__":
    main()