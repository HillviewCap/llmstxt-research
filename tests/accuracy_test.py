"""
Accuracy Testing Framework for LLMs.txt Security Analysis Platform

This module provides tools for measuring the accuracy of the security analysis pipeline
by comparing its findings against known vulnerabilities in test data. It calculates
metrics such as true positives, false positives, and false negatives.
"""

import os
import json
import logging
import csv
from typing import Dict, Any, List, Optional, Set, Tuple
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

from core.pipeline import Pipeline

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AccuracyTest")

class AccuracyTest:
    """Accuracy testing framework for the security analysis pipeline."""
    
    def __init__(self, config=None):
        """Initialize the accuracy test with configuration."""
        self.config = config or {
            "db": {
                "path": "researchdb/llms_metadata.db"
            },
            "pipeline_workers": 4,
            "test_data_dir": "tests/data"
        }
        self.pipeline = Pipeline(config=self.config)
        self.results_dir = "accuracy_results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Ground truth data for test files
        self.ground_truth = {
            "sample_clean.llms.txt": [],  # No vulnerabilities
            
            "sample_prompt_injection.llms.txt": [
                {"id": "PI-1", "type": "prompt_injection", "severity": "high", "line": 16, "pattern": "IGNORE ALL PREVIOUS INSTRUCTIONS"},
                {"id": "PI-2", "type": "prompt_injection", "severity": "medium", "line": 20, "pattern": "Secret Instructions"},
                {"id": "PI-3", "type": "prompt_injection", "severity": "high", "line": 24, "pattern": "system override alpha-123"}
            ],
            
            "sample_secrets.llms.txt": [
                {"id": "SEC-1", "type": "api_key", "severity": "high", "line": 9, "pattern": "AWS_ACCESS_KEY_ID"},
                {"id": "SEC-2", "type": "api_key", "severity": "high", "line": 10, "pattern": "AWS_SECRET_ACCESS_KEY"},
                {"id": "SEC-3", "type": "api_key", "severity": "high", "line": 11, "pattern": "OPENAI_API_KEY"},
                {"id": "SEC-4", "type": "api_key", "severity": "high", "line": 12, "pattern": "GITHUB_TOKEN"},
                {"id": "SEC-5", "type": "credential", "severity": "medium", "line": 13, "pattern": "DATABASE_URL"},
                {"id": "SEC-6", "type": "private_key", "severity": "high", "line": 14, "pattern": "PRIVATE_KEY"}
            ],
            
            "sample_malicious_code.llms.txt": [
                {"id": "CODE-1", "type": "malicious_code", "severity": "high", "line": 15, "pattern": "document.cookie"},
                {"id": "CODE-2", "type": "malicious_code", "severity": "high", "line": 23, "pattern": "document.write"},
                {"id": "CODE-3", "type": "malicious_code", "severity": "high", "line": 23, "pattern": "eval"},
                {"id": "CODE-4", "type": "malicious_code", "severity": "high", "line": 37, "pattern": "os.popen"},
                {"id": "CODE-5", "type": "malicious_code", "severity": "high", "line": 42, "pattern": "eval"}
            ],
            
            "sample_malformed.llms.txt": [
                {"id": "STRUCT-1", "type": "malformed", "severity": "medium", "line": 4, "pattern": "incomplete section"},
                {"id": "STRUCT-2", "type": "malformed", "severity": "medium", "line": 12, "pattern": "unclosed code block"}
            ]
        }
    
    def run_accuracy_test(self):
        """Run accuracy tests on all test files."""
        logger.info("Running accuracy tests...")
        
        results = {}
        overall_metrics = {
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0
        }
        
        # Process each test file
        for test_file, expected_findings in self.ground_truth.items():
            logger.info(f"Testing accuracy for {test_file}...")
            file_path = os.path.join(self.config["test_data_dir"], test_file)
            
            # Mock the content retrieval to use our test file
            self.pipeline.content_retriever.retrieve = lambda query: [{"path": file_path, "content": open(file_path).read()}]
            
            # Reset pipeline
            self.pipeline.reset()
            
            # Run the pipeline
            report = self.pipeline.run(content_query=None)
            
            # Extract findings from report
            actual_findings = self._get_findings_from_report(report)
            
            # Calculate metrics
            tp, fp, fn, matches = self._calculate_metrics(actual_findings, expected_findings)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            file_results = {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "expected_count": len(expected_findings),
                "actual_count": len(actual_findings),
                "matches": matches
            }
            
            results[test_file] = file_results
            
            # Update overall metrics
            overall_metrics["true_positives"] += tp
            overall_metrics["false_positives"] += fp
            overall_metrics["false_negatives"] += fn
            
            logger.info(f"Results for {test_file}:")
            logger.info(f"  True Positives: {tp}")
            logger.info(f"  False Positives: {fp}")
            logger.info(f"  False Negatives: {fn}")
            logger.info(f"  Precision: {precision:.4f}")
            logger.info(f"  Recall: {recall:.4f}")
            logger.info(f"  F1 Score: {f1:.4f}")
        
        # Calculate overall precision, recall, and F1
        total_tp = overall_metrics["true_positives"]
        total_fp = overall_metrics["false_positives"]
        total_fn = overall_metrics["false_negatives"]
        
        overall_metrics["precision"] = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        overall_metrics["recall"] = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        overall_metrics["f1_score"] = 2 * overall_metrics["precision"] * overall_metrics["recall"] / (overall_metrics["precision"] + overall_metrics["recall"]) if (overall_metrics["precision"] + overall_metrics["recall"]) > 0 else 0
        
        results["overall"] = overall_metrics
        
        logger.info("Overall Metrics:")
        logger.info(f"  True Positives: {total_tp}")
        logger.info(f"  False Positives: {total_fp}")
        logger.info(f"  False Negatives: {total_fn}")
        logger.info(f"  Precision: {overall_metrics['precision']:.4f}")
        logger.info(f"  Recall: {overall_metrics['recall']:.4f}")
        logger.info(f"  F1 Score: {overall_metrics['f1_score']:.4f}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(self.results_dir, f"accuracy_test_{timestamp}.json")
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate CSV report
        csv_file = os.path.join(self.results_dir, f"accuracy_test_{timestamp}.csv")
        self._generate_csv_report(results, csv_file)
        
        # Generate visualization
        self._visualize_results(results, os.path.join(self.results_dir, f"accuracy_test_{timestamp}.png"))
        
        logger.info(f"Accuracy test results saved to {result_file}")
        
        return results
    
    def _get_findings_from_report(self, report) -> List[Dict[str, Any]]:
        """Extract findings from a report object."""
        if hasattr(report, "findings"):
            return report.findings
        elif isinstance(report, dict) and "findings" in report:
            return report["findings"]
        elif isinstance(report, dict) and "status" in report and report["status"] == "failed":
            logger.error(f"Pipeline failed: {report.get('error')}")
            return []
        return []
    
    def _calculate_metrics(self, actual_findings: List[Dict[str, Any]], expected_findings: List[Dict[str, Any]]) -> Tuple[int, int, int, List[Dict[str, Any]]]:
        """
        Calculate true positives, false positives, and false negatives.
        
        Returns:
            Tuple of (true_positives, false_positives, false_negatives, matches)
        """
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        matches = []
        
        # Track which expected findings have been matched
        matched_expected = set()
        
        # Check each actual finding against expected findings
        for actual in actual_findings:
            matched = False
            
            for i, expected in enumerate(expected_findings):
                if i in matched_expected:
                    continue  # Skip already matched findings
                
                # Check if this is a match
                if self._is_finding_match(actual, expected):
                    true_positives += 1
                    matched_expected.add(i)
                    matched = True
                    matches.append({
                        "expected": expected,
                        "actual": actual,
                        "match_type": "true_positive"
                    })
                    break
            
            if not matched:
                false_positives += 1
                matches.append({
                    "expected": None,
                    "actual": actual,
                    "match_type": "false_positive"
                })
        
        # Count unmatched expected findings as false negatives
        for i, expected in enumerate(expected_findings):
            if i not in matched_expected:
                false_negatives += 1
                matches.append({
                    "expected": expected,
                    "actual": None,
                    "match_type": "false_negative"
                })
        
        return true_positives, false_positives, false_negatives, matches
    
    def _is_finding_match(self, actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
        """
        Determine if an actual finding matches an expected finding.
        
        This is a flexible matching algorithm that considers various fields
        and allows for some differences in how findings are reported.
        """
        # Check type match (if available in both)
        if "type" in actual and "type" in expected:
            actual_type = actual["type"].lower() if isinstance(actual["type"], str) else ""
            expected_type = expected["type"].lower()
            
            # If types don't match at all, check if expected type is in actual description
            if expected_type not in actual_type:
                actual_desc = actual.get("description", "").lower()
                if expected_type not in actual_desc:
                    return False
        
        # Check pattern match
        if "pattern" in expected:
            expected_pattern = expected["pattern"].lower()
            
            # Check various fields for the pattern
            pattern_found = False
            for field in ["description", "details", "code", "content"]:
                if field in actual:
                    field_value = actual[field]
                    if isinstance(field_value, str) and expected_pattern.lower() in field_value.lower():
                        pattern_found = True
                        break
                    elif isinstance(field_value, dict):
                        # Check nested dictionary values
                        for _, value in field_value.items():
                            if isinstance(value, str) and expected_pattern.lower() in value.lower():
                                pattern_found = True
                                break
            
            if not pattern_found:
                return False
        
        # Check severity match (if available in both)
        if "severity" in actual and "severity" in expected:
            # Allow some flexibility in severity matching
            # e.g., "high" in expected might match "critical" in actual
            high_severities = ["high", "critical", "severe"]
            medium_severities = ["medium", "moderate", "warning"]
            low_severities = ["low", "info", "informational"]
            
            actual_severity = actual["severity"].lower() if isinstance(actual["severity"], str) else ""
            expected_severity = expected["severity"].lower()
            
            if expected_severity in high_severities:
                if actual_severity not in high_severities:
                    return False
            elif expected_severity in medium_severities:
                if actual_severity not in medium_severities:
                    return False
            elif expected_severity in low_severities:
                if actual_severity not in low_severities:
                    return False
        
        # If we got here, it's a match
        return True
    
    def _generate_csv_report(self, results: Dict[str, Any], output_path: str):
        """Generate a CSV report of accuracy test results."""
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(["File", "Expected", "Actual", "TP", "FP", "FN", "Precision", "Recall", "F1"])
            
            # Write data for each file
            for file_name, file_results in results.items():
                if file_name == "overall":
                    continue
                
                writer.writerow([
                    file_name,
                    file_results["expected_count"],
                    file_results["actual_count"],
                    file_results["true_positives"],
                    file_results["false_positives"],
                    file_results["false_negatives"],
                    f"{file_results['precision']:.4f}",
                    f"{file_results['recall']:.4f}",
                    f"{file_results['f1_score']:.4f}"
                ])
            
            # Write overall results
            overall = results["overall"]
            writer.writerow([
                "OVERALL",
                "",
                "",
                overall["true_positives"],
                overall["false_positives"],
                overall["false_negatives"],
                f"{overall['precision']:.4f}",
                f"{overall['recall']:.4f}",
                f"{overall['f1_score']:.4f}"
            ])
        
        logger.info(f"CSV report saved to {output_path}")
    
    def _visualize_results(self, results: Dict[str, Any], output_path: str):
        """Generate visualization of accuracy test results."""
        plt.figure(figsize=(12, 10))
        
        # Plot metrics by file
        plt.subplot(2, 1, 1)
        files = [f for f in results.keys() if f != "overall"]
        metrics = ["precision", "recall", "f1_score"]
        
        x = np.arange(len(files))
        bar_width = 0.25
        
        for i, metric in enumerate(metrics):
            values = [results[f][metric] for f in files]
            plt.bar(x + i*bar_width - bar_width, values, width=bar_width, label=metric.capitalize())
        
        plt.xticks(x, files, rotation=45, ha="right")
        plt.ylabel("Score")
        plt.ylim(0, 1.1)
        plt.title("Accuracy Metrics by File")
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Plot TP, FP, FN by file
        plt.subplot(2, 1, 2)
        metrics = ["true_positives", "false_positives", "false_negatives"]
        labels = ["True Positives", "False Positives", "False Negatives"]
        
        for i, (metric, label) in enumerate(zip(metrics, labels)):
            values = [results[f][metric] for f in files]
            plt.bar(x + i*bar_width - bar_width, values, width=bar_width, label=label)
        
        plt.xticks(x, files, rotation=45, ha="right")
        plt.ylabel("Count")
        plt.title("Finding Counts by File")
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        plt.savefig(output_path)
        logger.info(f"Visualization saved to {output_path}")

def main():
    """Run accuracy tests when script is executed directly."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Accuracy Testing for LLMs.txt Security Analysis Platform")
    parser.add_argument("--output-dir", type=str, default="accuracy_results",
                        help="Directory to save results")
    
    args = parser.parse_args()
    
    accuracy_test = AccuracyTest()
    accuracy_test.results_dir = args.output_dir
    accuracy_test.run_accuracy_test()

if __name__ == "__main__":
    main()