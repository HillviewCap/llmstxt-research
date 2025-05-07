"""
Accuracy Validator for Advanced Testing Framework

This module provides tools for validating the accuracy of the LLMs.txt Security
Analysis Platform against known test cases and expected results.
"""

import os
import json
import logging
import hashlib
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Optional, Union, Tuple, Set
from datetime import datetime
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, classification_report

from core.pipeline import Pipeline

logger = logging.getLogger(__name__)

class AccuracyValidator:
    """
    Validates the accuracy of the security analysis platform.
    
    This class provides methods to validate the accuracy of the platform
    against known test cases with expected results, calculating metrics
    such as precision, recall, F1 score, and confusion matrices.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the accuracy validator with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for accuracy validation.
                   Supported keys:
                   - test_data_dir: Directory containing test data
                   - output_dir: Directory to save validation results
                   - pipeline_config: Configuration for the pipeline
                   - ground_truth_file: Path to ground truth file
        """
        self.config = config or {}
        self.test_data_dir = self.config.get("test_data_dir", "tests/advanced/generated")
        self.output_dir = self.config.get("output_dir", "tests/advanced/results")
        self.pipeline_config = self.config.get("pipeline_config", {})
        self.ground_truth_file = self.config.get("ground_truth_file", None)
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize pipeline
        self.pipeline = Pipeline(config=self.pipeline_config)
        
        # Load ground truth if provided
        self.ground_truth = {}
        if self.ground_truth_file and os.path.exists(self.ground_truth_file):
            self._load_ground_truth()
        
        logger.info("Initialized accuracy validator")
    
    def _load_ground_truth(self):
        """Load ground truth data from file."""
        try:
            with open(self.ground_truth_file, 'r') as f:
                self.ground_truth = json.load(f)
            
            logger.info(f"Loaded ground truth data for {len(self.ground_truth)} test cases")
        except Exception as e:
            logger.error(f"Error loading ground truth data: {e}")
    
    def validate(self, test_suite_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate the accuracy of the platform against a test suite.
        
        Args:
            test_suite_path: Path to test suite file (if None, use latest)
            
        Returns:
            Dictionary with validation results
        """
        # Find test suite file if not provided
        if not test_suite_path:
            test_suite_path = self._find_latest_test_suite()
            if not test_suite_path:
                raise ValueError("No test suite found and none provided")
        
        logger.info(f"Validating accuracy against test suite: {test_suite_path}")
        
        # Load test suite
        with open(test_suite_path, 'r') as f:
            test_suite = json.load(f)
        
        # Get test cases directory
        test_suite_dir = os.path.dirname(test_suite_path)
        test_cases_dir = os.path.join(test_suite_dir, 
                                     os.path.basename(test_suite_path).replace("test_suite_", "test_cases_"))
        
        if not os.path.exists(test_cases_dir):
            raise ValueError(f"Test cases directory not found: {test_cases_dir}")
        
        # Initialize results
        results = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "test_suite": test_suite_path,
                "test_cases_count": len(test_suite["test_cases"])
            },
            "overall_metrics": {},
            "scenario_metrics": {},
            "test_case_results": []
        }
        
        # Process each test case
        all_expected_labels = []
        all_predicted_labels = []
        
        for test_case_meta in test_suite["test_cases"]:
            test_case_id = test_case_meta["id"]
            
            # Load test case content
            test_case_path = os.path.join(test_cases_dir, f"{test_case_id}.llms.txt")
            if not os.path.exists(test_case_path):
                logger.warning(f"Test case file not found: {test_case_path}")
                continue
            
            # Load test case metadata
            meta_path = os.path.join(test_cases_dir, f"{test_case_id}.meta.json")
            if not os.path.exists(meta_path):
                logger.warning(f"Test case metadata file not found: {meta_path}")
                continue
            
            with open(meta_path, 'r') as f:
                test_case_metadata = json.load(f)
            
            # Get expected findings from ground truth or metadata
            expected_findings = self._get_expected_findings(test_case_id, test_case_metadata)
            
            # Run the pipeline on this test case
            with open(test_case_path, 'r') as f:
                content = f.read()
            
            # Mock the content retriever to use our test case
            self.pipeline.content_retriever.retrieve = lambda query: [{"path": test_case_path, "content": content}]
            
            # Reset pipeline
            self.pipeline.reset()
            
            # Run the pipeline
            report = self.pipeline.run(content_query=None)
            
            # Extract findings from report
            actual_findings = self._extract_findings_from_report(report)
            
            # Calculate metrics for this test case
            tp, fp, fn, matches = self._calculate_metrics(actual_findings, expected_findings)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # Determine if test passed based on F1 score threshold
            passed = f1 >= 0.7  # 70% F1 score threshold
            
            # Record test case result
            test_case_result = {
                "id": test_case_id,
                "scenario_type": test_case_metadata["scenario_type"],
                "metrics": {
                    "true_positives": tp,
                    "false_positives": fp,
                    "false_negatives": fn,
                    "precision": precision,
                    "recall": recall,
                    "f1_score": f1
                },
                "passed": passed,
                "expected_findings_count": len(expected_findings),
                "actual_findings_count": len(actual_findings),
                "matches": matches
            }
            
            results["test_case_results"].append(test_case_result)
            
            # Update labels for confusion matrix
            for _ in range(len(expected_findings)):
                all_expected_labels.append(1)  # 1 = should find
            for _ in range(fn):
                all_predicted_labels.append(0)  # 0 = not found
            for _ in range(tp):
                all_predicted_labels.append(1)  # 1 = found
            
            for _ in range(fp):
                all_expected_labels.append(0)  # 0 = should not find
                all_predicted_labels.append(1)  # 1 = found
            
            logger.info(f"Processed test case {test_case_id}: F1={f1:.4f}, Passed={passed}")
        
        # Calculate overall metrics
        overall_tp = sum(tc["metrics"]["true_positives"] for tc in results["test_case_results"])
        overall_fp = sum(tc["metrics"]["false_positives"] for tc in results["test_case_results"])
        overall_fn = sum(tc["metrics"]["false_negatives"] for tc in results["test_case_results"])
        
        overall_precision = overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else 0
        overall_recall = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else 0
        overall_f1 = 2 * overall_precision * overall_recall / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
        
        results["overall_metrics"] = {
            "true_positives": overall_tp,
            "false_positives": overall_fp,
            "false_negatives": overall_fn,
            "precision": overall_precision,
            "recall": overall_recall,
            "f1_score": overall_f1,
            "passed_tests": sum(1 for tc in results["test_case_results"] if tc["passed"]),
            "total_tests": len(results["test_case_results"]),
            "pass_rate": sum(1 for tc in results["test_case_results"] if tc["passed"]) / len(results["test_case_results"]) if results["test_case_results"] else 0
        }
        
        # Calculate metrics by scenario type
        scenario_types = set(tc["scenario_type"] for tc in results["test_case_results"])
        for scenario_type in scenario_types:
            scenario_results = [tc for tc in results["test_case_results"] if tc["scenario_type"] == scenario_type]
            
            scenario_tp = sum(tc["metrics"]["true_positives"] for tc in scenario_results)
            scenario_fp = sum(tc["metrics"]["false_positives"] for tc in scenario_results)
            scenario_fn = sum(tc["metrics"]["false_negatives"] for tc in scenario_results)
            
            scenario_precision = scenario_tp / (scenario_tp + scenario_fp) if (scenario_tp + scenario_fp) > 0 else 0
            scenario_recall = scenario_tp / (scenario_tp + scenario_fn) if (scenario_tp + scenario_fn) > 0 else 0
            scenario_f1 = 2 * scenario_precision * scenario_recall / (scenario_precision + scenario_recall) if (scenario_precision + scenario_recall) > 0 else 0
            
            results["scenario_metrics"][scenario_type] = {
                "true_positives": scenario_tp,
                "false_positives": scenario_fp,
                "false_negatives": scenario_fn,
                "precision": scenario_precision,
                "recall": scenario_recall,
                "f1_score": scenario_f1,
                "passed_tests": sum(1 for tc in scenario_results if tc["passed"]),
                "total_tests": len(scenario_results),
                "pass_rate": sum(1 for tc in scenario_results if tc["passed"]) / len(scenario_results) if scenario_results else 0
            }
        
        # Generate confusion matrix if we have labels
        if all_expected_labels and all_predicted_labels:
            cm = confusion_matrix(all_expected_labels, all_predicted_labels)
            results["confusion_matrix"] = cm.tolist()
            
            # Calculate classification report
            report = classification_report(all_expected_labels, all_predicted_labels, output_dict=True)
            results["classification_report"] = report
        
        # Save results
        self._save_results(results)
        
        # Generate visualizations
        self._generate_visualizations(results)
        
        logger.info(f"Validation complete: Overall F1={overall_f1:.4f}, Pass Rate={results['overall_metrics']['pass_rate']:.2f}")
        
        return results
    
    def _find_latest_test_suite(self) -> Optional[str]:
        """Find the latest test suite file in the test data directory."""
        test_suite_files = [
            os.path.join(self.test_data_dir, f)
            for f in os.listdir(self.test_data_dir)
            if f.startswith("test_suite_") and f.endswith(".json")
        ]
        
        if not test_suite_files:
            return None
        
        # Sort by modification time (newest first)
        test_suite_files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        
        return test_suite_files[0]
    
    def _get_expected_findings(self, test_case_id: str, test_case_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get expected findings for a test case from ground truth or metadata.
        
        Args:
            test_case_id: ID of the test case
            test_case_metadata: Metadata for the test case
            
        Returns:
            List of expected findings
        """
        # First check if we have ground truth for this test case
        if test_case_id in self.ground_truth:
            return self.ground_truth[test_case_id]
        
        # Otherwise, generate expected findings based on scenario type
        scenario_type = test_case_metadata["scenario_type"]
        expected_findings = []
        
        if scenario_type == "prompt_injection":
            expected_findings.append({
                "type": "prompt_injection",
                "severity": "high",
                "description": "Prompt injection attempt detected"
            })
        elif scenario_type == "malicious_code":
            expected_findings.append({
                "type": "malicious_code",
                "severity": "high",
                "description": "Potentially malicious code detected"
            })
        elif scenario_type == "credential_exposure":
            expected_findings.append({
                "type": "credential_exposure",
                "severity": "high",
                "description": "Credential exposure detected"
            })
        elif scenario_type == "structural_variation":
            expected_findings.append({
                "type": "structural_issue",
                "severity": "medium",
                "description": "Structural issue detected"
            })
        elif scenario_type == "special_characters":
            expected_findings.append({
                "type": "special_characters",
                "severity": "low",
                "description": "Special characters detected"
            })
        elif scenario_type == "mixed":
            # For mixed scenarios, check the transformation types
            if "transformation_types" in test_case_metadata:
                for transform_type in test_case_metadata["transformation_types"]:
                    if transform_type == "prompt_injection":
                        expected_findings.append({
                            "type": "prompt_injection",
                            "severity": "high",
                            "description": "Prompt injection attempt detected"
                        })
                    elif transform_type == "malicious_code":
                        expected_findings.append({
                            "type": "malicious_code",
                            "severity": "high",
                            "description": "Potentially malicious code detected"
                        })
                    elif transform_type == "credential_exposure":
                        expected_findings.append({
                            "type": "credential_exposure",
                            "severity": "high",
                            "description": "Credential exposure detected"
                        })
        
        return expected_findings
    
    def _extract_findings_from_report(self, report) -> List[Dict[str, Any]]:
        """
        Extract findings from a pipeline report.
        
        Args:
            report: Pipeline report object
            
        Returns:
            List of findings
        """
        if hasattr(report, "findings"):
            return report.findings
        elif isinstance(report, dict) and "findings" in report:
            return report["findings"]
        elif isinstance(report, dict) and "status" in report and report["status"] == "failed":
            logger.error(f"Pipeline failed: {report.get('error')}")
            return []
        
        # Try to extract findings from analysis results
        if isinstance(report, dict) and "analysis_results" in report:
            findings = []
            for result in report["analysis_results"]:
                for analyzer_type, analyzer_result in result.items():
                    if isinstance(analyzer_result, dict) and "findings" in analyzer_result:
                        findings.extend(analyzer_result["findings"])
            return findings
        
        return []
    
    def _calculate_metrics(self, actual_findings: List[Dict[str, Any]], 
                         expected_findings: List[Dict[str, Any]]) -> Tuple[int, int, int, List[Dict[str, Any]]]:
        """
        Calculate true positives, false positives, and false negatives.
        
        Args:
            actual_findings: List of actual findings
            expected_findings: List of expected findings
            
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
        
        Args:
            actual: Actual finding
            expected: Expected finding
            
        Returns:
            True if the findings match, False otherwise
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
    
    def _save_results(self, results: Dict[str, Any]) -> str:
        """
        Save validation results to file.
        
        Args:
            results: Validation results
            
        Returns:
            Path to saved results file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(self.output_dir, f"validation_results_{timestamp}.json")
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Saved validation results to {file_path}")
        
        # Also save a summary file
        summary_path = os.path.join(self.output_dir, f"validation_summary_{timestamp}.txt")
        with open(summary_path, 'w') as f:
            f.write(f"Accuracy Validation Summary\n")
            f.write(f"==========================\n\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Test Cases: {results['metadata']['test_cases_count']}\n\n")
            
            f.write(f"Overall Metrics:\n")
            f.write(f"  Precision: {results['overall_metrics']['precision']:.4f}\n")
            f.write(f"  Recall: {results['overall_metrics']['recall']:.4f}\n")
            f.write(f"  F1 Score: {results['overall_metrics']['f1_score']:.4f}\n")
            f.write(f"  Pass Rate: {results['overall_metrics']['pass_rate']:.2f} ({results['overall_metrics']['passed_tests']}/{results['overall_metrics']['total_tests']})\n\n")
            
            f.write(f"Metrics by Scenario Type:\n")
            for scenario_type, metrics in results["scenario_metrics"].items():
                f.write(f"  {scenario_type}:\n")
                f.write(f"    Precision: {metrics['precision']:.4f}\n")
                f.write(f"    Recall: {metrics['recall']:.4f}\n")
                f.write(f"    F1 Score: {metrics['f1_score']:.4f}\n")
                f.write(f"    Pass Rate: {metrics['pass_rate']:.2f} ({metrics['passed_tests']}/{metrics['total_tests']})\n")
            
            f.write(f"\nDetailed Results:\n")
            for tc in results["test_case_results"]:
                f.write(f"  {tc['id']} ({tc['scenario_type']}): {'PASSED' if tc['passed'] else 'FAILED'}\n")
                f.write(f"    F1 Score: {tc['metrics']['f1_score']:.4f}\n")
                f.write(f"    Expected Findings: {tc['expected_findings_count']}\n")
                f.write(f"    Actual Findings: {tc['actual_findings_count']}\n")
                f.write(f"    TP: {tc['metrics']['true_positives']}, FP: {tc['metrics']['false_positives']}, FN: {tc['metrics']['false_negatives']}\n")
        
        logger.info(f"Saved validation summary to {summary_path}")
        
        return file_path
    
    def _generate_visualizations(self, results: Dict[str, Any]) -> None:
        """
        Generate visualizations of validation results.
        
        Args:
            results: Validation results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create a figure with multiple subplots
        plt.figure(figsize=(15, 12))
        
        # Plot overall metrics
        plt.subplot(2, 2, 1)
        metrics = ["precision", "recall", "f1_score", "pass_rate"]
        values = [results["overall_metrics"][m] for m in metrics]
        plt.bar(metrics, values)
        plt.ylim(0, 1)
        plt.title("Overall Metrics")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Plot metrics by scenario type
        plt.subplot(2, 2, 2)
        scenario_types = list(results["scenario_metrics"].keys())
        x = np.arange(len(scenario_types))
        width = 0.25
        
        precisions = [results["scenario_metrics"][s]["precision"] for s in scenario_types]
        recalls = [results["scenario_metrics"][s]["recall"] for s in scenario_types]
        f1_scores = [results["scenario_metrics"][s]["f1_score"] for s in scenario_types]
        
        plt.bar(x - width, precisions, width, label="Precision")
        plt.bar(x, recalls, width, label="Recall")
        plt.bar(x + width, f1_scores, width, label="F1 Score")
        
        plt.xlabel("Scenario Type")
        plt.ylabel("Score")
        plt.title("Metrics by Scenario Type")
        plt.xticks(x, scenario_types, rotation=45, ha="right")
        plt.ylim(0, 1)
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Plot confusion matrix if available
        if "confusion_matrix" in results:
            plt.subplot(2, 2, 3)
            cm = np.array(results["confusion_matrix"])
            plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
            plt.title("Confusion Matrix")
            plt.colorbar()
            
            classes = ["Negative", "Positive"]
            tick_marks = np.arange(len(classes))
            plt.xticks(tick_marks, classes)
            plt.yticks(tick_marks, classes)
            
            # Add text annotations
            thresh = cm.max() / 2.0
            for i in range(cm.shape[0]):
                for j in range(cm.shape[1]):
                    plt.text(j, i, format(cm[i, j], 'd'),
                            ha="center", va="center",
                            color="white" if cm[i, j] > thresh else "black")
            
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
        
        # Plot pass/fail by scenario type
        plt.subplot(2, 2, 4)
        passed = [results["scenario_metrics"][s]["passed_tests"] for s in scenario_types]
        failed = [results["scenario_metrics"][s]["total_tests"] - results["scenario_metrics"][s]["passed_tests"] for s in scenario_types]
        
        plt.bar(scenario_types, passed, label="Passed")
        plt.bar(scenario_types, failed, bottom=passed, label="Failed")
        
        plt.xlabel("Scenario Type")
        plt.ylabel("Test Cases")
        plt.title("Pass/Fail by Scenario Type")
        plt.xticks(rotation=45, ha="right")
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        
        # Save the figure
        viz_path = os.path.join(self.output_dir, f"validation_viz_{timestamp}.png")
        plt.savefig(viz_path)
        plt.close()
        
        logger.info(f"Saved validation visualizations to {viz_path}")
    
    def generate_ground_truth(self, test_suite_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate ground truth data for a test suite based on expected findings.
        
        Args:
            test_suite_path: Path to test suite file
            
        Returns:
            Dictionary mapping test case IDs to expected findings
        """
        logger.info(f"Generating ground truth for test suite: {test_suite_path}")
        
        # Load test suite
        with open(test_suite_path, 'r') as f:
            test_suite = json.load(f)
        
        # Get test cases directory
        test_suite_dir = os.path.dirname(test_suite_path)
        test_cases_dir = os.path.join(test_suite_dir, 
                                     os.path.basename(test_suite_path).replace("test_suite_", "test_cases_"))
        
        if not os.path.exists(test_cases_dir):
            raise ValueError(f"Test cases directory not found: {test_cases_dir}")
        
        # Generate ground truth
        ground_truth = {}
        
        for test_case_meta in test_suite["test_cases"]:
            test_case_id = test_case_meta["id"]
            
            # Load test case metadata
            meta_path = os.path.join(test_cases_dir, f"{test_case_id}.meta.json")
            if not os.path.exists(meta_path):
                logger.warning(f"Test case metadata file not found: {meta_path}")
                continue
            
            with open(meta_path, 'r') as f:
                test_case_metadata = json.load(f)
            
            # Generate expected findings based on scenario type
            expected_findings = self._get_expected_findings(test_case_id, test_case_metadata)
            
            ground_truth[test_case_id] = expected_findings
        
        # Save ground truth
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ground_truth_path = os.path.join(self.output_dir, f"ground_truth_{timestamp}.json")
        
        with open(ground_truth_path, 'w') as f:
            json.dump(ground_truth, f, indent=2)
        
        logger.info(f"Generated ground truth for {len(ground_truth)} test cases")
        logger.info(f"Saved ground truth to {ground_truth_path}")
        
        return ground_truth