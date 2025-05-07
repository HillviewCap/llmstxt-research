"""
ML Integration Module for Security Analysis Pipeline

This module integrates machine learning components into the main analysis pipeline.
It provides a unified interface for ML-based analysis, including anomaly detection
and false positive reduction.
"""

import os
import logging
import json
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

# Local imports
from core.ml.feature_extraction import FeatureExtractor
from core.ml.anomaly_detection import AnomalyDetector
from core.ml.false_positive_reduction import FalsePositiveReducer
from core.ml.db_utils import MLDatabaseUtils
from core.database.connector import DatabaseConnector

class MLAnalysis:
    """
    Integrates machine learning components into the security analysis pipeline.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, db_connector: Optional[DatabaseConnector] = None):
        """
        Initialize the ML analysis integration with optional configuration.
        
        Args:
            config: Configuration dictionary with ML analysis parameters
            db_connector: Database connector for storing ML results
        """
        self.config = config or {}
        self.logger = logging.getLogger("MLAnalysis")
        
        # Initialize database connector and utilities
        self.db = db_connector
        if self.db:
            self.db_utils = MLDatabaseUtils(self.db)
        
        # Initialize ML components
        self.feature_extractor = FeatureExtractor(self.config.get("feature_extraction"))
        self.anomaly_detector = AnomalyDetector(self.config.get("anomaly_detection"))
        self.false_positive_reducer = FalsePositiveReducer(self.config.get("false_positive"))
        
        # Create model directories if they don't exist
        model_dir = self.config.get("model_dir", "models")
        os.makedirs(model_dir, exist_ok=True)
        
        # Initialize performance tracking
        self.performance = {}
    
    def analyze(self, 
               content_items: List[Dict[str, Any]], 
               findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Perform ML-based analysis on content items and findings.
        
        Args:
            content_items: List of content item dictionaries
            findings: Optional list of finding dictionaries from other analyzers
                
        Returns:
            Dictionary with ML analysis results
        """
        self.logger.info(f"Performing ML analysis on {len(content_items)} content items")
        
        start_time = datetime.now()
        
        # Extract features
        features_start = datetime.now()
        features_data = self.feature_extractor.extract_features_batch(content_items)
        self.performance['feature_extraction'] = (datetime.now() - features_start).total_seconds()
        
        # Perform anomaly detection
        anomaly_start = datetime.now()
        anomaly_results = self.anomaly_detector.detect_anomalies(content_items)
        
        # Perform outlier detection based on normal behavior modeling
        outlier_results = self.anomaly_detector.detect_outliers(content_items)
        
        # Combine anomaly and outlier detection results
        combined_anomaly_results = self.anomaly_detector.combine_detection_results(
            anomaly_results, outlier_results
        )
        self.performance['anomaly_detection'] = (datetime.now() - anomaly_start).total_seconds()
        
        # Perform false positive reduction if findings are provided
        fp_results = []
        if findings:
            fp_start = datetime.now()
            fp_results = self.false_positive_reducer.classify_findings(findings, content_items)
            self.performance['false_positive_reduction'] = (datetime.now() - fp_start).total_seconds()
        
        # Store results in database if configured
        if self.db and self.config.get("store_results", True):
            db_start = datetime.now()
            self._store_results_in_db(content_items, combined_anomaly_results, fp_results)
            self.performance['database_storage'] = (datetime.now() - db_start).total_seconds()
        
        # Calculate total time
        self.performance['total'] = (datetime.now() - start_time).total_seconds()
        
        return {
            "anomaly_detection": combined_anomaly_results,
            "false_positive_reduction": fp_results,
            "performance": self.performance
        }
    
    def _store_results_in_db(self,
                            content_items: List[Dict[str, Any]],
                            anomaly_results: List[Dict[str, Any]],
                            fp_results: List[Dict[str, Any]]):
        """
        Store ML analysis results in the database.
        
        Args:
            content_items: List of content item dictionaries
            anomaly_results: List of anomaly detection results
            fp_results: List of false positive reduction results
        """
        self.logger.info("Storing ML analysis results in database")
        
        # Create a mapping from content_id to content_item for efficient lookup
        content_map = {item.get("processed_id", ""): item for item in content_items}
        
        # Create a mapping from finding_id to false positive result for efficient lookup
        fp_map = {result["finding_id"]: result for result in fp_results}
        
        # Store anomaly detection results
        for result in anomaly_results:
            content_id = result.get("content_id")
            if not content_id or content_id not in content_map:
                continue
            
            content_item = content_map[content_id]
            url_id = content_item.get("url_id")
            
            if not url_id:
                continue
            
            # Store anomaly detection result in ML-specific table
            try:
                self.db_utils.store_anomaly_detection_result({
                    "content_id": content_id,
                    "is_anomalous": result.get("is_anomalous", False),
                    "anomaly_score": result.get("combined_score", 0),
                    "confidence": result.get("confidence", 0),
                    "model_version": self.config.get("model_version", "1.0.0"),
                    "contributing_factors": result.get("contributing_factors", [])
                })
            except Exception as e:
                self.logger.error(f"Error storing anomaly detection result: {e}")
            
            # Store anomaly detection result as a finding if it's anomalous
            if result.get("is_anomalous", False):
                # Prepare finding data
                finding_data = {
                    "analysis_id": None,  # Will be set by the database connector
                    "finding_type": "ml_anomaly_detection",
                    "severity": self._get_severity_from_score(result.get("combined_score", 0)),
                    "description": f"ML-based anomaly detection identified suspicious content",
                    "location": json.dumps({"content_id": content_id, "url_id": url_id}),
                    "evidence": json.dumps({
                        "anomaly_score": result.get("combined_score", 0),
                        "confidence": result.get("confidence", 0),
                        "contributing_factors": result.get("contributing_factors", [])
                    }),
                    "false_positive_likelihood": 0.0,  # Will be updated if FP reduction is applied
                    "remediation_suggestion": "Review the content for potential security issues"
                }
                
                # Store finding in database
                self.db.store_security_finding(finding_data, url_id)
        
        # Update false positive likelihoods for existing findings
        for result in fp_results:
            finding_id = result.get("finding_id")
            false_positive_likelihood = result.get("false_positive_likelihood", 0.0)
            
            # Update finding in database
            try:
                self.db_utils.update_finding_false_positive_likelihood(finding_id, false_positive_likelihood)
            except Exception as e:
                self.logger.error(f"Error updating false positive likelihood: {e}")
    
    def _get_severity_from_score(self, score: float) -> str:
        """
        Convert a numerical score to a severity level.
        
        Args:
            score: Numerical score between 0 and 1
                
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        if score >= 0.85:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        elif score >= 0.3:
            return "low"
        else:
            return "info"
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """
        Get performance metrics for ML analysis.
        
        Returns:
            Dictionary with performance metrics
        """
        return self.performance
    
    def process_feedback(self, feedback: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process feedback for continuous learning.
        
        Args:
            feedback: Dictionary with feedback data
                
        Returns:
            Dictionary with feedback processing status
        """
        self.logger.info(f"Processing feedback for finding {feedback.get('finding_id')}")
        
        finding_id = feedback.get("finding_id")
        is_true_positive = feedback.get("is_true_positive", False)
        content_id = feedback.get("content_id")
        
        if not finding_id or not content_id:
            return {
                "status": "error",
                "message": "Missing required feedback data (finding_id or content_id)"
            }
        
        # Get content item and finding from database
        content_item = self.db_utils.get_content_by_id(content_id)
        finding = self.db_utils.get_finding_by_id(finding_id)
        
        if not content_item or not finding:
            return {
                "status": "error",
                "message": f"Content item or finding not found in database"
            }
        
        # Store feedback in database
        try:
            self.db_utils.store_feedback({
                "finding_id": finding_id,
                "is_true_positive": is_true_positive,
                "content_id": content_id,
                "feedback_source": feedback.get("feedback_source", "user"),
                "notes": feedback.get("notes")
            })
        except Exception as e:
            self.logger.error(f"Error storing feedback: {e}")
        
        # Add feedback to false positive reducer
        result = self.false_positive_reducer.add_feedback(
            finding_id, is_true_positive, content_item, finding
        )
        
        return {
            "status": "success",
            "message": f"Feedback processed for finding {finding_id}",
            "details": result
        }
    
    def train_models(self, 
                    training_data: Optional[Dict[str, Any]] = None, 
                    use_db_data: bool = True) -> Dict[str, Any]:
        """
        Train ML models using provided data or data from the database.
        
        Args:
            training_data: Optional dictionary with training data
            use_db_data: Whether to use data from the database
                
        Returns:
            Dictionary with training results
        """
        self.logger.info("Training ML models")
        
        # Import training module
        from core.ml.model_training import ModelTrainer
        
        # Initialize model trainer
        trainer = ModelTrainer(self.config.get("model_training"))
        
        # Get training data
        anomaly_data = []
        fp_data = []
        fp_labels = []
        
        if training_data:
            anomaly_data = training_data.get("anomaly_data", [])
            fp_data = training_data.get("fp_data", [])
            fp_labels = training_data.get("fp_labels", [])
        
        if use_db_data:
            # Get data from database
            db_content_items = self.db_utils.get_all_content_items()
            db_findings = self.db_utils.get_all_findings()
            
            # Use all content items for anomaly detection
            anomaly_data.extend(db_content_items)
            
            # Generate training data for false positive reduction
            if db_findings:
                fp_training_data = trainer.generate_training_data_from_findings(
                    db_findings, db_content_items
                )
                fp_data.extend(fp_training_data[0])
                fp_labels.extend(fp_training_data[1])
        
        # Train models
        results = {}
        
        # Train anomaly detection model if data is available
        if anomaly_data:
            self.logger.info(f"Training anomaly detection model with {len(anomaly_data)} samples")
            anomaly_result = trainer.train_anomaly_detection_model(anomaly_data)
            
            # Store model metadata in database
            try:
                model_id = self.db_utils.store_model_metadata({
                    "model_name": "anomaly_detection",
                    "model_type": "isolation_forest",
                    "version": self.config.get("model_version", "1.0.0"),
                    "parameters": anomaly_result["metadata"].get("parameters"),
                    "performance_metrics": anomaly_result["metadata"].get("performance"),
                    "feature_version": self.feature_extractor.feature_version
                })
                
                # Store initial performance metrics
                self.db_utils.store_model_performance({
                    "model_id": model_id,
                    "num_samples": len(anomaly_data),
                    "additional_metrics": anomaly_result["metadata"].get("performance")
                })
            except Exception as e:
                self.logger.error(f"Error storing model metadata: {e}")
            
            results["anomaly_detection"] = {
                "status": "success",
                "model_path": anomaly_result["model_path"],
                "metadata_path": anomaly_result["metadata_path"],
                "num_samples": len(anomaly_data)
            }
        else:
            results["anomaly_detection"] = {
                "status": "error",
                "message": "No data available for training anomaly detection model"
            }
        
        # Train false positive reduction model if data is available
        if fp_data and fp_labels and len(fp_data) == len(fp_labels):
            self.logger.info(f"Training false positive reduction model with {len(fp_data)} samples")
            fp_result = trainer.train_false_positive_model(fp_data, fp_labels)
            
            # Store model metadata in database
            try:
                model_id = self.db_utils.store_model_metadata({
                    "model_name": "false_positive_classifier",
                    "model_type": "random_forest",
                    "version": self.config.get("model_version", "1.0.0"),
                    "parameters": fp_result["metadata"].get("parameters"),
                    "performance_metrics": fp_result["performance"],
                    "feature_version": self.feature_extractor.feature_version
                })
                
                # Store initial performance metrics
                self.db_utils.store_model_performance({
                    "model_id": model_id,
                    "accuracy": fp_result["performance"].get("accuracy"),
                    "precision": fp_result["performance"].get("precision"),
                    "recall": fp_result["performance"].get("recall"),
                    "f1_score": fp_result["performance"].get("f1_score"),
                    "num_samples": len(fp_data),
                    "additional_metrics": {
                        "feature_importances": fp_result.get("feature_importances", {})
                    }
                })
            except Exception as e:
                self.logger.error(f"Error storing model metadata: {e}")
            
            results["false_positive_reduction"] = {
                "status": "success",
                "model_path": fp_result["model_path"],
                "metadata_path": fp_result["metadata_path"],
                "num_samples": len(fp_data),
                "performance": fp_result["performance"]
            }
        else:
            results["false_positive_reduction"] = {
                "status": "error",
                "message": "No data available for training false positive reduction model"
            }
        
        # Reload models after training
        self.anomaly_detector = AnomalyDetector(self.config.get("anomaly_detection"))
        self.false_positive_reducer = FalsePositiveReducer(self.config.get("false_positive"))
        
        return results
    
    def evaluate_models(self, 
                       test_data: Optional[Dict[str, Any]] = None, 
                       use_db_data: bool = True) -> Dict[str, Any]:
        """
        Evaluate ML models using provided data or data from the database.
        
        Args:
            test_data: Optional dictionary with test data
            use_db_data: Whether to use data from the database
                
        Returns:
            Dictionary with evaluation results
        """
        self.logger.info("Evaluating ML models")
        
        # Import evaluation module
        from core.ml.model_evaluation import ModelEvaluator
        
        # Initialize model evaluator
        evaluator = ModelEvaluator(self.config.get("model_evaluation"))
        
        # Get test data
        anomaly_data = []
        anomaly_labels = []
        fp_data = []
        fp_labels = []
        
        if test_data:
            anomaly_data = test_data.get("anomaly_data", [])
            anomaly_labels = test_data.get("anomaly_labels", [])
            fp_data = test_data.get("fp_data", [])
            fp_labels = test_data.get("fp_labels", [])
        
        if use_db_data:
            # Get data from database
            db_content_items = self.db_utils.get_all_content_items()
            db_findings = self.db_utils.get_all_findings()
            
            # Use a subset of content items for testing
            if db_content_items:
                import random
                test_size = min(len(db_content_items), 100)  # Limit to 100 samples
                anomaly_data.extend(random.sample(db_content_items, test_size))
            
            # Generate test data for false positive reduction
            if db_findings:
                from core.ml.model_training import ModelTrainer
                trainer = ModelTrainer(self.config.get("model_training"))
                fp_test_data = trainer.generate_training_data_from_findings(
                    db_findings, db_content_items
                )
                fp_data.extend(fp_test_data[0])
                fp_labels.extend(fp_test_data[1])
        
        # Evaluate models
        results = {}
        
        # Evaluate anomaly detection model if data is available
        if anomaly_data:
            self.logger.info(f"Evaluating anomaly detection model with {len(anomaly_data)} samples")
            try:
                anomaly_result = evaluator.evaluate_anomaly_detection_model(
                    "anomaly_detection", anomaly_data, anomaly_labels if anomaly_labels else None
                )
                # Store performance metrics in database
                try:
                    # Get model metadata
                    model_metadata = self.db_utils.get_model_metadata("anomaly_detection")
                    if model_metadata:
                        # Store performance metrics
                        self.db_utils.store_model_performance({
                            "model_id": model_metadata["id"],
                            "num_samples": len(anomaly_data),
                            "additional_metrics": anomaly_result
                        })
                except Exception as e:
                    self.logger.error(f"Error storing model performance: {e}")
                
                results["anomaly_detection"] = {
                    "status": "success",
                    "num_samples": len(anomaly_data),
                    "results": anomaly_result
                }
            except Exception as e:
                self.logger.error(f"Error evaluating anomaly detection model: {e}")
                results["anomaly_detection"] = {
                    "status": "error",
                    "message": str(e)
                }
        else:
            results["anomaly_detection"] = {
                "status": "error",
                "message": "No data available for evaluating anomaly detection model"
            }
        
        # Evaluate false positive reduction model if data is available
        if fp_data and fp_labels and len(fp_data) == len(fp_labels):
            self.logger.info(f"Evaluating false positive reduction model with {len(fp_data)} samples")
            try:
                fp_result = evaluator.evaluate_false_positive_model(
                    "false_positive_classifier", fp_data, fp_labels
                )
                # Store performance metrics in database
                try:
                    # Get model metadata
                    model_metadata = self.db_utils.get_model_metadata("false_positive_classifier")
                    if model_metadata:
                        # Store performance metrics
                        self.db_utils.store_model_performance({
                            "model_id": model_metadata["id"],
                            "accuracy": fp_result.get("performance", {}).get("accuracy"),
                            "precision": fp_result.get("performance", {}).get("precision"),
                            "recall": fp_result.get("performance", {}).get("recall"),
                            "f1_score": fp_result.get("performance", {}).get("f1_score"),
                            "num_samples": len(fp_data),
                            "additional_metrics": fp_result
                        })
                except Exception as e:
                    self.logger.error(f"Error storing model performance: {e}")
                
                results["false_positive_reduction"] = {
                    "status": "success",
                    "num_samples": len(fp_data),
                    "results": fp_result
                }
            except Exception as e:
                self.logger.error(f"Error evaluating false positive reduction model: {e}")
                results["false_positive_reduction"] = {
                    "status": "error",
                    "message": str(e)
                }
        else:
            results["false_positive_reduction"] = {
                "status": "error",
                "message": "No data available for evaluating false positive reduction model"
            }
        
        return results