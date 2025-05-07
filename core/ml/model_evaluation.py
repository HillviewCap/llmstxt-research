"""
Model Evaluation Module for ML-based Analysis

This module provides functionality to evaluate machine learning models for security analysis.
It supports evaluating models for anomaly detection and false positive reduction.
"""

import os
import pickle
import json
import logging
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

# ML libraries
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score, 
    precision_recall_fscore_support, roc_curve, auc, 
    precision_recall_curve, average_precision_score
)

# Local imports
from core.ml.feature_extraction import FeatureExtractor

class ModelEvaluator:
    """
    Evaluates machine learning models for security analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the model evaluator with optional configuration.
        
        Args:
            config: Configuration dictionary with evaluation parameters
        """
        self.config = config or {}
        self.logger = logging.getLogger("ModelEvaluator")
        
        # Set default model directory
        self.model_dir = self.config.get("model_dir", "models")
        
        # Set default evaluation output directory
        self.eval_dir = self.config.get("eval_dir", "evaluation")
        os.makedirs(self.eval_dir, exist_ok=True)
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor(self.config.get("feature_extraction"))
    
    def load_model(self, model_name: str) -> Tuple[Any, Dict[str, Any]]:
        """
        Load a trained model and its metadata.
        
        Args:
            model_name: Name of the model to load
            
        Returns:
            Tuple of (model, metadata)
        """
        model_path = os.path.join(self.model_dir, f"{model_name}.pkl")
        metadata_path = os.path.join(self.model_dir, f"{model_name}_metadata.json")
        
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            return model, metadata
        except FileNotFoundError as e:
            self.logger.error(f"Model or metadata file not found: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise
    
    def evaluate_anomaly_detection_model(self, 
                                        model_name: str,
                                        test_data: List[Dict[str, Any]],
                                        ground_truth: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Evaluate an anomaly detection model.
        
        Args:
            model_name: Name of the model to evaluate
            test_data: List of content items to evaluate on
            ground_truth: Optional list of ground truth labels (1 for normal, -1 for anomaly)
            
        Returns:
            Dictionary with evaluation results
        """
        self.logger.info(f"Evaluating anomaly detection model '{model_name}' on {len(test_data)} samples")
        
        # Load the model and metadata
        model, metadata = self.load_model(model_name)
        
        # Extract features
        features_data = self.feature_extractor.extract_features_batch(test_data)
        feature_vectors = [item["feature_vector"] for item in features_data]
        
        # Convert to numpy array
        X = np.array(feature_vectors)
        
        # Get anomaly scores and predictions
        # For isolation forest, decision_function returns the negative of the anomaly score
        anomaly_scores = -model.decision_function(X)
        threshold = metadata.get("threshold", 0)
        predictions = (anomaly_scores > threshold).astype(int) * 2 - 1  # Convert to -1/1
        
        # Calculate statistics
        num_anomalies = np.sum(predictions == -1)
        anomaly_ratio = num_anomalies / len(predictions)
        
        results = {
            "model_name": model_name,
            "num_samples": len(test_data),
            "num_anomalies_detected": int(num_anomalies),
            "anomaly_ratio": float(anomaly_ratio),
            "threshold": float(threshold),
            "score_statistics": {
                "min": float(np.min(anomaly_scores)),
                "max": float(np.max(anomaly_scores)),
                "mean": float(np.mean(anomaly_scores)),
                "median": float(np.median(anomaly_scores)),
                "std": float(np.std(anomaly_scores))
            }
        }
        
        # If ground truth is provided, calculate additional metrics
        if ground_truth is not None:
            if len(ground_truth) != len(test_data):
                raise ValueError(f"Ground truth length ({len(ground_truth)}) must match test data length ({len(test_data)})")
            
            y_true = np.array(ground_truth)
            
            # Calculate metrics
            accuracy = accuracy_score(y_true, predictions)
            precision, recall, f1, _ = precision_recall_fscore_support(y_true, predictions, average='binary', pos_label=-1)
            
            results["supervised_metrics"] = {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "confusion_matrix": confusion_matrix(y_true, predictions).tolist()
            }
            
            # Generate ROC curve data
            # For anomaly detection, we need to adjust the scores and labels
            # Higher anomaly score means more likely to be an anomaly (-1)
            # ROC curve expects higher scores for positive class (which is -1 for anomalies)
            fpr, tpr, _ = roc_curve((y_true == -1).astype(int), anomaly_scores)
            roc_auc = auc(fpr, tpr)
            
            results["roc_curve"] = {
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
                "auc": float(roc_auc)
            }
            
            # Generate precision-recall curve data
            precision_curve, recall_curve, _ = precision_recall_curve((y_true == -1).astype(int), anomaly_scores)
            avg_precision = average_precision_score((y_true == -1).astype(int), anomaly_scores)
            
            results["pr_curve"] = {
                "precision": precision_curve.tolist(),
                "recall": recall_curve.tolist(),
                "average_precision": float(avg_precision)
            }
            
            # Generate plots if configured
            if self.config.get("generate_plots", False):
                self._generate_anomaly_detection_plots(
                    model_name, anomaly_scores, y_true, 
                    fpr, tpr, roc_auc, 
                    precision_curve, recall_curve, avg_precision
                )
        
        # Save evaluation results
        results_path = os.path.join(self.eval_dir, f"{model_name}_evaluation.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Anomaly detection model evaluation saved to {results_path}")
        
        return results
    
    def evaluate_false_positive_model(self, 
                                     model_name: str,
                                     test_data: List[Dict[str, Any]],
                                     labels: List[int]) -> Dict[str, Any]:
        """
        Evaluate a false positive reduction model.
        
        Args:
            model_name: Name of the model to evaluate
            test_data: List of content items to evaluate on
            labels: Binary labels (1 for true positive, 0 for false positive)
            
        Returns:
            Dictionary with evaluation results
        """
        self.logger.info(f"Evaluating false positive model '{model_name}' on {len(test_data)} samples")
        
        if len(test_data) != len(labels):
            raise ValueError(f"Test data length ({len(test_data)}) must match labels length ({len(labels)})")
        
        # Load the model and metadata
        model, metadata = self.load_model(model_name)
        
        # Extract features
        features_data = self.feature_extractor.extract_features_batch(test_data)
        feature_vectors = [item["feature_vector"] for item in features_data]
        
        # Convert to numpy arrays
        X = np.array(feature_vectors)
        y_true = np.array(labels)
        
        # Get predictions and probabilities
        y_pred = model.predict(X)
        y_prob = model.predict_proba(X)[:, 1]  # Probability of class 1 (true positive)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
        
        # Generate classification report
        report = classification_report(y_true, y_pred, output_dict=True)
        
        # Generate confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Generate ROC curve data
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)
        
        # Generate precision-recall curve data
        precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_prob)
        avg_precision = average_precision_score(y_true, y_prob)
        
        results = {
            "model_name": model_name,
            "num_samples": len(test_data),
            "performance": {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1)
            },
            "classification_report": report,
            "confusion_matrix": cm.tolist(),
            "roc_curve": {
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
                "auc": float(roc_auc)
            },
            "pr_curve": {
                "precision": precision_curve.tolist(),
                "recall": recall_curve.tolist(),
                "average_precision": float(avg_precision)
            }
        }
        
        # Generate plots if configured
        if self.config.get("generate_plots", False):
            self._generate_classification_plots(
                model_name, y_true, y_pred, y_prob, 
                fpr, tpr, roc_auc, 
                precision_curve, recall_curve, avg_precision
            )
        
        # Save evaluation results
        results_path = os.path.join(self.eval_dir, f"{model_name}_evaluation.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"False positive model evaluation saved to {results_path}")
        
        return results
    
    def _generate_anomaly_detection_plots(self, 
                                         model_name: str, 
                                         anomaly_scores: np.ndarray, 
                                         y_true: np.ndarray,
                                         fpr: np.ndarray, 
                                         tpr: np.ndarray, 
                                         roc_auc: float,
                                         precision_curve: np.ndarray, 
                                         recall_curve: np.ndarray, 
                                         avg_precision: float):
        """Generate plots for anomaly detection evaluation"""
        # Create a directory for plots
        plots_dir = os.path.join(self.eval_dir, "plots")
        os.makedirs(plots_dir, exist_ok=True)
        
        # Plot anomaly score distribution
        plt.figure(figsize=(10, 6))
        plt.hist(anomaly_scores[y_true == 1], bins=20, alpha=0.5, label='Normal')
        plt.hist(anomaly_scores[y_true == -1], bins=20, alpha=0.5, label='Anomaly')
        plt.xlabel('Anomaly Score')
        plt.ylabel('Count')
        plt.title(f'Anomaly Score Distribution - {model_name}')
        plt.legend()
        plt.savefig(os.path.join(plots_dir, f"{model_name}_score_distribution.png"))
        plt.close()
        
        # Plot ROC curve
        plt.figure(figsize=(10, 6))
        plt.plot(fpr, tpr, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], 'k--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'ROC Curve - {model_name}')
        plt.legend(loc="lower right")
        plt.savefig(os.path.join(plots_dir, f"{model_name}_roc_curve.png"))
        plt.close()
        
        # Plot precision-recall curve
        plt.figure(figsize=(10, 6))
        plt.plot(recall_curve, precision_curve, label=f'Precision-Recall curve (AP = {avg_precision:.2f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.ylim([0.0, 1.05])
        plt.xlim([0.0, 1.0])
        plt.title(f'Precision-Recall Curve - {model_name}')
        plt.legend(loc="lower left")
        plt.savefig(os.path.join(plots_dir, f"{model_name}_pr_curve.png"))
        plt.close()
    
    def _generate_classification_plots(self, 
                                      model_name: str, 
                                      y_true: np.ndarray, 
                                      y_pred: np.ndarray, 
                                      y_prob: np.ndarray,
                                      fpr: np.ndarray, 
                                      tpr: np.ndarray, 
                                      roc_auc: float,
                                      precision_curve: np.ndarray, 
                                      recall_curve: np.ndarray, 
                                      avg_precision: float):
        """Generate plots for classification evaluation"""
        # Create a directory for plots
        plots_dir = os.path.join(self.eval_dir, "plots")
        os.makedirs(plots_dir, exist_ok=True)
        
        # Plot confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(8, 6))
        plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        plt.title(f'Confusion Matrix - {model_name}')
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ['False Positive', 'True Positive'])
        plt.yticks(tick_marks, ['False Positive', 'True Positive'])
        
        # Add text annotations
        thresh = cm.max() / 2.
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                plt.text(j, i, format(cm[i, j], 'd'),
                        ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black")
        
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, f"{model_name}_confusion_matrix.png"))
        plt.close()
        
        # Plot ROC curve
        plt.figure(figsize=(10, 6))
        plt.plot(fpr, tpr, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], 'k--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'ROC Curve - {model_name}')
        plt.legend(loc="lower right")
        plt.savefig(os.path.join(plots_dir, f"{model_name}_roc_curve.png"))
        plt.close()
        
        # Plot precision-recall curve
        plt.figure(figsize=(10, 6))
        plt.plot(recall_curve, precision_curve, label=f'Precision-Recall curve (AP = {avg_precision:.2f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.ylim([0.0, 1.05])
        plt.xlim([0.0, 1.0])
        plt.title(f'Precision-Recall Curve - {model_name}')
        plt.legend(loc="lower left")
        plt.savefig(os.path.join(plots_dir, f"{model_name}_pr_curve.png"))
        plt.close()
        
        # Plot probability distribution
        plt.figure(figsize=(10, 6))
        plt.hist(y_prob[y_true == 0], bins=20, alpha=0.5, label='False Positive')
        plt.hist(y_prob[y_true == 1], bins=20, alpha=0.5, label='True Positive')
        plt.xlabel('Probability of True Positive')
        plt.ylabel('Count')
        plt.title(f'Probability Distribution - {model_name}')
        plt.legend()
        plt.savefig(os.path.join(plots_dir, f"{model_name}_prob_distribution.png"))
        plt.close()
    
    def evaluate_model_performance_over_time(self, 
                                           model_name: str, 
                                           historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate model performance over time using historical data.
        
        Args:
            model_name: Name of the model to evaluate
            historical_data: List of dictionaries with 'data', 'labels', and 'timestamp' keys
            
        Returns:
            Dictionary with evaluation results over time
        """
        self.logger.info(f"Evaluating model '{model_name}' performance over time")
        
        # Load the model and metadata
        model, metadata = self.load_model(model_name)
        
        # Sort historical data by timestamp
        historical_data.sort(key=lambda x: x.get('timestamp', ''))
        
        results = {
            "model_name": model_name,
            "timestamps": [],
            "metrics": []
        }
        
        model_type = metadata.get("model_type", "unknown")
        
        for entry in historical_data:
            timestamp = entry.get('timestamp')
            data = entry.get('data', [])
            labels = entry.get('labels', [])
            
            if not data or (model_type == "false_positive_classifier" and not labels):
                continue
            
            # Extract features
            features_data = self.feature_extractor.extract_features_batch(data)
            feature_vectors = [item["feature_vector"] for item in features_data]
            X = np.array(feature_vectors)
            
            metrics = {}
            
            if model_type == "anomaly_detection":
                # For anomaly detection
                anomaly_scores = -model.decision_function(X)
                threshold = metadata.get("threshold", 0)
                predictions = (anomaly_scores > threshold).astype(int) * 2 - 1
                
                num_anomalies = np.sum(predictions == -1)
                anomaly_ratio = num_anomalies / len(predictions)
                
                metrics = {
                    "num_samples": len(data),
                    "num_anomalies": int(num_anomalies),
                    "anomaly_ratio": float(anomaly_ratio)
                }
                
                # If labels are provided, calculate supervised metrics
                if labels and len(labels) == len(data):
                    y_true = np.array(labels)
                    accuracy = accuracy_score(y_true, predictions)
                    precision, recall, f1, _ = precision_recall_fscore_support(
                        y_true, predictions, average='binary', pos_label=-1
                    )
                    
                    metrics.update({
                        "accuracy": float(accuracy),
                        "precision": float(precision),
                        "recall": float(recall),
                        "f1_score": float(f1)
                    })
            
            elif model_type == "false_positive_classifier":
                # For false positive classifier
                if not labels or len(labels) != len(data):
                    continue
                
                y_true = np.array(labels)
                y_pred = model.predict(X)
                
                accuracy = accuracy_score(y_true, y_pred)
                precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
                
                metrics = {
                    "num_samples": len(data),
                    "accuracy": float(accuracy),
                    "precision": float(precision),
                    "recall": float(recall),
                    "f1_score": float(f1)
                }
            
            results["timestamps"].append(timestamp)
            results["metrics"].append(metrics)
        
        # Save evaluation results
        results_path = os.path.join(self.eval_dir, f"{model_name}_performance_over_time.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate performance over time plot if configured
        if self.config.get("generate_plots", False) and results["timestamps"]:
            self._generate_performance_over_time_plot(model_name, results)
        
        self.logger.info(f"Model performance over time evaluation saved to {results_path}")
        
        return results
    
    def _generate_performance_over_time_plot(self, model_name: str, results: Dict[str, Any]):
        """Generate plot for model performance over time"""
        # Create a directory for plots
        plots_dir = os.path.join(self.eval_dir, "plots")
        os.makedirs(plots_dir, exist_ok=True)
        
        timestamps = results["timestamps"]
        metrics = results["metrics"]
        
        # Check which metrics are available
        available_metrics = set()
        for m in metrics:
            available_metrics.update(m.keys())
        
        # Remove non-numeric metrics
        available_metrics.discard("num_samples")
        
        # Plot each available metric over time
        plt.figure(figsize=(12, 8))
        
        for metric_name in available_metrics:
            if metric_name == "num_samples":
                continue
                
            metric_values = [m.get(metric_name, None) for m in metrics]
            # Filter out None values
            valid_indices = [i for i, v in enumerate(metric_values) if v is not None]
            valid_timestamps = [timestamps[i] for i in valid_indices]
            valid_values = [metric_values[i] for i in valid_indices]
            
            if valid_values:
                plt.plot(valid_timestamps, valid_values, marker='o', label=metric_name)
        
        plt.xlabel('Timestamp')
        plt.ylabel('Metric Value')
        plt.title(f'Model Performance Over Time - {model_name}')
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, f"{model_name}_performance_over_time.png"))
        plt.close()