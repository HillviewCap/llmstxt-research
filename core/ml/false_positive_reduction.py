"""
False Positive Reduction Module for ML-based Analysis

This module provides functionality to reduce false positives using supervised learning.
It implements classification of findings as true or false positives and provides
feature importance analysis to understand what drives false positive classification.
"""

import os
import pickle
import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

# Local imports
from core.ml.feature_extraction import FeatureExtractor

class FalsePositiveReducer:
    """
    Reduces false positives using supervised learning.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the false positive reducer with optional configuration.
        
        Args:
            config: Configuration dictionary with false positive reduction parameters
        """
        self.config = config or {}
        self.logger = logging.getLogger("FalsePositiveReducer")
        
        # Set default model directory
        self.model_dir = self.config.get("model_dir", "models")
        
        # Set default model name
        self.model_name = self.config.get("model_name", "false_positive_classifier")
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor(self.config.get("feature_extraction"))
        
        # Load model if available
        self.model = None
        self.metadata = None
        self._load_model()
        
        # Initialize feedback storage
        self.feedback_data = []
    
    def _load_model(self):
        """Load the trained false positive classifier model if available"""
        model_path = os.path.join(self.model_dir, f"{self.model_name}.pkl")
        metadata_path = os.path.join(self.model_dir, f"{self.model_name}_metadata.json")
        
        if os.path.exists(model_path) and os.path.exists(metadata_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                
                self.logger.info(f"Loaded false positive classifier model from {model_path}")
            except Exception as e:
                self.logger.error(f"Error loading model: {e}")
                self.model = None
                self.metadata = None
        else:
            self.logger.warning(f"False positive classifier model not found at {model_path}")
    
    def classify_findings(self, 
                         findings: List[Dict[str, Any]], 
                         content_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Classify findings as true or false positives.
        
        Args:
            findings: List of finding dictionaries
            content_items: List of content item dictionaries
                
        Returns:
            List of dictionaries with classification results
        """
        if not self.model:
            self.logger.error("No false positive classifier model loaded")
            return [{"error": "No model loaded", "finding_id": finding.get("id", "unknown")} 
                    for finding in findings]
        
        self.logger.info(f"Classifying {len(findings)} findings")
        
        # Create a mapping from content_id to content_item for efficient lookup
        content_map = {item.get("processed_id", ""): item for item in content_items}
        
        # Prepare data for classification
        classification_data = []
        for finding in findings:
            content_id = finding.get("content_id")
            if not content_id or content_id not in content_map:
                self.logger.warning(f"Content item not found for finding with content_id {content_id}")
                continue
            
            content_item = content_map[content_id]
            
            # Extract features from content
            features_data = self.feature_extractor.extract_features(content_item)
            
            # Combine with finding-specific features
            combined_features = self._combine_features(features_data, finding)
            
            classification_data.append({
                "finding": finding,
                "features": combined_features
            })
        
        # Classify findings
        results = []
        for item in classification_data:
            finding = item["finding"]
            features = item["features"]
            
            # Extract feature vector
            feature_vector = np.array([features["feature_vector"]])
            
            # Get prediction and probability
            is_true_positive = bool(self.model.predict(feature_vector)[0])
            probabilities = self.model.predict_proba(feature_vector)[0]
            
            # Probability of being a true positive (class 1)
            true_positive_probability = float(probabilities[1])
            
            # Calculate false positive likelihood (inverse of true positive probability)
            false_positive_likelihood = 1.0 - true_positive_probability
            
            # Get feature importance
            feature_importance = self._get_feature_importance(features, is_true_positive)
            
            results.append({
                "finding_id": finding.get("id", "unknown"),
                "is_true_positive": is_true_positive,
                "true_positive_probability": true_positive_probability,
                "false_positive_likelihood": false_positive_likelihood,
                "feature_importance": feature_importance
            })
        
        return results
    
    def _combine_features(self, 
                         content_features: Dict[str, Any], 
                         finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combine content features with finding-specific features.
        
        Args:
            content_features: Dictionary of content features
            finding: Finding dictionary
                
        Returns:
            Dictionary with combined features
        """
        # Start with content features
        combined = content_features.copy()
        
        # Extract finding-specific features
        finding_features = {
            "finding_type": finding.get("finding_type", "unknown"),
            "severity": finding.get("severity", "unknown"),
            "has_evidence": bool(finding.get("evidence")),
            "has_location": bool(finding.get("location")),
            "has_remediation": bool(finding.get("remediation_suggestion"))
        }
        
        # Add finding features to feature sets
        combined["feature_sets"]["finding_specific"] = finding_features
        
        # Update feature vector with finding-specific features
        # This is a simplified approach - in practice, you would use proper feature encoding
        finding_vector = [
            # One-hot encoding for finding type (simplified)
            1 if finding_features["finding_type"] == "credential_exposure" else 0,
            1 if finding_features["finding_type"] == "code_injection" else 0,
            1 if finding_features["finding_type"] == "xss" else 0,
            1 if finding_features["finding_type"] == "prompt_injection" else 0,
            
            # One-hot encoding for severity (simplified)
            1 if finding_features["severity"] == "critical" else 0,
            1 if finding_features["severity"] == "high" else 0,
            1 if finding_features["severity"] == "medium" else 0,
            1 if finding_features["severity"] == "low" else 0,
            
            # Boolean features
            1 if finding_features["has_evidence"] else 0,
            1 if finding_features["has_location"] else 0,
            1 if finding_features["has_remediation"] else 0
        ]
        
        # Combine vectors
        combined["feature_vector"] = combined["feature_vector"] + finding_vector
        
        return combined
    
    def _get_feature_importance(self, 
                               features: Dict[str, Any], 
                               is_true_positive: bool) -> List[Dict[str, Any]]:
        """
        Get feature importance for a classification result.
        This is a simplified implementation - in practice, this would use
        SHAP values or other model-specific feature importance methods.
        
        Args:
            features: Dictionary of features
            is_true_positive: Whether the finding is classified as a true positive
                
        Returns:
            List of dictionaries with feature name and importance score
        """
        feature_importance = []
        
        # If no model metadata is available, return empty list
        if not self.metadata or "top_features" not in self.metadata:
            return feature_importance
        
        # Get top features from model metadata
        top_features = self.metadata.get("top_features", [])
        
        # Get feature sets
        feature_sets = features.get("feature_sets", {})
        
        # Check for important features in the content
        for feature_name, importance in top_features:
            # Parse feature name to get feature set and specific feature
            if "." in feature_name:
                feature_set, specific_feature = feature_name.split(".", 1)
                
                if feature_set in feature_sets and specific_feature in feature_sets[feature_set]:
                    value = feature_sets[feature_set][specific_feature]
                    
                    # Only include features that contribute to the classification
                    if isinstance(value, bool) and value:
                        feature_importance.append({
                            "feature": feature_name,
                            "importance": float(importance),
                            "value": value
                        })
                    elif isinstance(value, (int, float)) and value > 0:
                        feature_importance.append({
                            "feature": feature_name,
                            "importance": float(importance),
                            "value": value
                        })
        
        # Add finding-specific features if available
        if "finding_specific" in feature_sets:
            finding_features = feature_sets["finding_specific"]
            
            # Add finding type
            finding_type = finding_features.get("finding_type", "unknown")
            feature_importance.append({
                "feature": f"finding_type.{finding_type}",
                "importance": 0.7 if is_true_positive else 0.3,
                "value": finding_type
            })
            
            # Add severity
            severity = finding_features.get("severity", "unknown")
            feature_importance.append({
                "feature": f"severity.{severity}",
                "importance": 0.6 if is_true_positive else 0.4,
                "value": severity
            })
            
            # Add evidence presence
            has_evidence = finding_features.get("has_evidence", False)
            if has_evidence:
                feature_importance.append({
                    "feature": "has_evidence",
                    "importance": 0.8 if is_true_positive else 0.2,
                    "value": True
                })
        
        # Sort by importance (highest first)
        feature_importance.sort(key=lambda x: x["importance"], reverse=True)
        
        # Limit to top 5 features
        return feature_importance[:5]
    
    def add_feedback(self, 
                    finding_id: str, 
                    is_true_positive: bool, 
                    content_item: Dict[str, Any],
                    finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add feedback for continuous learning.
        
        Args:
            finding_id: ID of the finding
            is_true_positive: Whether the finding is a true positive
            content_item: Content item dictionary
            finding: Finding dictionary
                
        Returns:
            Dictionary with feedback status
        """
        self.logger.info(f"Adding feedback for finding {finding_id}: is_true_positive={is_true_positive}")
        
        # Extract features
        features_data = self.feature_extractor.extract_features(content_item)
        
        # Combine with finding-specific features
        combined_features = self._combine_features(features_data, finding)
        
        # Add to feedback data
        feedback_entry = {
            "finding_id": finding_id,
            "is_true_positive": is_true_positive,
            "timestamp": datetime.now().isoformat(),
            "features": combined_features,
            "content_id": content_item.get("processed_id", "unknown"),
            "finding": finding
        }
        
        self.feedback_data.append(feedback_entry)
        
        # Save feedback data if configured
        if self.config.get("save_feedback", False):
            self._save_feedback()
        
        return {
            "status": "success",
            "message": f"Feedback added for finding {finding_id}",
            "feedback_count": len(self.feedback_data)
        }
    
    def _save_feedback(self):
        """Save feedback data to disk"""
        feedback_dir = self.config.get("feedback_dir", "feedback")
        os.makedirs(feedback_dir, exist_ok=True)
        
        feedback_path = os.path.join(feedback_dir, "fp_feedback.json")
        
        # Prepare data for serialization (remove non-serializable objects)
        serializable_feedback = []
        for entry in self.feedback_data:
            serializable_entry = {
                "finding_id": entry["finding_id"],
                "is_true_positive": entry["is_true_positive"],
                "timestamp": entry["timestamp"],
                "content_id": entry["content_id"]
            }
            serializable_feedback.append(serializable_entry)
        
        with open(feedback_path, 'w') as f:
            json.dump(serializable_feedback, f, indent=2)
        
        self.logger.info(f"Saved {len(serializable_feedback)} feedback entries to {feedback_path}")
    
    def get_feedback_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about collected feedback.
        
        Returns:
            Dictionary with feedback statistics
        """
        if not self.feedback_data:
            return {
                "count": 0,
                "true_positive_count": 0,
                "false_positive_count": 0,
                "true_positive_rate": 0.0
            }
        
        true_positive_count = sum(1 for entry in self.feedback_data if entry["is_true_positive"])
        false_positive_count = len(self.feedback_data) - true_positive_count
        true_positive_rate = true_positive_count / len(self.feedback_data)
        
        # Count by finding type
        finding_type_counts = {}
        for entry in self.feedback_data:
            finding_type = entry["finding"].get("finding_type", "unknown")
            if finding_type not in finding_type_counts:
                finding_type_counts[finding_type] = {
                    "total": 0,
                    "true_positive": 0,
                    "false_positive": 0
                }
            
            finding_type_counts[finding_type]["total"] += 1
            if entry["is_true_positive"]:
                finding_type_counts[finding_type]["true_positive"] += 1
            else:
                finding_type_counts[finding_type]["false_positive"] += 1
        
        # Calculate false positive rates by finding type
        for finding_type, counts in finding_type_counts.items():
            counts["false_positive_rate"] = counts["false_positive"] / counts["total"] if counts["total"] > 0 else 0
        
        return {
            "count": len(self.feedback_data),
            "true_positive_count": true_positive_count,
            "false_positive_count": false_positive_count,
            "true_positive_rate": true_positive_rate,
            "false_positive_rate": 1.0 - true_positive_rate,
            "by_finding_type": finding_type_counts
        }
    
    def track_model_performance(self, 
                               classification_results: List[Dict[str, Any]], 
                               feedback: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Track model performance based on feedback.
        
        Args:
            classification_results: List of classification results
            feedback: List of feedback entries
                
        Returns:
            Dictionary with performance metrics
        """
        self.logger.info(f"Tracking model performance with {len(feedback)} feedback entries")
        
        # Create a mapping from finding_id to classification result
        classification_map = {result["finding_id"]: result for result in classification_results}
        
        # Compare classifications with feedback
        correct_count = 0
        true_positive_correct = 0
        true_positive_total = 0
        false_positive_correct = 0
        false_positive_total = 0
        
        for entry in feedback:
            finding_id = entry["finding_id"]
            actual_is_true_positive = entry["is_true_positive"]
            
            if finding_id not in classification_map:
                continue
            
            predicted_is_true_positive = classification_map[finding_id]["is_true_positive"]
            
            if predicted_is_true_positive == actual_is_true_positive:
                correct_count += 1
                
                if actual_is_true_positive:
                    true_positive_correct += 1
                else:
                    false_positive_correct += 1
            
            if actual_is_true_positive:
                true_positive_total += 1
            else:
                false_positive_total += 1
        
        # Calculate metrics
        accuracy = correct_count / len(feedback) if feedback else 0
        true_positive_accuracy = true_positive_correct / true_positive_total if true_positive_total else 0
        false_positive_accuracy = false_positive_correct / false_positive_total if false_positive_total else 0
        
        performance = {
            "timestamp": datetime.now().isoformat(),
            "model_name": self.model_name,
            "feedback_count": len(feedback),
            "accuracy": accuracy,
            "true_positive_accuracy": true_positive_accuracy,
            "false_positive_accuracy": false_positive_accuracy,
            "metrics": {
                "correct_count": correct_count,
                "true_positive_correct": true_positive_correct,
                "true_positive_total": true_positive_total,
                "false_positive_correct": false_positive_correct,
                "false_positive_total": false_positive_total
            }
        }
        
        # Save performance tracking if configured
        if self.config.get("track_performance", False):
            self._save_performance_tracking(performance)
        
        return performance
    
    def _save_performance_tracking(self, performance: Dict[str, Any]):
        """Save performance tracking data to disk"""
        tracking_dir = self.config.get("tracking_dir", "tracking")
        os.makedirs(tracking_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tracking_path = os.path.join(tracking_dir, f"performance_{self.model_name}_{timestamp}.json")
        
        with open(tracking_path, 'w') as f:
            json.dump(performance, f, indent=2)
        
        self.logger.info(f"Saved performance tracking to {tracking_path}")