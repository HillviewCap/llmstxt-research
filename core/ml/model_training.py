"""
Model Training Module for ML-based Analysis

This module provides functionality to train machine learning models for security analysis.
It supports training models for anomaly detection and false positive reduction.
"""

import os
import pickle
import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

# ML libraries
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Local imports
from core.ml.feature_extraction import FeatureExtractor

class ModelTrainer:
    """
    Trains machine learning models for security analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the model trainer with optional configuration.
        
        Args:
            config: Configuration dictionary with training parameters
        """
        self.config = config or {}
        self.logger = logging.getLogger("ModelTrainer")
        
        # Set default model directory
        self.model_dir = self.config.get("model_dir", "models")
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor(self.config.get("feature_extraction"))
        
        # Set default training parameters
        self.training_params = self.config.get("training_params", {
            "test_size": 0.2,
            "random_state": 42,
            "n_jobs": -1  # Use all available cores
        })
    
    def train_anomaly_detection_model(self, 
                                      data: List[Dict[str, Any]], 
                                      model_name: str = "anomaly_detection") -> Dict[str, Any]:
        """
        Train an anomaly detection model using unsupervised learning.
        
        Args:
            data: List of content items to extract features from
            model_name: Name to save the model under
            
        Returns:
            Dictionary with training results and model metadata
        """
        self.logger.info(f"Training anomaly detection model '{model_name}' with {len(data)} samples")
        
        # Extract features
        features_data = self.feature_extractor.extract_features_batch(data)
        feature_vectors = [item["feature_vector"] for item in features_data]
        
        # Convert to numpy array
        X = np.array(feature_vectors)
        
        # Create and train the model
        model = Pipeline([
            ('scaler', StandardScaler()),
            ('isolation_forest', IsolationForest(
                n_estimators=self.config.get("anomaly_detection", {}).get("n_estimators", 100),
                contamination=self.config.get("anomaly_detection", {}).get("contamination", 0.1),
                random_state=self.training_params.get("random_state"),
                n_jobs=self.training_params.get("n_jobs")
            ))
        ])
        
        model.fit(X)
        
        # Get anomaly scores for the training data
        # Convert predictions (-1 for outliers, 1 for inliers) to anomaly scores (higher means more anomalous)
        raw_predictions = model.predict(X)
        anomaly_scores = model.decision_function(X)
        # Convert to anomaly scores (higher is more anomalous)
        anomaly_scores = -anomaly_scores
        
        # Calculate threshold based on contamination
        contamination = self.config.get("anomaly_detection", {}).get("contamination", 0.1)
        threshold = np.percentile(anomaly_scores, 100 * (1 - contamination))
        
        # Save the model
        model_path = os.path.join(self.model_dir, f"{model_name}.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Save model metadata
        metadata = {
            "model_type": "anomaly_detection",
            "algorithm": "isolation_forest",
            "training_date": datetime.now().isoformat(),
            "num_samples": len(data),
            "feature_version": self.feature_extractor.feature_version,
            "parameters": {
                "n_estimators": self.config.get("anomaly_detection", {}).get("n_estimators", 100),
                "contamination": contamination
            },
            "threshold": float(threshold),
            "performance": {
                "num_anomalies_detected": int(np.sum(raw_predictions == -1)),
                "anomaly_ratio": float(np.mean(raw_predictions == -1))
            }
        }
        
        metadata_path = os.path.join(self.model_dir, f"{model_name}_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Anomaly detection model trained and saved to {model_path}")
        
        return {
            "model": model,
            "metadata": metadata,
            "model_path": model_path,
            "metadata_path": metadata_path
        }
    
    def train_false_positive_model(self, 
                                  data: List[Dict[str, Any]], 
                                  labels: List[int],
                                  model_name: str = "false_positive_classifier") -> Dict[str, Any]:
        """
        Train a supervised model for false positive reduction.
        
        Args:
            data: List of content items to extract features from
            labels: Binary labels (1 for true positive, 0 for false positive)
            model_name: Name to save the model under
            
        Returns:
            Dictionary with training results and model metadata
        """
        self.logger.info(f"Training false positive classifier '{model_name}' with {len(data)} samples")
        
        if len(data) != len(labels):
            raise ValueError(f"Data length ({len(data)}) must match labels length ({len(labels)})")
        
        # Extract features
        features_data = self.feature_extractor.extract_features_batch(data)
        feature_vectors = [item["feature_vector"] for item in features_data]
        
        # Convert to numpy arrays
        X = np.array(feature_vectors)
        y = np.array(labels)
        
        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.training_params.get("test_size"), 
            random_state=self.training_params.get("random_state"),
            stratify=y  # Ensure balanced classes in train/test
        )
        
        # Define the model pipeline
        model = Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(
                n_estimators=self.config.get("false_positive", {}).get("n_estimators", 100),
                max_depth=self.config.get("false_positive", {}).get("max_depth", None),
                random_state=self.training_params.get("random_state"),
                n_jobs=self.training_params.get("n_jobs")
            ))
        ])
        
        # Train the model
        model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
        
        # Get feature importances
        feature_names = self.feature_extractor.get_feature_names()
        feature_importances = model.named_steps['classifier'].feature_importances_
        
        # Sort feature importances
        sorted_idx = np.argsort(feature_importances)[::-1]
        top_features = [(feature_names[i], float(feature_importances[i])) 
                         for i in sorted_idx[:10]]  # Top 10 features
        
        # Save the model
        model_path = os.path.join(self.model_dir, f"{model_name}.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Save model metadata
        metadata = {
            "model_type": "false_positive_classifier",
            "algorithm": "random_forest",
            "training_date": datetime.now().isoformat(),
            "num_samples": len(data),
            "feature_version": self.feature_extractor.feature_version,
            "parameters": {
                "n_estimators": self.config.get("false_positive", {}).get("n_estimators", 100),
                "max_depth": self.config.get("false_positive", {}).get("max_depth", None)
            },
            "performance": {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1)
            },
            "top_features": top_features
        }
        
        metadata_path = os.path.join(self.model_dir, f"{model_name}_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"False positive classifier trained and saved to {model_path}")
        
        return {
            "model": model,
            "metadata": metadata,
            "model_path": model_path,
            "metadata_path": metadata_path,
            "performance": {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            },
            "feature_importances": dict(top_features)
        }
    
    def perform_hyperparameter_tuning(self, 
                                     data: List[Dict[str, Any]], 
                                     labels: Optional[List[int]] = None,
                                     model_type: str = "false_positive") -> Dict[str, Any]:
        """
        Perform hyperparameter tuning for a model.
        
        Args:
            data: List of content items to extract features from
            labels: Binary labels (required for supervised models)
            model_type: Type of model to tune ('anomaly_detection' or 'false_positive')
            
        Returns:
            Dictionary with tuning results and best parameters
        """
        self.logger.info(f"Performing hyperparameter tuning for {model_type} model")
        
        # Extract features
        features_data = self.feature_extractor.extract_features_batch(data)
        feature_vectors = [item["feature_vector"] for item in features_data]
        
        # Convert to numpy array
        X = np.array(feature_vectors)
        
        if model_type == "false_positive":
            if labels is None:
                raise ValueError("Labels are required for false positive model tuning")
            
            y = np.array(labels)
            
            # Split into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=self.training_params.get("test_size"), 
                random_state=self.training_params.get("random_state"),
                stratify=y
            )
            
            # Define the model pipeline
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', RandomForestClassifier())
            ])
            
            # Define the parameter grid
            param_grid = {
                'classifier__n_estimators': [50, 100, 200],
                'classifier__max_depth': [None, 10, 20, 30],
                'classifier__min_samples_split': [2, 5, 10],
                'classifier__min_samples_leaf': [1, 2, 4]
            }
            
            # Create the grid search
            grid_search = GridSearchCV(
                pipeline, 
                param_grid, 
                cv=5, 
                scoring='f1',
                n_jobs=self.training_params.get("n_jobs"),
                verbose=1
            )
            
            # Perform the grid search
            grid_search.fit(X_train, y_train)
            
            # Evaluate the best model
            best_model = grid_search.best_estimator_
            y_pred = best_model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
            
            return {
                "best_params": grid_search.best_params_,
                "best_score": grid_search.best_score_,
                "performance": {
                    "accuracy": float(accuracy),
                    "precision": float(precision),
                    "recall": float(recall),
                    "f1_score": float(f1)
                }
            }
            
        elif model_type == "anomaly_detection":
            # Define the model pipeline
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('isolation_forest', IsolationForest())
            ])
            
            # Define the parameter grid
            param_grid = {
                'isolation_forest__n_estimators': [50, 100, 200],
                'isolation_forest__contamination': [0.05, 0.1, 0.15],
                'isolation_forest__max_samples': ['auto', 100, 200]
            }
            
            # For unsupervised models, we need a custom scoring function
            # This is a simplified example - in practice, you would need a more sophisticated approach
            def custom_scorer(estimator, X):
                # Get anomaly scores
                scores = -estimator.decision_function(X)
                # Higher variance in scores is better (more discriminative)
                return np.var(scores)
            
            # Create the grid search
            grid_search = GridSearchCV(
                pipeline, 
                param_grid, 
                cv=5, 
                scoring=custom_scorer,
                n_jobs=self.training_params.get("n_jobs"),
                verbose=1
            )
            
            # Perform the grid search
            grid_search.fit(X)
            
            return {
                "best_params": grid_search.best_params_,
                "best_score": grid_search.best_score_
            }
        
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def generate_training_data_from_findings(self, 
                                           findings: List[Dict[str, Any]], 
                                           content_items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[int]]:
        """
        Generate training data from existing findings.
        
        Args:
            findings: List of finding dictionaries
            content_items: List of content item dictionaries
            
        Returns:
            Tuple of (data, labels) for training
        """
        data = []
        labels = []
        
        # Create a mapping from content_id to content_item for efficient lookup
        content_map = {item.get("processed_id", ""): item for item in content_items}
        
        for finding in findings:
            content_id = finding.get("content_id")
            if not content_id or content_id not in content_map:
                continue
            
            content_item = content_map[content_id]
            
            # Label is 0 for false positive, 1 for true positive
            is_false_positive = finding.get("false_positive_likelihood", 0) > 0.7
            label = 0 if is_false_positive else 1
            
            data.append(content_item)
            labels.append(label)
        
        return data, labels