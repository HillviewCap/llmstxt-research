"""
Machine Learning Module for Security Analysis

This package provides machine learning capabilities for the security analysis platform,
including anomaly detection, false positive reduction, and feature extraction.

Components:
- feature_extraction: Extracts features from content for ML models
- model_training: Trains ML models for security analysis
- model_evaluation: Evaluates ML models for security analysis
- anomaly_detection: Detects anomalies in content using unsupervised learning
- false_positive_reduction: Reduces false positives using supervised learning
- integration: Integrates ML components into the main analysis pipeline
"""

from core.ml.feature_extraction import FeatureExtractor
from core.ml.anomaly_detection import AnomalyDetector
from core.ml.false_positive_reduction import FalsePositiveReducer
from core.ml.integration import MLAnalysis

__all__ = [
    'FeatureExtractor',
    'AnomalyDetector',
    'FalsePositiveReducer',
    'MLAnalysis'
]