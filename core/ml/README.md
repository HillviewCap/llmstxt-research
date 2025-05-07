# Machine Learning Enhancement Module

This module implements machine learning capabilities for the AI Code Agent Security Analysis Platform, as specified in Milestone 11 of the implementation roadmap.

## Overview

The ML module enhances the security analysis platform with:

1. **ML Model Integration** - A complete pipeline for training, evaluating, and using ML models
2. **Anomaly Detection** - Unsupervised learning for detecting anomalies in content
3. **False Positive Reduction** - Supervised learning for reducing false positives

## Components

### Feature Extraction (`feature_extraction.py`)

Extracts features from content for use in machine learning models:
- Text-based features (statistics, patterns)
- Code structure features
- Markdown structure features
- Security indicator features
- Metadata features

### Model Training (`model_training.py`)

Provides functionality to train machine learning models:
- Anomaly detection models using unsupervised learning (Isolation Forest)
- False positive classification models using supervised learning (Random Forest)
- Hyperparameter tuning
- Training data generation from existing findings

### Model Evaluation (`model_evaluation.py`)

Evaluates machine learning models and tracks performance:
- Evaluation metrics for anomaly detection (AUC, precision, recall)
- Evaluation metrics for false positive classification (accuracy, precision, recall, F1)
- Performance visualization
- Performance tracking over time

### Anomaly Detection (`anomaly_detection.py`)

Detects anomalies in content using unsupervised learning:
- Isolation Forest for anomaly detection
- Normal behavior modeling
- Outlier detection based on statistical analysis
- Confidence scoring for detected anomalies

### False Positive Reduction (`false_positive_reduction.py`)

Reduces false positives using supervised learning:
- Classification of findings as true or false positives
- Feature importance analysis
- Feedback integration for continuous learning
- Model performance tracking

### Integration (`integration.py`)

Integrates ML components into the main analysis pipeline:
- Unified interface for ML-based analysis
- Database integration for storing and retrieving ML results
- Training and evaluation orchestration
- Feedback processing

### Database Utilities (`db_utils.py`)

Provides database utilities for ML components:
- Storing and retrieving model metadata
- Tracking model performance
- Storing and retrieving feedback
- Storing anomaly detection results

### Database Schema (`schema.py`)

Defines the database schema for ML components:
- ML model metadata
- Model performance tracking
- Feedback storage
- Anomaly detection results

## Usage

The ML module is integrated into the main pipeline and is automatically used during analysis. The `MLAnalysis` class in `integration.py` provides the main interface for using the ML components.

### Basic Usage

```python
from core.ml.integration import MLAnalysis

# Initialize ML analysis with database connector
ml_analyzer = MLAnalysis(config, db_connector)

# Perform ML-based analysis on content items and findings
ml_results = ml_analyzer.analyze(content_items, findings)

# Process feedback for continuous learning
feedback_result = ml_analyzer.process_feedback({
    "finding_id": 123,
    "is_true_positive": False,
    "content_id": 456
})

# Train ML models
training_result = ml_analyzer.train_models(use_db_data=True)

# Evaluate ML models
evaluation_result = ml_analyzer.evaluate_models(use_db_data=True)
```

## Database Schema

The ML module extends the database schema with the following tables:

- `ml_models` - Stores metadata about trained ML models
- `ml_model_performance` - Tracks performance of ML models over time
- `ml_feedback` - Stores feedback for continuous learning
- `ml_anomaly_detection` - Stores anomaly detection results

## Dependencies

The ML module requires the following dependencies:

- scikit-learn>=1.3.0
- numpy>=1.20.0
- matplotlib>=3.5.0 (for visualization)
- sqlalchemy>=2.0.0 (for database integration)