#!/usr/bin/env python
"""
Create Placeholder ML Models

This script creates placeholder ML model files to prevent warnings during execution.
In a production environment, these would be actual trained models.
"""

import os
import sys
import pickle
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def create_placeholder_models():
    """Create placeholder ML model files."""
    try:
        # Ensure the models directory exists
        models_dir = os.path.join(project_root, "models")
        os.makedirs(models_dir, exist_ok=True)
        
        # Create placeholder anomaly detection model
        anomaly_model_path = os.path.join(models_dir, "anomaly_detection.pkl")
        if not os.path.exists(anomaly_model_path):
            # Simple placeholder model (just a dictionary with configuration)
            anomaly_model = {
                "model_type": "placeholder",
                "description": "Placeholder anomaly detection model",
                "version": "0.1.0",
                "created_at": "2025-05-07",
                "parameters": {
                    "threshold": 0.8,
                    "features": ["content_length", "entropy", "special_char_ratio"]
                }
            }
            with open(anomaly_model_path, 'wb') as f:
                pickle.dump(anomaly_model, f)
            print(f"Created placeholder anomaly detection model at {anomaly_model_path}")
        
        # Create placeholder false positive classifier model
        fp_model_path = os.path.join(models_dir, "false_positive_classifier.pkl")
        if not os.path.exists(fp_model_path):
            # Simple placeholder model
            fp_model = {
                "model_type": "placeholder",
                "description": "Placeholder false positive classifier model",
                "version": "0.1.0",
                "created_at": "2025-05-07",
                "parameters": {
                    "threshold": 0.7,
                    "features": ["finding_type", "context", "pattern_match_length"]
                }
            }
            with open(fp_model_path, 'wb') as f:
                pickle.dump(fp_model, f)
            print(f"Created placeholder false positive classifier model at {fp_model_path}")
        
        print("Placeholder models created successfully.")
    except Exception as e:
        print(f"Error creating placeholder models: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    create_placeholder_models()