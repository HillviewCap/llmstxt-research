"""
Database Schema for ML Components

This module defines the database schema for ML model metadata and performance tracking.
"""

from sqlalchemy import (
    Column, Integer, Float, String, Text, DateTime, Boolean, ForeignKey, JSON, Index
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

# Import the Base from the main schema
from core.database.schema import Base

class MLModel(Base):
    """
    Stores metadata about trained ML models.
    """
    __tablename__ = "ml_models"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_name = Column(String(100), nullable=False)
    model_type = Column(String(50), nullable=False)  # 'anomaly_detection', 'false_positive_classifier', etc.
    version = Column(String(20), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
    parameters = Column(JSON, nullable=True)  # Model hyperparameters
    performance_metrics = Column(JSON, nullable=True)  # Performance metrics from training
    feature_version = Column(String(20), nullable=True)  # Version of feature extraction used
    
    # Relationships
    performance_entries = relationship("MLModelPerformance", back_populates="model")
    
    __table_args__ = (
        Index("idx_model_name_version", "model_name", "version"),
    )


class MLModelPerformance(Base):
    """
    Tracks performance of ML models over time.
    """
    __tablename__ = "ml_model_performance"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_id = Column(Integer, ForeignKey("ml_models.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, server_default=func.now())
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    true_positive_rate = Column(Float, nullable=True)
    auc = Column(Float, nullable=True)  # Area Under ROC Curve
    num_samples = Column(Integer, nullable=True)  # Number of samples used for evaluation
    additional_metrics = Column(JSON, nullable=True)  # Any additional metrics
    
    # Relationships
    model = relationship("MLModel", back_populates="performance_entries")


class MLFeedback(Base):
    """
    Stores feedback for continuous learning.
    """
    __tablename__ = "ml_feedback"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("security_findings.id"), nullable=False)
    is_true_positive = Column(Boolean, nullable=False)
    timestamp = Column(DateTime, nullable=False, server_default=func.now())
    content_id = Column(Integer, ForeignKey("processed_markdown_content.id"), nullable=False)
    feedback_source = Column(String(50), nullable=True)  # 'user', 'automated', etc.
    notes = Column(Text, nullable=True)
    
    # Relationships
    finding = relationship("SecurityFinding")
    content = relationship("ProcessedMarkdownContent")


class MLAnomalyDetection(Base):
    """
    Stores anomaly detection results.
    """
    __tablename__ = "ml_anomaly_detection"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    content_id = Column(Integer, ForeignKey("processed_markdown_content.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, server_default=func.now())
    is_anomalous = Column(Boolean, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    model_version = Column(String(20), nullable=True)
    contributing_factors = Column(JSON, nullable=True)
    
    # Relationships
    content = relationship("ProcessedMarkdownContent")
    
    __table_args__ = (
        Index("idx_content_id_timestamp", "content_id", "timestamp"),
    )


def create_ml_schema(engine):
    """
    Create or extend the database schema for ML tables.
    """
    Base.metadata.create_all(engine)