"""
Database Utilities for ML Components

This module provides database utility functions for ML components,
including storing and retrieving ML model metadata, performance metrics,
feedback, and anomaly detection results.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

from sqlalchemy import select, update, insert, delete
from sqlalchemy.exc import SQLAlchemyError

from core.database.connector import DatabaseConnector
from core.ml.schema import MLModel, MLModelPerformance, MLFeedback, MLAnomalyDetection

class MLDatabaseUtils:
    """
    Database utilities for ML components.
    """
    
    def __init__(self, db_connector: DatabaseConnector):
        """
        Initialize the ML database utilities.
        
        Args:
            db_connector: Database connector instance
        """
        self.db = db_connector
        self.logger = logging.getLogger("MLDatabaseUtils")
    
    def store_model_metadata(self, model_data: Dict[str, Any]) -> int:
        """
        Store ML model metadata in the database.
        
        Args:
            model_data: Dictionary with model metadata
                Required keys: model_name, model_type, version
                Optional keys: parameters, performance_metrics, feature_version
                
        Returns:
            ID of the stored model
        """
        try:
            # Check if model with same name and version already exists
            with self.db.session_scope() as session:
                existing_model = session.query(MLModel).filter_by(
                    model_name=model_data["model_name"],
                    version=model_data["version"]
                ).first()
                
                if existing_model:
                    # Update existing model
                    for key, value in model_data.items():
                        if key not in ["id", "created_at"]:
                            setattr(existing_model, key, value)
                    existing_model.updated_at = datetime.now()
                    session.commit()
                    return existing_model.id
                else:
                    # Create new model
                    new_model = MLModel(
                        model_name=model_data["model_name"],
                        model_type=model_data["model_type"],
                        version=model_data["version"],
                        parameters=model_data.get("parameters"),
                        performance_metrics=model_data.get("performance_metrics"),
                        feature_version=model_data.get("feature_version")
                    )
                    session.add(new_model)
                    session.commit()
                    return new_model.id
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing model metadata: {e}")
            raise
    
    def get_model_metadata(self, model_name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get ML model metadata from the database.
        
        Args:
            model_name: Name of the model
            version: Optional version of the model (if None, returns the latest version)
                
        Returns:
            Dictionary with model metadata or None if not found
        """
        try:
            with self.db.session_scope() as session:
                query = session.query(MLModel).filter_by(model_name=model_name)
                
                if version:
                    query = query.filter_by(version=version)
                else:
                    # Get the latest version
                    query = query.order_by(MLModel.version.desc())
                
                model = query.first()
                
                if model:
                    return {
                        "id": model.id,
                        "model_name": model.model_name,
                        "model_type": model.model_type,
                        "version": model.version,
                        "created_at": model.created_at,
                        "updated_at": model.updated_at,
                        "parameters": model.parameters,
                        "performance_metrics": model.performance_metrics,
                        "feature_version": model.feature_version
                    }
                return None
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting model metadata: {e}")
            raise
    
    def store_model_performance(self, performance_data: Dict[str, Any]) -> int:
        """
        Store ML model performance metrics in the database.
        
        Args:
            performance_data: Dictionary with performance metrics
                Required keys: model_id
                Optional keys: accuracy, precision, recall, f1_score, false_positive_rate,
                              true_positive_rate, auc, num_samples, additional_metrics
                
        Returns:
            ID of the stored performance entry
        """
        try:
            with self.db.session_scope() as session:
                new_performance = MLModelPerformance(
                    model_id=performance_data["model_id"],
                    timestamp=datetime.now(),
                    accuracy=performance_data.get("accuracy"),
                    precision=performance_data.get("precision"),
                    recall=performance_data.get("recall"),
                    f1_score=performance_data.get("f1_score"),
                    false_positive_rate=performance_data.get("false_positive_rate"),
                    true_positive_rate=performance_data.get("true_positive_rate"),
                    auc=performance_data.get("auc"),
                    num_samples=performance_data.get("num_samples"),
                    additional_metrics=performance_data.get("additional_metrics")
                )
                session.add(new_performance)
                session.commit()
                return new_performance.id
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing model performance: {e}")
            raise
    
    def get_model_performance_history(self, model_id: int) -> List[Dict[str, Any]]:
        """
        Get ML model performance history from the database.
        
        Args:
            model_id: ID of the model
                
        Returns:
            List of dictionaries with performance metrics
        """
        try:
            with self.db.session_scope() as session:
                performance_entries = session.query(MLModelPerformance).filter_by(
                    model_id=model_id
                ).order_by(MLModelPerformance.timestamp.desc()).all()
                
                return [{
                    "id": entry.id,
                    "model_id": entry.model_id,
                    "timestamp": entry.timestamp,
                    "accuracy": entry.accuracy,
                    "precision": entry.precision,
                    "recall": entry.recall,
                    "f1_score": entry.f1_score,
                    "false_positive_rate": entry.false_positive_rate,
                    "true_positive_rate": entry.true_positive_rate,
                    "auc": entry.auc,
                    "num_samples": entry.num_samples,
                    "additional_metrics": entry.additional_metrics
                } for entry in performance_entries]
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting model performance history: {e}")
            raise
    
    def store_feedback(self, feedback_data: Dict[str, Any]) -> int:
        """
        Store feedback for continuous learning.
        
        Args:
            feedback_data: Dictionary with feedback data
                Required keys: finding_id, is_true_positive, content_id
                Optional keys: feedback_source, notes
                
        Returns:
            ID of the stored feedback entry
        """
        try:
            with self.db.session_scope() as session:
                new_feedback = MLFeedback(
                    finding_id=feedback_data["finding_id"],
                    is_true_positive=feedback_data["is_true_positive"],
                    content_id=feedback_data["content_id"],
                    timestamp=datetime.now(),
                    feedback_source=feedback_data.get("feedback_source", "user"),
                    notes=feedback_data.get("notes")
                )
                session.add(new_feedback)
                session.commit()
                return new_feedback.id
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing feedback: {e}")
            raise
    
    def get_feedback(self, finding_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback from the database.
        
        Args:
            finding_id: Optional ID of the finding to get feedback for
            limit: Maximum number of feedback entries to return
                
        Returns:
            List of dictionaries with feedback data
        """
        try:
            with self.db.session_scope() as session:
                query = session.query(MLFeedback)
                
                if finding_id:
                    query = query.filter_by(finding_id=finding_id)
                
                feedback_entries = query.order_by(MLFeedback.timestamp.desc()).limit(limit).all()
                
                return [{
                    "id": entry.id,
                    "finding_id": entry.finding_id,
                    "is_true_positive": entry.is_true_positive,
                    "content_id": entry.content_id,
                    "timestamp": entry.timestamp,
                    "feedback_source": entry.feedback_source,
                    "notes": entry.notes
                } for entry in feedback_entries]
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting feedback: {e}")
            raise
    
    def store_anomaly_detection_result(self, result_data: Dict[str, Any]) -> int:
        """
        Store anomaly detection result in the database.
        
        Args:
            result_data: Dictionary with anomaly detection result
                Required keys: content_id, is_anomalous, anomaly_score, confidence
                Optional keys: model_version, contributing_factors
                
        Returns:
            ID of the stored result
        """
        try:
            with self.db.session_scope() as session:
                new_result = MLAnomalyDetection(
                    content_id=result_data["content_id"],
                    timestamp=datetime.now(),
                    is_anomalous=result_data["is_anomalous"],
                    anomaly_score=result_data["anomaly_score"],
                    confidence=result_data["confidence"],
                    model_version=result_data.get("model_version"),
                    contributing_factors=result_data.get("contributing_factors")
                )
                session.add(new_result)
                session.commit()
                return new_result.id
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing anomaly detection result: {e}")
            raise
    
    def get_anomaly_detection_results(self, content_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get anomaly detection results from the database.
        
        Args:
            content_id: Optional ID of the content to get results for
            limit: Maximum number of results to return
                
        Returns:
            List of dictionaries with anomaly detection results
        """
        try:
            with self.db.session_scope() as session:
                query = session.query(MLAnomalyDetection)
                
                if content_id:
                    query = query.filter_by(content_id=content_id)
                
                results = query.order_by(MLAnomalyDetection.timestamp.desc()).limit(limit).all()
                
                return [{
                    "id": result.id,
                    "content_id": result.content_id,
                    "timestamp": result.timestamp,
                    "is_anomalous": result.is_anomalous,
                    "anomaly_score": result.anomaly_score,
                    "confidence": result.confidence,
                    "model_version": result.model_version,
                    "contributing_factors": result.contributing_factors
                } for result in results]
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting anomaly detection results: {e}")
            raise
    
    def update_finding_false_positive_likelihood(self, finding_id: int, false_positive_likelihood: float) -> bool:
        """
        Update the false positive likelihood of a finding.
        
        Args:
            finding_id: ID of the finding
            false_positive_likelihood: New false positive likelihood value
                
        Returns:
            True if the update was successful, False otherwise
        """
        try:
            with self.db.session_scope() as session:
                # Import here to avoid circular imports
                from core.database.schema import SecurityFinding
                
                finding = session.query(SecurityFinding).filter_by(id=finding_id).first()
                
                if finding:
                    finding.false_positive_likelihood = false_positive_likelihood
                    session.commit()
                    return True
                return False
        except SQLAlchemyError as e:
            self.logger.error(f"Error updating finding false positive likelihood: {e}")
            raise
    
    def get_content_by_id(self, content_id: int) -> Optional[Dict[str, Any]]:
        """
        Get content item by ID.
        
        Args:
            content_id: ID of the content item
                
        Returns:
            Dictionary with content item data or None if not found
        """
        try:
            with self.db.session_scope() as session:
                # Import here to avoid circular imports
                from core.database.schema import ProcessedMarkdownContent, Urls
                
                content = session.query(ProcessedMarkdownContent).filter_by(id=content_id).first()
                
                if content:
                    url = session.query(Urls).filter_by(id=content.url_id).first()
                    
                    return {
                        "processed_id": content.id,
                        "url_id": content.url_id,
                        "url": url.url_string if url else None,
                        "raw_content_hash": content.raw_content_hash,
                        "fetched_timestamp": content.fetched_timestamp,
                        "parsed_timestamp": content.parsed_timestamp,
                        "normalized_representation": content.normalized_representation,
                        "document_structure_summary": content.document_structure_summary
                    }
                return None
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting content by ID: {e}")
            raise
    
    def get_finding_by_id(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """
        Get finding by ID.
        
        Args:
            finding_id: ID of the finding
                
        Returns:
            Dictionary with finding data or None if not found
        """
        try:
            with self.db.session_scope() as session:
                # Import here to avoid circular imports
                from core.database.schema import SecurityFinding
                
                finding = session.query(SecurityFinding).filter_by(id=finding_id).first()
                
                if finding:
                    return {
                        "id": finding.id,
                        "analysis_id": finding.analysis_id,
                        "finding_type": finding.finding_type,
                        "severity": finding.severity,
                        "description": finding.description,
                        "location": finding.location,
                        "evidence": finding.evidence,
                        "false_positive_likelihood": finding.false_positive_likelihood,
                        "remediation_suggestion": finding.remediation_suggestion
                    }
                return None
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting finding by ID: {e}")
            raise
    
    def get_all_content_items(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get all content items from the database.
        
        Args:
            limit: Maximum number of content items to return
                
        Returns:
            List of dictionaries with content item data
        """
        try:
            with self.db.session_scope() as session:
                # Import here to avoid circular imports
                from core.database.schema import ProcessedMarkdownContent, Urls
                
                content_items = session.query(
                    ProcessedMarkdownContent, Urls
                ).join(
                    Urls, ProcessedMarkdownContent.url_id == Urls.id
                ).limit(limit).all()
                
                return [{
                    "processed_id": content.id,
                    "url_id": content.url_id,
                    "url": url.url_string,
                    "raw_content_hash": content.raw_content_hash,
                    "fetched_timestamp": content.fetched_timestamp,
                    "parsed_timestamp": content.parsed_timestamp,
                    "normalized_representation": content.normalized_representation,
                    "document_structure_summary": content.document_structure_summary
                } for content, url in content_items]
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting all content items: {e}")
            raise
    
    def get_all_findings(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get all findings from the database.
        
        Args:
            limit: Maximum number of findings to return
                
        Returns:
            List of dictionaries with finding data
        """
        try:
            with self.db.session_scope() as session:
                # Import here to avoid circular imports
                from core.database.schema import SecurityFinding
                
                findings = session.query(SecurityFinding).limit(limit).all()
                
                return [{
                    "id": finding.id,
                    "analysis_id": finding.analysis_id,
                    "finding_type": finding.finding_type,
                    "severity": finding.severity,
                    "description": finding.description,
                    "location": finding.location,
                    "evidence": finding.evidence,
                    "false_positive_likelihood": finding.false_positive_likelihood,
                    "remediation_suggestion": finding.remediation_suggestion
                } for finding in findings]
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting all findings: {e}")
            raise