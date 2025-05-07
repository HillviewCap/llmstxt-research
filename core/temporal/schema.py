"""
Schema extensions for temporal analysis features.

This module defines additional database tables needed for:
- Content versioning
- Change detection
- Historical trend tracking
"""

from sqlalchemy import (
    Column, Integer, Float, String, Text, DateTime, Boolean, ForeignKey, JSON, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from core.database.schema import Base

class ContentVersion(Base):
    """
    Tracks versions of content for temporal analysis.
    Extends the existing ProcessedMarkdownContent table with version information.
    """
    __tablename__ = "content_versions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    content_hash = Column(String(64), nullable=False, index=True)  # SHA256 hash of content
    version_number = Column(Integer, nullable=False)  # Incremental version number
    timestamp = Column(DateTime, nullable=False, server_default=func.now())
    raw_content = Column(Text, nullable=True)  # Optional storage of raw content
    processed_content_id = Column(Integer, ForeignKey("processed_markdown_content.id"), nullable=True)
    
    # Relationships
    url_source = relationship("Urls", backref="content_versions")
    processed_content = relationship("ProcessedMarkdownContent", backref="version_info")
    changes = relationship("ContentChange", back_populates="version")
    
    __table_args__ = (
        Index("idx_url_version", "url_id", "version_number", unique=True),
    )


class ContentChange(Base):
    """
    Records specific changes between content versions.
    """
    __tablename__ = "content_changes"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    version_id = Column(Integer, ForeignKey("content_versions.id"), nullable=False)
    previous_version_id = Column(Integer, ForeignKey("content_versions.id"), nullable=True)
    change_type = Column(String(50), nullable=False)  # 'addition', 'deletion', 'modification'
    section_type = Column(String(50), nullable=False)  # 'text', 'code_block', 'url', etc.
    location = Column(JSON, nullable=True)  # JSON object describing location in document
    content_before = Column(Text, nullable=True)
    content_after = Column(Text, nullable=True)
    change_size = Column(Integer, nullable=True)  # Size of change in characters or lines
    suspicion_score = Column(Float, nullable=True)  # Score indicating how suspicious the change is
    
    # Relationships
    version = relationship("ContentVersion", foreign_keys=[version_id], back_populates="changes")
    previous_version = relationship("ContentVersion", foreign_keys=[previous_version_id])


class HistoricalRiskScore(Base):
    """
    Tracks risk scores over time for trend analysis.
    """
    __tablename__ = "historical_risk_scores"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    version_id = Column(Integer, ForeignKey("content_versions.id"), nullable=True)
    analysis_id = Column(Integer, ForeignKey("security_analysis_results.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False, server_default=func.now())
    overall_risk_score = Column(Float, nullable=False)
    malicious_confidence = Column(Float, nullable=False)
    markdown_risk = Column(Float, nullable=True)
    pattern_risk = Column(Float, nullable=True)
    secrets_risk = Column(Float, nullable=True)
    static_risk = Column(Float, nullable=True)
    
    # Relationships
    url_source = relationship("Urls", backref="historical_scores")
    version = relationship("ContentVersion", backref="risk_scores")
    analysis = relationship("SecurityAnalysisResult", backref="historical_record")


class TemporalAnomaly(Base):
    """
    Records detected anomalies in content changes or risk score trends.
    """
    __tablename__ = "temporal_anomalies"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    detection_timestamp = Column(DateTime, nullable=False, server_default=func.now())
    anomaly_type = Column(String(50), nullable=False)  # 'sudden_change', 'gradual_drift', etc.
    severity = Column(String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    start_version_id = Column(Integer, ForeignKey("content_versions.id"), nullable=True)
    end_version_id = Column(Integer, ForeignKey("content_versions.id"), nullable=True)
    
    # Relationships
    url_source = relationship("Urls", backref="temporal_anomalies")
    start_version = relationship("ContentVersion", foreign_keys=[start_version_id])
    end_version = relationship("ContentVersion", foreign_keys=[end_version_id])


def create_temporal_schema(engine):
    """
    Create the temporal analysis tables in the database.
    """
    Base.metadata.create_all(engine, tables=[
        ContentVersion.__table__,
        ContentChange.__table__,
        HistoricalRiskScore.__table__,
        TemporalAnomaly.__table__
    ])