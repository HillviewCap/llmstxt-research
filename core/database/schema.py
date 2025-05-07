from sqlalchemy import (
    Column, Integer, Float, String, Text, DateTime, Boolean, ForeignKey
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.engine import Engine

Base = declarative_base()

class SecurityAnalysisResult(Base):
    __tablename__ = "security_analysis_results"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    analysis_timestamp = Column(DateTime, nullable=False)
    overall_risk_score = Column(Float, nullable=False)
    malicious_confidence = Column(Float, nullable=False)
    analysis_version = Column(String, nullable=False)

    findings = relationship("SecurityFinding", back_populates="analysis_result")

class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("security_analysis_results.id"), nullable=False)
    finding_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    location = Column(Text)
    evidence = Column(Text)
    false_positive_likelihood = Column(Float)
    remediation_suggestion = Column(Text)

    analysis_result = relationship("SecurityAnalysisResult", back_populates="findings")

class CodeBlock(Base):
    __tablename__ = "code_blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    language = Column(String)
    content = Column(Text, nullable=False)
    line_start = Column(Integer)
    line_end = Column(Integer)
    context = Column(Text)

class AnalysisHistory(Base):
    __tablename__ = "analysis_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    analysis_timestamp = Column(DateTime, nullable=False)
    changes_detected = Column(Boolean, nullable=False)
    change_summary = Column(Text)

def create_security_schema(engine: Engine):
    """
    Create or extend the database schema for security analysis tables.
    """
    Base.metadata.create_all(engine)