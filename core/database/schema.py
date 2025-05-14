from sqlalchemy import (
    Column,
    Integer,
    Float,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func  # For server-side default timestamps
from sqlalchemy.engine import Engine

Base = declarative_base()


# New Urls table (central registry for URLs)
class Urls(Base):
    __tablename__ = "urls"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_string = Column(String(2048), nullable=False, unique=True, index=True)
    first_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    last_accessed_at = Column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    processed_contents = relationship(
        "ProcessedMarkdownContent", back_populates="url_source"
    )
    code_blocks = relationship("CodeBlock", back_populates="url_source")
    analysis_results = relationship(
        "SecurityAnalysisResult", back_populates="url_source"
    )
    analysis_history_entries = relationship(
        "AnalysisHistory", back_populates="url_source"
    )


# New ProcessedMarkdownContent table
class ProcessedMarkdownContent(Base):
    __tablename__ = "processed_markdown_content"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(Integer, ForeignKey("urls.id"), nullable=False)
    raw_content_hash = Column(String(64), nullable=False, index=True)  # e.g., SHA256
    fetched_timestamp = Column(DateTime, nullable=False, server_default=func.now())
    parsed_timestamp = Column(DateTime, nullable=False, server_default=func.now())
    # Storing as JSON as it's flexible for structured data from the parser
    normalized_representation = Column(JSON, nullable=True)
    document_structure_summary = Column(JSON, nullable=True)
    raw_markdown_text = Column(Text, nullable=True)

    url_source = relationship("Urls", back_populates="processed_contents")
    # Relationships to items extracted from this specific processed content
    extracted_code_blocks = relationship(
        "CodeBlock", back_populates="processed_content_source"
    )
    extracted_items = relationship(
        "ExtractedItems", back_populates="processed_content_source"
    )

    __table_args__ = (Index("idx_url_id_hash", "url_id", "raw_content_hash"),)


class SecurityAnalysisResult(Base):
    __tablename__ = "security_analysis_results"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(
        Integer, ForeignKey("urls.id"), nullable=False
    )  # References the new Urls table
    analysis_timestamp = Column(DateTime, nullable=False, server_default=func.now())
    overall_risk_score = Column(Float, nullable=False)
    malicious_confidence = Column(Float, nullable=False)
    analysis_version = Column(String, nullable=False)

    findings = relationship("SecurityFinding", back_populates="analysis_result")
    url_source = relationship("Urls", back_populates="analysis_results")


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(
        Integer, ForeignKey("security_analysis_results.id"), nullable=False
    )
    finding_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    location = Column(Text)  # Could be JSON for structured location
    evidence = Column(Text)
    false_positive_likelihood = Column(Float)
    remediation_suggestion = Column(Text)

    analysis_result = relationship("SecurityAnalysisResult", back_populates="findings")


class CodeBlock(Base):
    __tablename__ = "code_blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(
        Integer, ForeignKey("urls.id"), nullable=False
    )  # Original source URL
    processed_content_id = Column(
        Integer, ForeignKey("processed_markdown_content.id"), nullable=False
    )  # Link to specific parse
    language = Column(String(50))
    content = Column(Text, nullable=False)
    # line_start, line_end, context can be added later if parser provides them
    # For now, keeping schema simpler as per current parser output
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    context_before = Column(Text, nullable=True)  # Placeholder for future enhancement
    context_after = Column(Text, nullable=True)  # Placeholder for future enhancement

    url_source = relationship("Urls", back_populates="code_blocks")
    processed_content_source = relationship(
        "ProcessedMarkdownContent", back_populates="extracted_code_blocks"
    )


# New ExtractedItems table (for URLs, references from markdown)
class ExtractedItems(Base):
    __tablename__ = "extracted_items"
    id = Column(Integer, primary_key=True, autoincrement=True)
    processed_content_id = Column(
        Integer, ForeignKey("processed_markdown_content.id"), nullable=False
    )
    item_type = Column(
        String(50), nullable=False
    )  # e.g., 'url', 'image_src', 'footnote_ref'
    target_value = Column(
        Text, nullable=False
    )  # The actual URL string or reference key
    source_text = Column(Text, nullable=True)  # e.g., anchor text for a link

    processed_content_source = relationship(
        "ProcessedMarkdownContent", back_populates="extracted_items"
    )
    __table_args__ = (
        Index("idx_processed_content_item_type", "processed_content_id", "item_type"),
    )


class AnalysisHistory(Base):
    __tablename__ = "analysis_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url_id = Column(
        Integer, ForeignKey("urls.id"), nullable=False
    )  # References the new Urls table
    analysis_timestamp = Column(DateTime, nullable=False, server_default=func.now())
    changes_detected = Column(Boolean, nullable=False, default=False)
    change_summary = Column(Text, nullable=True)

    url_source = relationship("Urls", back_populates="analysis_history_entries")


def create_security_schema(engine: Engine):
    """
    Create or extend the database schema for security analysis tables.
    """
    Base.metadata.create_all(engine)
