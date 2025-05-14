from typing import Optional, Dict, Any
from sqlalchemy import select

from .structural_validator import MarkdownStructuralValidator
from .link_analyzer import MarkdownLinkAnalyzer
from .content_scanner import MarkdownContentScanner
from core.database.connector import DatabaseConnector
from core.database.schema import ProcessedMarkdownContent


class MarkdownSecurityAnalyzer:
    """
    Orchestrates all markdown security analysis components.
    """

    def __init__(
        self,
        template: Optional[str] = None,
        structural_validator: MarkdownStructuralValidator = None,
        link_analyzer: MarkdownLinkAnalyzer = None,
        content_scanner: MarkdownContentScanner = None,
        db_connector: Optional[DatabaseConnector] = None,
    ):
        self.structural_validator = structural_validator or MarkdownStructuralValidator(
            template=template
        )
        self.link_analyzer = link_analyzer or MarkdownLinkAnalyzer()
        self.content_scanner = content_scanner or MarkdownContentScanner()
        self.template = template
        self.db_connector = db_connector or DatabaseConnector()

    def analyze(
        self, processed_content_id: int, template: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run all markdown security analysis components and aggregate results.

        Args:
            processed_content_id: ID of the processed markdown content in the database
            template: Optional template to use for validation
        """
        # Fetch markdown content from the database
        markdown_content = None

        try:
            with self.db_connector.session_scope() as session:
                # Assuming raw_markdown_text column exists in ProcessedMarkdownContent table
                stmt = select(ProcessedMarkdownContent.raw_markdown_text).where(
                    ProcessedMarkdownContent.id == processed_content_id
                )
                markdown_content = session.execute(stmt).scalar_one_or_none()

            if markdown_content is None:
                print(
                    f"Warning: Content for processed_content_id {processed_content_id} not found or raw_markdown_text is empty."
                )
                return {
                    "structural_validation": {"error": "Content not found"},
                    "link_analysis": {},
                    "content_security": {},
                }
        except Exception as e:
            print(f"Error fetching content from database: {e}")
            return {
                "structural_validation": {"error": f"Database error: {str(e)}"},
                "link_analysis": {},
                "content_security": {},
            }

        structural_results = self.structural_validator.validate(markdown_content)
        link_results = self.link_analyzer.analyze(markdown_content)
        content_results = self.content_scanner.scan(markdown_content)
        return {
            "structural_validation": structural_results,
            "link_analysis": link_results,
            "content_security": content_results,
        }


# Create an alias for compatibility with existing code
MarkdownAnalyzer = MarkdownSecurityAnalyzer
