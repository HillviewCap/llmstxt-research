from typing import Optional, Dict, Any

from .structural_validator import MarkdownStructuralValidator
from .link_analyzer import MarkdownLinkAnalyzer
from .content_scanner import MarkdownContentScanner

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
    ):
        self.structural_validator = structural_validator or MarkdownStructuralValidator(template=template)
        self.link_analyzer = link_analyzer or MarkdownLinkAnalyzer()
        self.content_scanner = content_scanner or MarkdownContentScanner()
        self.template = template

    def analyze(self, content_item: Any, template: Optional[str] = None) -> Dict[str, Any]:
        """
        Run all markdown security analysis components and aggregate results.
        
        Args:
            content_item: Either a string containing markdown or a dictionary with content
            template: Optional template to use for validation
        """
        # Extract markdown content from the input
        if isinstance(content_item, dict):
            print(f"Analyzing content item: {content_item.get('id', 'unknown')}")
            markdown = content_item.get('content', '')
            if not isinstance(markdown, str):
                print(f"Warning: content is not a string, using empty string instead. Type: {type(markdown)}")
                markdown = ''
        else:
            markdown = str(content_item)
            
        structural_results = self.structural_validator.validate(markdown)
        link_results = self.link_analyzer.analyze(markdown)
        content_results = self.content_scanner.scan(markdown)
        return {
            "structural_validation": structural_results,
            "link_analysis": link_results,
            "content_security": content_results,
        }

# Create an alias for compatibility with existing code
MarkdownAnalyzer = MarkdownSecurityAnalyzer