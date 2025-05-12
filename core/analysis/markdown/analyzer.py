from typing import Optional, Dict, Any, List

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
        config: Optional[Dict[str, Any]] = None,
        structural_validator: MarkdownStructuralValidator = None,
        link_analyzer: MarkdownLinkAnalyzer = None,
        content_scanner: MarkdownContentScanner = None,
    ):
        self.config = config or {}
        self.max_content_size = self.config.get("max_content_size", 1024 * 1024)  # Default 1MB
        
        self.structural_validator = structural_validator or MarkdownStructuralValidator(template=template)
        self.link_analyzer = link_analyzer or MarkdownLinkAnalyzer()
        self.content_scanner = content_scanner or MarkdownContentScanner(config=self.config)
        self.template = template

    def analyze(self, content_item: Any, template: Optional[str] = None) -> Dict[str, Any]:
        """
        Run all markdown security analysis components and aggregate results.
        
        Args:
            content_item: Either a string containing markdown or a dictionary with content
            template: Optional template to use for validation
        """
        # Extract markdown content from the input
        item_id = "unknown"
        if isinstance(content_item, dict):
            item_id = content_item.get('id', 'unknown')
            print(f"Analyzing content item: {item_id}")
            markdown = content_item.get('content', '')
            if not isinstance(markdown, str):
                print(f"Warning: content is not a string, using empty string instead. Type: {type(markdown)}")
                markdown = ''
        else:
            markdown = str(content_item)
        
        # Check content size before processing
        content_size = len(markdown)
        if content_size > self.max_content_size:
            print(f"WARNING: Item {item_id}: Content size ({content_size} bytes) exceeds maximum allowed size ({self.max_content_size} bytes)")
            return {
                "structural_validation": {"valid": False, "errors": [f"Content size ({content_size} bytes) exceeds maximum allowed size ({self.max_content_size} bytes)"]},
                "link_analysis": {"links": [], "errors": ["Content too large for analysis"]},
                "content_security": {
                    "sanitized_content": "[Content too large for sanitization]",
                    "xss_vectors_found_in_markdown": [],
                    "prompt_injection_attempts": [],
                    "behavior_manipulation_attempts": [],
                    "size_limit_exceeded": True,
                    "content_size": content_size,
                    "max_size": self.max_content_size
                },
            }
            
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