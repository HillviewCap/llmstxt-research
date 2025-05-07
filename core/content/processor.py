from typing import List, Dict, Any, Optional
import hashlib

from .retriever import batch_retrieve, ContentRetrievalError
from .markdown_parser import extract_markdown_components, MarkdownParseError
from .storage import ContentStorage, ContentStorageError

class ContentProcessor:
    """
    Integrates retrieval, parsing, and storage of content.
    """
    def __init__(self, storage: Optional[ContentStorage] = None):
        self.storage = storage or ContentStorage()

    def process_urls(self, urls: List[str]) -> Dict[str, Optional[str]]:
        """
        Retrieves, parses, and stores content for a batch of URLs.
        Returns a dict mapping url to doc_id (or None if failed).
        """
        results = {}
        url_contents = batch_retrieve(urls)
        for url, content in url_contents.items():
            if content is None:
                results[url] = None
                continue
            doc_id = self._make_doc_id(url)
            try:
                parsed = extract_markdown_components(content)
                self.storage.store(doc_id, parsed, url=url)
                results[url] = doc_id
            except MarkdownParseError:
                results[url] = None
        return results

    def get_parsed_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        return self.storage.get_by_url(url)

    def get_parsed_by_doc_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        return self.storage.get_by_doc_id(doc_id)

    def process(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single content item.
        This method is called by the pipeline for each content item.
        """
        print(f"Processing content item: {item.get('id', 'unknown')}")
        
        # If the item has a URL, process it
        if 'source' in item and item['source'].startswith('http'):
            try:
                url = item['source']
                doc_id = self._make_doc_id(url)
                
                # If the item has content, parse it
                if 'content' in item:
                    try:
                        parsed = extract_markdown_components(item['content'])
                        self.storage.store(doc_id, parsed, url=url)
                        item['parsed'] = parsed
                    except MarkdownParseError as e:
                        print(f"Error parsing content: {e}")
                        item['parsed'] = None
            except Exception as e:
                print(f"Error processing item: {e}")
        
        return item
        
    @staticmethod
    def _make_doc_id(url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()