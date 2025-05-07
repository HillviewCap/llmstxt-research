from typing import List, Dict, Any, Optional

from core.database.connector import DatabaseConnector
from .retriever import batch_retrieve, ContentRetrievalError
from .markdown_parser import MarkdownParser, MarkdownParseError
from .storage import ContentStorage, ContentStorageError

class ContentProcessorError(Exception):
    """Custom exception for content processing errors."""
    pass

class ContentProcessor:
    """
    Integrates retrieval, parsing, and storage of markdown content.
    """
    def __init__(self, db_connector: DatabaseConnector):
        self.parser = MarkdownParser()
        self.storage = ContentStorage(db_connector=db_connector)

    def process_single_url(self, url: str, raw_content: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves (if not provided), parses, and stores content for a single URL.
        Returns the parsed data if successful, otherwise None.
        """
        try:
            if raw_content is None:
                retrieved_content_map = batch_retrieve([url])
                raw_content = retrieved_content_map.get(url)

            if raw_content is None:
                print(f"Failed to retrieve content for URL: {url}")
                return None

            parsed_data = self.parser.parse(raw_content)
            self.storage.store_parsed_content(
                source_url=url,
                raw_markdown_text=raw_content,
                parsed_data=parsed_data
            )
            return parsed_data
        except ContentRetrievalError as e:
            print(f"Content retrieval error for {url}: {e}")
            raise ContentProcessorError(f"Retrieval failed for {url}: {e}") from e
        except MarkdownParseError as e:
            print(f"Markdown parsing error for {url}: {e}")
            raise ContentProcessorError(f"Parsing failed for {url}: {e}") from e
        except ContentStorageError as e:
            print(f"Content storage error for {url}: {e}")
            raise ContentProcessorError(f"Storage failed for {url}: {e}") from e
        except Exception as e:
            print(f"Unexpected error processing URL {url}: {e}")
            raise ContentProcessorError(f"Unexpected error for {url}: {e}") from e


    def process_batch_urls(self, urls: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Retrieves, parses, and stores content for a batch of URLs.
        Returns a dict mapping URL to parsed_data (or None if failed for that URL).
        Individual failures do not stop the processing of other URLs.
        """
        results: Dict[str, Optional[Dict[str, Any]]] = {}
        
        try:
            url_contents = batch_retrieve(urls)
        except ContentRetrievalError as e:
            print(f"Batch retrieval failed: {e}. Marking all URLs in this batch as failed for retrieval.")
            for url_item in urls:
                results[url_item] = None # Mark as retrieval failure
            return results # Early exit if batch retrieval itself fails catastrophically

        for url, raw_content in url_contents.items():
            if raw_content is None:
                print(f"No content retrieved for {url} in batch.")
                results[url] = None
                continue
            try:
                # Re-use single URL processing logic
                parsed_data = self.process_single_url(url=url, raw_content=raw_content)
                results[url] = parsed_data
            except ContentProcessorError as e: # Catch errors from process_single_url
                print(f"Failed to process {url} in batch: {e}")
                results[url] = None # Mark as failed for this specific URL
            except Exception as e: # Catch any other unexpected errors
                print(f"Unexpected critical error processing {url} in batch: {e}")
                results[url] = None
        return results

    def get_parsed_content(self, url: str) -> Optional[Dict[str, Any]]:
        """Retrieves parsed content by URL from storage."""
        try:
            return self.storage.get_parsed_content_by_url(url)
        except ContentStorageError as e:
            print(f"Error retrieving parsed content for {url}: {e}")
            return None

    def process_pipeline_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single content item, typically coming from a pipeline.
        Expected item structure: {'source': <url_string>, 'content': <optional_raw_markdown_text>}
        Adds 'parsed_content' key to the item with parsed data or None on failure.
        """
        source_url = item.get("source")
        raw_content = item.get("content") # May or may not be pre-fetched

        if not source_url or not isinstance(source_url, str) or not source_url.startswith('http'):
            print(f"Invalid or missing 'source' URL in item: {item.get('id', 'unknown')}")
            item['parsed_content'] = None
            item['processing_error'] = "Invalid source URL"
            return item

        print(f"Processing pipeline item, source URL: {source_url}")
        try:
            # If content is already provided in the item, use it. Otherwise, it will be fetched.
            parsed_data = self.process_single_url(url=source_url, raw_content=raw_content)
            item['parsed_content'] = parsed_data
            if parsed_data is None:
                 item['processing_error'] = f"Content processing failed for {source_url} (check logs for details)."

        except ContentProcessorError as e:
            print(f"ContentProcessorError for item {item.get('id', source_url)}: {e}")
            item['parsed_content'] = None
            item['processing_error'] = str(e)
        except Exception as e: # Catch any other unexpected errors
            print(f"Unexpected critical error processing pipeline item {item.get('id', source_url)}: {e}")
            item['parsed_content'] = None
            item['processing_error'] = f"Unexpected critical error: {str(e)}"
        
        return item