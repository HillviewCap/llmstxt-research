from typing import Dict, Any, Optional, List
import threading
import hashlib
import re
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.sql import func  # for func.now()

from ..database.connector import DatabaseConnector
from ..database.schema import Urls, ProcessedMarkdownContent, CodeBlock, ExtractedItems


class ContentStorageError(Exception):
    """Custom exception for content storage errors."""

    pass


class ContentStorage:
    """
    Manages storage and retrieval of parsed markdown content, utilizing
    both an in-memory cache for speed and a database for persistence.
    Thread-safe for concurrent access to the in-memory cache.
    """

    def __init__(self, db_connector: DatabaseConnector):
        self._db_connector = db_connector
        self._cache: Dict[str, Dict[str, Any]] = {}  # Cache key: source_url
        self._lock = threading.Lock()

    def _calculate_hash(self, text: str) -> str:
        """Calculates SHA256 hash for the given text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def store_parsed_content(
        self, source_url: str, raw_markdown_text: str, parsed_data: Dict[str, Any]
    ) -> None:
        """
        Stores parsed markdown content into the database and updates the cache.

        Args:
            source_url: The URL from which the content was fetched.
            raw_markdown_text: The original raw markdown text.
            parsed_data: The dictionary of components from MarkdownParser.
        """
        content_hash = self._calculate_hash(raw_markdown_text)

        with self._db_connector.session_scope() as session:
            try:
                # 1. Get or create Urls record
                url_record = (
                    session.query(Urls).filter_by(url_string=source_url).first()
                )
                if not url_record:
                    url_record = Urls(url_string=source_url)
                    session.add(url_record)
                    session.flush()  # To get url_record.id
                else:
                    # Update last_accessed_at if needed, though server_default onupdate handles it
                    url_record.last_accessed_at = func.now()

                # 2. Check if this exact ProcessedMarkdownContent already exists
                processed_content_record = (
                    session.query(ProcessedMarkdownContent)
                    .filter_by(url_id=url_record.id, raw_content_hash=content_hash)
                    .first()
                )

                if processed_content_record:
                    # Content with this hash for this URL already processed and stored.
                    # We can assume its sub-components (code blocks, extracted items) are also stored.
                    # For simplicity, we'll update the cache and return.
                    # More sophisticated logic could involve checking/updating timestamps.
                    print(
                        f"Content for URL {source_url} with hash {content_hash} already exists. Updating cache."
                    )
                else:
                    # Create new ProcessedMarkdownContent record
                    processed_content_record = ProcessedMarkdownContent(
                        url_id=url_record.id,
                        raw_content_hash=content_hash,
                        normalized_representation=parsed_data.get("normalized_content"),
                        document_structure_summary=parsed_data.get("structure"),
                        # fetched_timestamp and parsed_timestamp will use server_default
                    )
                    session.add(processed_content_record)
                    session.flush()  # To get processed_content_record.id

                    # 3. Store CodeBlocks
                    for cb_data in parsed_data.get("code_blocks", []):
                        code_block_record = CodeBlock(
                            url_id=url_record.id,
                            processed_content_id=processed_content_record.id,
                            language=cb_data.get("language"),
                            content=cb_data.get("code"),
                            line_start=cb_data.get("line_start"),
                            line_end=cb_data.get("line_end"),
                            context_before=cb_data.get("context_before"),
                            context_after=cb_data.get("context_after"),
                        )
                        session.add(code_block_record)

                    # 4. Store ExtractedItems (URLs and references)
                    # For URLs, extract both target_value and source_text
                    self._store_extracted_items(
                        session=session,
                        processed_content_id=processed_content_record.id,
                        parsed_data=parsed_data,
                    )

                session.commit()  # Commit all changes for this storage operation

                # Update in-memory cache
                with self._lock:
                    self._cache[source_url] = parsed_data  # Store the full parsed data

            except Exception as e:
                session.rollback()
                raise ContentStorageError(
                    f"Failed to store content for URL {source_url}: {e}"
                )

    def get_parsed_content_by_url(self, source_url: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves parsed content for a given URL, from cache or database.
        If retrieved from DB, it reconstructs the parsed_data format.
        """
        with self._lock:
            if source_url in self._cache:
                return self._cache[source_url]

        # Not in cache, try to fetch from DB
        with self._db_connector.session_scope() as session:
            try:
                url_record = (
                    session.query(Urls).filter_by(url_string=source_url).first()
                )
                if not url_record:
                    return None

                # Get the most recent ProcessedMarkdownContent for this URL
                # Order by fetched_timestamp or parsed_timestamp if multiple versions are expected
                # For now, let's assume we typically want the latest based on ID or timestamp
                processed_content_record = (
                    session.query(ProcessedMarkdownContent)
                    .filter_by(url_id=url_record.id)
                    .order_by(ProcessedMarkdownContent.parsed_timestamp.desc())
                    .first()
                )

                if not processed_content_record:
                    return None

                # Reconstruct the parsed_data dictionary
                reconstructed_data: Dict[str, Any] = {
                    "normalized_content": processed_content_record.normalized_representation,
                    "structure": processed_content_record.document_structure_summary,
                    "code_blocks": [],
                    "urls": [],
                    "references": [],
                }

                db_code_blocks = (
                    session.query(CodeBlock)
                    .filter_by(processed_content_id=processed_content_record.id)
                    .all()
                )
                for cb in db_code_blocks:
                    reconstructed_data["code_blocks"].append(
                        {"language": cb.language, "code": cb.content}
                    )

                db_extracted_items = (
                    session.query(ExtractedItems)
                    .filter_by(processed_content_id=processed_content_record.id)
                    .all()
                )

                # Create a dictionary to store URL to source_text mapping
                url_source_texts = {}

                for item in db_extracted_items:
                    if item.item_type == "url":
                        reconstructed_data["urls"].append(item.target_value)
                        # Store the source_text for this URL if it exists
                        if item.source_text:
                            url_source_texts[item.target_value] = item.source_text
                    elif item.item_type == "reference":
                        reconstructed_data["references"].append(item.target_value)

                # Add the URL source texts to the reconstructed data
                reconstructed_data["url_source_texts"] = url_source_texts

                # Sort for consistency if needed, matching parser output
                reconstructed_data["urls"] = sorted(
                    list(set(reconstructed_data["urls"]))
                )
                reconstructed_data["references"] = sorted(
                    list(set(reconstructed_data["references"]))
                )

                # Update cache
                with self._lock:
                    self._cache[source_url] = reconstructed_data

                return reconstructed_data

            except Exception as e:
                # Log error, but don't necessarily raise if it's a retrieval issue
                # For now, re-raise to be aware of problems.
                # print(f"Error retrieving content for URL {source_url} from DB: {e}")
                raise ContentStorageError(
                    f"Failed to retrieve content for URL {source_url} from DB: {e}"
                )
                # return None

    def has_content_for_url(self, source_url: str) -> bool:
        """Checks if content for the given URL exists in cache or database."""
        with self._lock:
            if source_url in self._cache:
                return True

        try:
            with self._db_connector.session_scope() as session:
                url_record = (
                    session.query(Urls).filter_by(url_string=source_url).first()
                )
                if url_record:
                    # Check if there's at least one processed content entry
                    return (
                        session.query(ProcessedMarkdownContent)
                        .filter_by(url_id=url_record.id)
                        .count()
                        > 0
                    )
                return False
        except Exception:
            # If DB check fails, assume no for safety, or log error
            return False

    def clear_cache(self):
        """Clears the in-memory cache."""
        with self._lock:
            self._cache.clear()
            print("In-memory content cache cleared.")

    # Consider if clear_all_stored_content (DB + cache) is needed
    # def clear_all_stored_content(self):
    #     with self._db_connector.session_scope() as session:
    #         try:
    #             # Order of deletion matters due to foreign keys
    #             session.query(ExtractedItems).delete()
    #             session.query(CodeBlock).delete()
    #             session.query(ProcessedMarkdownContent).delete()
    #             # Urls table might be kept or cleared depending on requirements
    #             # session.query(Urls).delete()
    #             session.commit()
    #             self.clear_cache()
    #             print("All stored content from database and cache cleared (excluding Urls table by default).")
    #         except Exception as e:
    #             session.rollback()
    #             raise ContentStorageError(f"Failed to clear all stored content: {e}")

    def _store_extracted_items(
        self, session: Session, processed_content_id: int, parsed_data: Dict[str, Any]
    ) -> None:
        """
        Store extracted items (URLs and references) with their target values and source text.

        Args:
            session: The database session
            processed_content_id: The ID of the processed content record
            parsed_data: The parsed data from MarkdownParser
        """
        # 1. Handle URLs
        for url in parsed_data.get("urls", []):
            source_text = None

            # Try to find source text for this URL in normalized_content
            if "normalized_content" in parsed_data:
                source_text = self._find_source_text_for_url(
                    parsed_data["normalized_content"], url
                )

            extracted_item_record = ExtractedItems(
                processed_content_id=processed_content_id,
                item_type="url",
                target_value=url,
                source_text=source_text,
            )
            session.add(extracted_item_record)

        # 2. Handle references
        for ref in parsed_data.get("references", []):
            extracted_item_record = ExtractedItems(
                processed_content_id=processed_content_id,
                item_type="reference",
                target_value=ref,
                source_text=None,  # References typically don't have source text
            )
            session.add(extracted_item_record)

    def _find_source_text_for_url(
        self, normalized_content: List[Dict[str, Any]], url: str
    ) -> Optional[str]:
        """
        Find the source text for a URL in the normalized content tree.

        Args:
            normalized_content: The normalized content tree from MarkdownParser
            url: The URL to find source text for

        Returns:
            The source text if found, otherwise None
        """

        def search_nodes(nodes):
            for node in nodes:
                # Check if this is a link node with the target URL
                if node.get("type") == "link" and node.get("url") == url:
                    return node.get("text")

                # For llmstxt format, check if the node text contains a markdown link with this URL
                if (
                    "[" in node.get("text", "")
                    and "](" in node.get("text", "")
                    and url in node.get("text", "")
                ):
                    # Extract the text part from a markdown link [text](url)
                    link_pattern = r"\[(.*?)\]\(" + re.escape(url) + r"\)"
                    match = re.search(link_pattern, node.get("text", ""))
                    if match:
                        return match.group(1)

                # Recursively search children
                if "children" in node and node["children"]:
                    result = search_nodes(node["children"])
                    if result:
                        return result

            return None

        return search_nodes(normalized_content)


# Example Usage (Illustrative - would be in a higher-level orchestrator)
# if __name__ == '__main__':
#     from .markdown_parser import MarkdownParser
#
#     # Setup (replace with actual project setup)
#     db_conn = DatabaseConnector(db_config="sqlite:///./test_content_storage.db", echo=True)
#     from core.database.schema import create_security_schema
#     create_security_schema(db_conn.get_engine()) # Create tables
#
#     storage = ContentStorage(db_connector=db_conn)
#     parser = MarkdownParser()
#
#     sample_md = """
#     # Title
#     Some text with a [link](http://example.com/page1).
#     ```python
#     print("Hello")
#     ```
#     Another [ref][1].
#
#     [1]: http://example.com/ref1
#     """
#     sample_url = "http://example.com/doc1"
#
#     # --- Test Store ---
#     parsed = parser.parse(sample_md)
#     storage.store_parsed_content(sample_url, sample_md, parsed)
#     print(f"Stored content for {sample_url}")
#
#     # --- Test Get from Cache ---
#     cached_content = storage.get_parsed_content_by_url(sample_url)
#     if cached_content:
#         print(f"\nRetrieved from cache for {sample_url}:")
#         # print(cached_content)
#     assert cached_content is not None and cached_content["urls"] == ["http://example.com/page1"]
#
#     # --- Test Get from DB (after clearing cache) ---
#     storage.clear_cache()
#     db_content = storage.get_parsed_content_by_url(sample_url)
#     if db_content:
#         print(f"\nRetrieved from DB for {sample_url} (after cache clear):")
#         # print(db_content)
#     assert db_content is not None and db_content["code_blocks"][0]["language"] == "python"
#
#     # --- Test Store again (should use existing ProcessedMarkdownContent) ---
#     print("\nStoring same content again...")
#     storage.store_parsed_content(sample_url, sample_md, parsed) # Should print it already exists
#
#     # --- Test Store modified content ---
#     modified_md = sample_md + "\n## New Section"
#     modified_parsed = parser.parse(modified_md)
#     print("\nStoring modified content...")
#     storage.store_parsed_content(sample_url, modified_md, modified_parsed)
#
#     # --- Test Get modified content (should be the latest) ---
#     storage.clear_cache()
#     latest_content = storage.get_parsed_content_by_url(sample_url)
#     if latest_content:
#         assert "New Section" in latest_content["structure"][-1]["text"]
#         print(f"\nRetrieved latest (modified) content for {sample_url} from DB.")
#
#     print("\nContentStorage tests completed (basic).")
