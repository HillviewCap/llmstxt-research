import requests
try:
    import chardet
    print("Successfully imported chardet")
except ImportError:
    print("ERROR: The 'chardet' package is not installed. This package is required for encoding detection.")
    print("Please install it using: pip install chardet")
    print("Or with UV: uv pip install chardet")
    # Provide a fallback option to continue without chardet
    chardet = None
import hashlib
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from functools import lru_cache

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".retriever_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

class ContentRetrievalError(Exception):
    pass

def _cache_path(url: str) -> str:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return os.path.join(CACHE_DIR, f"{h}.cache")

def detect_encoding(content: bytes) -> str:
    if chardet is None:
        print("WARNING: Using fallback encoding detection since chardet is not installed")
        # Simple fallback: try UTF-8 first, then latin-1 as a fallback
        try:
            content.decode('utf-8')
            return 'utf-8'
        except UnicodeDecodeError:
            return 'latin-1'  # A safe fallback that can decode any byte sequence
    else:
        result = chardet.detect(content)
        return result["encoding"] or "utf-8"

def normalize_content(content: bytes, encoding: Optional[str] = None) -> str:
    if not encoding:
        encoding = detect_encoding(content)
    try:
        return content.decode(encoding, errors="replace")
    except Exception:
        return content.decode("utf-8", errors="replace")

def retrieve_url_content(url: str, timeout: int = 10, use_cache: bool = True) -> str:
    cache_file = _cache_path(url)
    if use_cache and os.path.exists(cache_file):
        with open(cache_file, "rb") as f:
            raw = f.read()
        return normalize_content(raw)
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        content = resp.content
        if use_cache:
            with open(cache_file, "wb") as f:
                f.write(content)
        return normalize_content(content)
    except Exception as e:
        raise ContentRetrievalError(f"Failed to retrieve {url}: {e}")

def batch_retrieve(urls: List[str], timeout: int = 10, use_cache: bool = True) -> Dict[str, Optional[str]]:
    results = {}
    for url in urls:
        try:
            content = retrieve_url_content(url, timeout=timeout, use_cache=use_cache)
            results[url] = content
        except ContentRetrievalError:
            results[url] = None
    return results


class ContentRetriever:
    """
    Content retrieval class that interfaces with the database and external sources.
    """
    def __init__(self, db=None):
        self.db = db
        
    def retrieve(self, query=None):
        """
        Retrieve content items based on query parameters.
        Returns a list of content items.
        """
        print("ContentRetriever.retrieve called with query:", query)
        
        # If no query is provided, fetch all URLs from the database that have
        # a corresponding entry in the processed_markdown_content table
        if query is None:
            print("No query provided. Fetching all known URLs from the database.")
            content_items = []
            
            # Check if database connector is available
            if self.db is None:
                print("Warning: Database connector is not available. Returning empty list.")
                return []
            
            try:
                # Look for the llms database in multiple possible locations
                possible_db_paths = [
                    os.path.join(os.getcwd(), "llms.db"),
                    os.path.join(os.getcwd(), "data", "llms.db"),
                    os.path.join(os.getcwd(), "researchdb", "llms.db"),
                    os.path.join(os.getcwd(), "data", "llms_metadata.db"),
                    os.path.join(os.getcwd(), "..", "llms.db")
                ]
                
                llms_db_path = None
                for path in possible_db_paths:
                    print(f"Checking for database at: {path}")
                    if os.path.exists(path):
                        llms_db_path = path
                        print(f"Found database at: {llms_db_path}")
                        break
                
                if llms_db_path:
                    # Connect to llms.db
                    import sqlite3
                    llms_conn = sqlite3.connect(llms_db_path)
                    llms_cursor = llms_conn.cursor()
                    
                    # Check if it has the expected tables
                    llms_cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    llms_tables = llms_cursor.fetchall()
                    llms_table_names = [t[0] for t in llms_tables]
                    print(f"Tables in llms.db: {llms_table_names}")
                    
                    # Check if it has the urls and url_text_content tables
                    if 'urls' in llms_table_names and 'url_text_content' in llms_table_names:
                        print("Found urls and url_text_content tables in llms.db")
                        # Query URLs that have content in the url_text_content table
                        llms_cursor.execute("""
                        SELECT u.id, u.url, utc.text_content
                        FROM urls u
                        JOIN url_text_content utc ON u.id = utc.url_id
                        WHERE utc.fetch_status = 'success' AND utc.text_content IS NOT NULL;
                        """)
                        db_results = llms_cursor.fetchall()
                        print(f"Found {len(db_results)} URLs with content in llms.db")
                        
                        # If we found URLs in llms.db, use them
                        if db_results:
                            print("Using URLs from llms.db")
                            llms_conn.close()
                            # Skip checking the security analysis platform database
                            return self._process_db_results(db_results, content_items)
                    
                    # Close the connection to llms.db
                    llms_conn.close()
                
                # If we didn't find or couldn't use llms.db, check the security analysis platform database
                db_path = self.db.engine.url.database
                print(f"Checking security analysis database at: {db_path}")
                if not os.path.exists(db_path):
                    print(f"Database file does not exist: {db_path}")
                    return []
                    
                # Try a direct connection approach
                import sqlite3
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Check if tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                table_names = [t[0] for t in tables]
                print(f"Tables in database: {table_names}")
                
                # Determine which schema we're working with
                db_results = []
                
                # Check if we're using the security analysis platform schema
                if 'urls' in table_names and 'processed_markdown_content' in table_names:
                    print("Detected security analysis platform schema")
                    cursor.execute("""
                    SELECT DISTINCT u.id, u.url_string
                    FROM urls u
                    JOIN processed_markdown_content pmc ON u.id = pmc.url_id;
                    """)
                    db_results = cursor.fetchall()
                    print(f"Found {len(db_results)} URLs in the security analysis platform database")
                
                # If no results found
                if not db_results:
                    print("No URLs found in any database")
                    # Create a test URL for demonstration
                    print("Creating a test URL for demonstration")
                    db_results = [(1, "https://example.com/test", "# Test Content\n\nThis is a test content item.")]
                
                return self._process_db_results(db_results, content_items)
            except Exception as e:
                print(f"Error querying database: {e}")
                # If database query fails, return an empty list
                return []
        
    def _process_db_results(self, db_results, content_items=None):
        """Helper method to process database results and create content items."""
        if content_items is None:
            content_items = []
            
        # Process each URL
        for row in db_results:
            # With direct sqlite3, results are tuples, not dicts
            try:
                url_id = row[0]
                url_s = row[1]
                
                # Check if we have content directly from the database
                if len(row) > 2 and row[2]:
                    # Content is already in the database (from url_text_content table)
                    actual_content = row[2]
                    print(f"Using content from database for URL: {url_s} (ID: {url_id})")
                else:
                    # Need to retrieve content from the URL
                    print(f"Retrieving content for URL: {url_s} (ID: {url_id})")
                    actual_content = retrieve_url_content(url_s, use_cache=True)
                
                # Create content item
                item = {
                    "id": f"db-item-{url_id}",
                    "type": "markdown",
                    "source": url_s,
                    "language": "markdown",
                    "content": actual_content,
                    "raw_content": actual_content,
                    "metadata": {
                        "timestamp": datetime.now().isoformat() + "Z",
                        "db_url_id": url_id,
                        "retrieval_method": "db_all_known_urls"
                    }
                }
                content_items.append(item)
                print(f"Successfully processed content for URL: {url_s}")
            except ContentRetrievalError as e:
                print(f"Error retrieving content for URL {url_s} (ID: {url_id}): {e}")
                # Skip this URL and continue with the next one
            except Exception as e:
                print(f"Error processing row {row}: {e}")
                # Skip this row and continue with the next one
        
        return content_items
        
    # For URL queries, try to use the query as the URL
        if query and isinstance(query, str) and (query.startswith('http://') or query.startswith('https://')):
            print(f"Using query as URL: {query}")
            try:
                content = retrieve_url_content(query, use_cache=True)
                return [
                    {
                        "id": "query-content-1",
                        "type": "markdown",
                        "source": query,  # Use the actual URL
                        "language": "markdown",  # Add language for static analyzer
                        "content": content,
                        "raw_content": content,  # Add raw_content for temporal analysis
                        "metadata": {
                            "timestamp": datetime.now().isoformat() + "Z",
                            "retrieval_method": "direct_url_query"
                        }
                    }
                ]
            except ContentRetrievalError as e:
                print(f"Error retrieving content from URL {query}: {e}")
                # Return empty list if URL retrieval fails
                return []
        
        # If query is not None and not a URL, it's an unsupported query type
        print(f"Unsupported query type: {query}. Returning empty list.")
        return []