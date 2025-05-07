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
        # This is a placeholder implementation
        # In a real implementation, this would query the database or external sources
        
        # Return a dummy content item for testing
        # For URL queries, try to use the query as the URL
        if query and isinstance(query, str) and (query.startswith('http://') or query.startswith('https://')):
            print(f"Using query as URL: {query}")
            try:
                content = retrieve_url_content(query, use_cache=True)
                return [
                    {
                        "id": "test-content-1",
                        "type": "markdown",
                        "source": query,  # Use the actual URL
                        "language": "markdown",  # Add language for static analyzer
                        "content": content,
                        "raw_content": content,  # Add raw_content for temporal analysis
                        "metadata": {"timestamp": "2023-01-01T00:00:00Z"}
                    }
                ]
            except ContentRetrievalError as e:
                print(f"Error retrieving content from URL {query}: {e}")
                # Fall back to test content but with proper URL
        
        # Default test content with proper URL format
        return [
            {
                "id": "test-content-1",
                "type": "markdown",
                "source": "https://example.com/test",  # Valid URL format
                "language": "markdown",  # Add language for static analyzer
                "content": "# Test Content\n\nThis is a test content item.",
                "raw_content": "# Test Content\n\nThis is a test content item.",  # Add raw_content for temporal analysis
                "metadata": {"timestamp": "2023-01-01T00:00:00Z"}
            }
        ]