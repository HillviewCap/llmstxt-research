from typing import Dict, Any, Optional
import threading

class ContentStorageError(Exception):
    pass

class ContentStorage:
    """
    In-memory storage for parsed content components with indexing and caching.
    Thread-safe for concurrent access.
    """
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._index: Dict[str, str] = {}  # e.g., url -> doc_id
        self._lock = threading.Lock()

    def store(self, doc_id: str, content: Dict[str, Any], url: Optional[str] = None):
        with self._lock:
            self._store[doc_id] = content
            if url:
                self._index[url] = doc_id

    def get_by_doc_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._store.get(doc_id)

    def get_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            doc_id = self._index.get(url)
            if doc_id:
                return self._store.get(doc_id)
            return None

    def has_doc(self, doc_id: str) -> bool:
        with self._lock:
            return doc_id in self._store

    def has_url(self, url: str) -> bool:
        with self._lock:
            return url in self._index

    def clear(self):
        with self._lock:
            self._store.clear()
            self._index.clear()