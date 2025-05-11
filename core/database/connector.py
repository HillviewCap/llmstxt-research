from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from contextlib import contextmanager
from typing import Any, Dict, List, Optional
import time
import logging

logger = logging.getLogger(__name__)

class DatabaseConnector:
    def __init__(self, db_config: Any = "sqlite:///researchdb/llms_metadata.db", echo: bool = False, pool_size: int = 5, max_overflow: int = 10):
        try:
            # Handle case where db_config is a dictionary
            if isinstance(db_config, dict):
                logger.debug(f"Received db_config as dictionary: {db_config}")
                # Extract the URL from the dictionary
                db_url = f"sqlite:///{db_config.get('path', 'researchdb/llms_metadata.db')}"
                logger.debug(f"Using database URL: {db_url}")
            else:
                # Use the provided string directly
                db_url = db_config
            
            # Configure SQLite connection parameters
            connect_args = {}
            if str(db_url).startswith("sqlite"):
                # Enable WAL mode for better concurrency
                connect_args = {
                    "check_same_thread": False,
                    "timeout": 30.0,  # Increase default timeout for locks
                    "isolation_level": None  # Required for pragma statements
                }
                
            self.engine = create_engine(
                db_url,
                echo=echo,
                pool_size=pool_size,
                max_overflow=max_overflow,
                connect_args=connect_args,
            )
            
            # Enable WAL mode for SQLite
            if str(db_url).startswith("sqlite"):
                with self.engine.connect() as conn:
                    conn.execute(text("PRAGMA journal_mode=WAL"))
                    conn.execute(text("PRAGMA synchronous=NORMAL"))
                    conn.execute(text("PRAGMA busy_timeout=10000"))
                    logger.info("SQLite WAL mode enabled with busy_timeout=10000ms")
            
            self.Session = scoped_session(sessionmaker(bind=self.engine))
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to initialize database engine: {e}")

    @contextmanager
    def session_scope(self, retries=3, retry_delay=0.5):
        """Provide a transactional scope around a series of operations."""
        session = self.Session()
        attempt = 0
        start_time = time.time()
        operation_name = "unknown"
        
        # Try to identify the calling function for better logging
        try:
            import inspect
            frame = inspect.currentframe().f_back
            if frame:
                operation_name = frame.f_code.co_name
        except:
            pass
        
        try:
            yield session
            session.commit()
            duration = time.time() - start_time
            if duration > 1.0:  # Log slow transactions
                logger.info(f"Long transaction in {operation_name}: {duration:.2f}s")
                
        except SQLAlchemyError as e:
            session.rollback()
            attempt += 1
            
            # Check if it's a database lock error and we should retry
            lock_error = "database is locked" in str(e).lower()
            if lock_error and attempt <= retries:
                logger.warning(f"Database locked in {operation_name}, retrying in {retry_delay}s (attempt {attempt}/{retries})")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                
                # Try again with the same session
                try:
                    yield session
                    session.commit()
                    duration = time.time() - start_time
                    logger.info(f"Retry succeeded for {operation_name} after {duration:.2f}s")
                except SQLAlchemyError as e2:
                    session.rollback()
                    logger.error(f"Retry failed for {operation_name}: {e2}")
                    raise
            else:
                # Either not a lock error or we've exhausted retries
                logger.error(f"Database error in {operation_name}: {e}")
                raise
        finally:
            # Always close the session
            session.close()
    
    @contextmanager
    def no_autoflush_scope(self):
        """Provide a scope with autoflush disabled to reduce lock contention."""
        session = self.Session()
        original_autoflush = session.autoflush
        session.autoflush = False
        start_time = time.time()
        
        try:
            yield session
            session.commit()
            duration = time.time() - start_time
            if duration > 1.0:  # Log slow transactions
                logger.info(f"Long no_autoflush transaction: {duration:.2f}s")
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error in no_autoflush transaction: {e}")
            raise
        finally:
            session.autoflush = original_autoflush
            session.close()

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Execute a raw SQL query and return results as list of dicts."""
        start_time = time.time()
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(query), params or {})
                if result.returns_rows:
                    rows = [dict(row) for row in result.fetchall()]
                    duration = time.time() - start_time
                    if duration > 1.0:  # Log slow queries
                        logger.info(f"Slow query ({duration:.2f}s): {query[:100]}...")
                    return rows
                return []
        except SQLAlchemyError as e:
            logger.error(f"Query execution failed: {e}")
            raise RuntimeError(f"Query execution failed: {e}")

    def execute_statement(self, statement, retries=3):
        """Execute a SQLAlchemy statement (ORM or Core) with retry logic."""
        retry_delay = 0.5  # Start with 0.5 second delay
        start_time = time.time()
        
        for attempt in range(retries + 1):
            try:
                with self.session_scope() as session:
                    result = session.execute(statement)
                    duration = time.time() - start_time
                    if duration > 1.0:  # Log slow statements
                        logger.info(f"Slow statement execution ({duration:.2f}s)")
                    return result
            except SQLAlchemyError as e:
                if "database is locked" in str(e).lower() and attempt < retries:
                    logger.warning(f"Database locked during statement execution, retrying in {retry_delay}s (attempt {attempt+1}/{retries})")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    # Either not a lock error or we've exhausted retries
                    logger.error(f"Statement execution failed: {e}")
                    raise RuntimeError(f"Statement execution failed: {e}")

    def get_engine(self):
        return self.engine

    def get_session(self):
        """
        Get a new session. IMPORTANT: Caller is responsible for closing this session!
        Prefer using session_scope() or no_autoflush_scope() instead.
        """
        logger.warning("Direct session requested - ensure it's closed after use")
        return self.Session()
        
    def check_connection(self):
        """Check if database connection is working properly."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False