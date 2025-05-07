from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

class DatabaseConnector:
    def __init__(self, db_config: Any = "sqlite:///researchdb/llms_metadata.db", echo: bool = False, pool_size: int = 5, max_overflow: int = 10):
        try:
            # Handle case where db_config is a dictionary
            if isinstance(db_config, dict):
                print(f"Received db_config as dictionary: {db_config}")
                # Extract the URL from the dictionary
                db_url = f"sqlite:///{db_config.get('path', 'researchdb/llms_metadata.db')}"
                print(f"Using database URL: {db_url}")
            else:
                # Use the provided string directly
                db_url = db_config
                
            self.engine = create_engine(
                db_url,
                echo=echo,
                pool_size=pool_size,
                max_overflow=max_overflow,
                connect_args={"check_same_thread": False} if str(db_url).startswith("sqlite") else {},
            )
            self.Session = scoped_session(sessionmaker(bind=self.engine))
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to initialize database engine: {e}")

    @contextmanager
    def session_scope(self):
        """Provide a transactional scope around a series of operations."""
        session = self.Session()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            raise
        finally:
            session.close()

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Execute a raw SQL query and return results as list of dicts."""
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(query), params or {})
                if result.returns_rows:
                    return [dict(row) for row in result.fetchall()]
                return []
        except SQLAlchemyError as e:
            raise RuntimeError(f"Query execution failed: {e}")

    def execute_statement(self, statement):
        """Execute a SQLAlchemy statement (ORM or Core)."""
        try:
            with self.session_scope() as session:
                result = session.execute(statement)
                session.commit()
                return result
        except SQLAlchemyError as e:
            raise RuntimeError(f"Statement execution failed: {e}")

    def get_engine(self):
        return self.engine

    def get_session(self):
        return self.Session()