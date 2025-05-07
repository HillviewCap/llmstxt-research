from typing import Type, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

def add_record(session: Session, record: Any) -> None:
    """Add a record to the database."""
    try:
        session.add(record)
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        raise RuntimeError(f"Failed to add record: {e}")

def get_record_by_id(session: Session, model: Type, record_id: Any) -> Optional[Any]:
    """Retrieve a record by primary key."""
    try:
        return session.get(model, record_id)
    except SQLAlchemyError as e:
        raise RuntimeError(f"Failed to retrieve record: {e}")

def get_all_records(session: Session, model: Type) -> List[Any]:
    """Retrieve all records of a model."""
    try:
        return session.query(model).all()
    except SQLAlchemyError as e:
        raise RuntimeError(f"Failed to retrieve records: {e}")

def delete_record(session: Session, record: Any) -> None:
    """Delete a record from the database."""
    try:
        session.delete(record)
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        raise RuntimeError(f"Failed to delete record: {e}")