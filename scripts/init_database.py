#!/usr/bin/env python
"""
Database Initialization Script

This script initializes the database with all required tables for the LLMs.txt Research project.
It creates both the security schema and the temporal schema.
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from core.database.connector import DatabaseConnector
from core.database.schema import create_security_schema
from core.temporal.schema import create_temporal_schema
from core.ml.schema import create_ml_schema

def init_database():
    """Initialize the database with all required tables."""
    try:
        # Ensure the database directory exists
        db_dir = os.path.join(project_root, "researchdb")
        os.makedirs(db_dir, exist_ok=True)
        
        print("Initializing database...")
        db = DatabaseConnector()
        engine = db.get_engine()
        
        # Create all schemas
        print("Creating security schema...")
        create_security_schema(engine)
        
        print("Creating temporal schema...")
        create_temporal_schema(engine)
        
        print("Creating ML schema...")
        create_ml_schema(engine)
        
        print("Database initialization completed successfully.")
    except Exception as e:
        print(f"Database initialization failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    init_database()