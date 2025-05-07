import sys
from core.database.connector import DatabaseConnector
from core.database.schema import create_security_schema
from core.ml.schema import create_ml_schema

def run_migration():
    try:
        db = DatabaseConnector()
        engine = db.get_engine()
        create_security_schema(engine)
        create_ml_schema(engine)
        print("Migration completed: Security analysis and ML tables are up to date.")
    except Exception as e:
        print(f"Migration failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    run_migration()