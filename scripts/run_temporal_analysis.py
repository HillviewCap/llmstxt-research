#!/usr/bin/env python3
"""
Standalone Script for Temporal Analysis Pipeline

This script allows you to run just the temporal analysis pipeline without
executing the entire workflow. Useful for testing changes to the temporal
analysis components.
"""

import argparse
import json
import sys
import os
import subprocess
from typing import Dict, Any, Optional
from datetime import datetime

def check_dependencies():
    """Check and install required dependencies."""
    required_packages = [
        "sqlalchemy",
        "pyyaml",
        "pandas",
        "numpy"
    ]
    
    try:
        import importlib
        missing_packages = []
        
        for package in required_packages:
            try:
                importlib.import_module(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"Missing dependencies: {', '.join(missing_packages)}")
            print("Please install the required dependencies using:")
            print(f"uv pip install {' '.join(missing_packages)}")
            print("\nOr run the script with uv directly:")
            print(f"uv pip install {' '.join(missing_packages)} && uv run scripts/run_temporal_analysis.py [args]")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking dependencies: {e}", file=sys.stderr)
        sys.exit(1)

# Check dependencies before imports
check_dependencies()

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database.connector import DatabaseConnector
from core.temporal.integration import TemporalAnalysis
from core.database.schema import SecurityAnalysisResult


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run temporal analysis pipeline")
    
    parser.add_argument(
        "--url",
        type=str,
        required=True,
        help="URL or identifier for the content to analyze"
    )
    
    parser.add_argument(
        "--content",
        type=str,
        help="Content to analyze (if not provided, will attempt to load from file)"
    )
    
    parser.add_argument(
        "--content-file",
        type=str,
        help="File containing content to analyze"
    )
    
    parser.add_argument(
        "--db-url",
        type=str,
        default="sqlite:///researchdb/llms_metadata.db",
        help="Database URL (default: sqlite:///researchdb/llms_metadata.db)"
    )
    
    parser.add_argument(
        "--processed-content-id",
        type=int,
        help="ID of already processed content (optional)"
    )
    
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print JSON output"
    )
    
    return parser.parse_args()


def ensure_database_exists(db_url: str) -> None:
    """
    Check if the database exists and create it if it doesn't.
    
    Args:
        db_url: Database URL
    """
    if db_url.startswith('sqlite:///'):
        # Extract the database file path from the URL
        db_path = db_url.replace('sqlite:///', '')
        
        # Create the directory if it doesn't exist
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            print(f"Creating database directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)
        
        # Check if the database file exists
        if not os.path.exists(db_path):
            print(f"Database file does not exist: {db_path}")
            print("Initializing database schema...")
            
            # Import schema creation functions
            try:
                from core.database.schema import create_security_schema
                from core.temporal.schema import create_temporal_schema
                
                # Create engine and schemas
                from sqlalchemy import create_engine
                engine = create_engine(db_url)
                
                create_security_schema(engine)
                create_temporal_schema(engine)
                
                print("Database schema created successfully.")
            except Exception as e:
                print(f"Error creating database schema: {e}", file=sys.stderr)
                print("You may need to run scripts/init_database.py first.")
                sys.exit(1)


def run_temporal_analysis(
    url: str,
    content: str,
    db_url: str,
    processed_content_id: Optional[int] = None
) -> Dict[str, Any]:
    """
    Run the temporal analysis pipeline.
    
    Args:
        url: URL or identifier for the content
        content: Content to analyze
        db_url: Database URL
        processed_content_id: ID of already processed content (optional)
        
    Returns:
        Dictionary with temporal analysis results
    """
    # Ensure database exists
    ensure_database_exists(db_url)
    
    # Connect to database
    db_connector = DatabaseConnector(db_url)
    
    # Initialize temporal analysis
    temporal = TemporalAnalysis(db_connector)
    
    # Run temporal analysis
    result = temporal.process_content(url, content, processed_content_id)
    
    return result


def main():
    """Main entry point."""
    args = parse_args()
    
    print(f"Running temporal analysis for URL: {args.url}")
    
    # Get content from file if specified
    if args.content is None and args.content_file:
        try:
            print(f"Reading content from file: {args.content_file}")
            with open(args.content_file, 'r', encoding='utf-8') as f:
                content = f.read()
            print(f"Successfully read {len(content)} characters from file")
        except Exception as e:
            print(f"Error reading content file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        content = args.content
        if content:
            print(f"Using provided content string ({len(content)} characters)")
    
    # Validate required parameters
    if content is None:
        print("Error: Either --content or --content-file must be provided", file=sys.stderr)
        sys.exit(1)
    
    # Run temporal analysis
    try:
        print(f"Connecting to database: {args.db_url}")
        print("Initializing temporal analysis pipeline...")
        
        result = run_temporal_analysis(
            url=args.url,
            content=content,
            db_url=args.db_url,
            processed_content_id=args.processed_content_id
        )
        
        print("\nTemporal analysis completed successfully!")
        
        # Output results
        if args.pretty:
            print("\nResults:")
            print(json.dumps(result, indent=2, default=str))
        else:
            print(json.dumps(result, default=str))
        
        # Provide a summary of key results
        if result.get('is_new_version'):
            print("\nSummary: New version detected!")
        else:
            print("\nSummary: No new version detected.")
            
        if result.get('changes_detected'):
            print("Changes were detected in the content.")
            
            if result.get('suspicious_changes'):
                print(f"Found {len(result.get('suspicious_changes', []))} suspicious changes.")
                
            if result.get('gradual_modifications'):
                print(f"Found {len(result.get('gradual_modifications', []))} gradual modifications.")
        
        if result.get('trend_analysis'):
            print("Trend analysis completed successfully.")
            
    except Exception as e:
        print(f"Error running temporal analysis: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()