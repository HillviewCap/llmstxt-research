#!/usr/bin/env python3
"""
Deployment Script for LLMs.txt Security Analysis Platform

This script automates the deployment process for the platform, including:
- Environment setup
- Dependency installation
- Database initialization
- Configuration validation
"""

import os
import sys
import argparse
import subprocess
import logging
import json
import shutil
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Deployment")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Deploy LLMs.txt Security Analysis Platform")
    
    parser.add_argument("--env", choices=["dev", "test", "prod"], default="dev",
                       help="Deployment environment")
    
    parser.add_argument("--config", type=str, default="config/deployment_config.json",
                       help="Path to deployment configuration file")
    
    parser.add_argument("--skip-deps", action="store_true",
                       help="Skip dependency installation")
    
    parser.add_argument("--skip-db", action="store_true",
                       help="Skip database initialization")
    
    parser.add_argument("--backup", action="store_true",
                       help="Create backup before deployment")
    
    return parser.parse_args()

def load_config(config_path, env):
    """Load deployment configuration."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Get environment-specific configuration
        if env in config:
            env_config = config[env]
        else:
            logger.warning(f"No configuration found for environment '{env}'. Using default.")
            env_config = config.get("default", {})
        
        return env_config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        return {}
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in configuration file: {config_path}")
        return {}

def check_prerequisites():
    """Check if all prerequisites are met."""
    logger.info("Checking prerequisites...")
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        logger.error("Python 3.8 or higher is required.")
        return False
    
    # Check if required tools are installed
    required_tools = ["pip", "git"]
    for tool in required_tools:
        try:
            subprocess.run([tool, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error(f"Required tool not found: {tool}")
            return False
    
    logger.info("All prerequisites met.")
    return True

def install_dependencies(skip_deps):
    """Install dependencies."""
    if skip_deps:
        logger.info("Skipping dependency installation.")
        return True
    
    logger.info("Installing dependencies...")
    
    try:
        # Install Python dependencies
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
        
        # Install test dependencies
        subprocess.run(["pip", "install", "-r", "tests/requirements-test.txt"], check=True)
        
        logger.info("Dependencies installed successfully.")
        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to install dependencies: {e}")
        return False

def initialize_database(skip_db, config):
    """Initialize the database."""
    if skip_db:
        logger.info("Skipping database initialization.")
        return True
    
    logger.info("Initializing database...")
    
    try:
        # Import database connector
        sys.path.append(os.getcwd())
        from core.database.connector import DatabaseConnector
        from core.database.migration import run_migrations
        
        # Get database configuration
        db_config = config.get("database", {})
        db_path = db_config.get("path", "researchdb/llms_metadata.db")
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        db = DatabaseConnector({"path": db_path})
        
        # Run migrations
        run_migrations(db)
        
        logger.info(f"Database initialized successfully at {db_path}.")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False

def create_backup(config):
    """Create a backup of the current deployment."""
    logger.info("Creating backup...")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"backups/backup_{timestamp}"
    
    try:
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup database
        db_path = config.get("database", {}).get("path", "researchdb/llms_metadata.db")
        if os.path.exists(db_path):
            shutil.copy2(db_path, f"{backup_dir}/database.db")
        
        # Backup configuration
        config_dir = "config"
        if os.path.exists(config_dir):
            shutil.copytree(config_dir, f"{backup_dir}/config")
        
        logger.info(f"Backup created at {backup_dir}")
        return True
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return False

def validate_configuration(config):
    """Validate deployment configuration."""
    logger.info("Validating configuration...")
    
    # Check required configuration keys
    required_keys = ["database", "pipeline_workers"]
    for key in required_keys:
        if key not in config:
            logger.warning(f"Missing required configuration key: {key}")
    
    # Validate database configuration
    db_config = config.get("database", {})
    if "path" not in db_config:
        logger.warning("Missing database path in configuration.")
    
    # Validate pipeline configuration
    pipeline_workers = config.get("pipeline_workers", 0)
    if pipeline_workers <= 0:
        logger.warning("Invalid number of pipeline workers.")
    
    logger.info("Configuration validation complete.")
    return True

def setup_environment(env, config):
    """Set up the deployment environment."""
    logger.info(f"Setting up {env} environment...")
    
    # Create necessary directories
    directories = [
        "logs",
        "researchdb",
        "results"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Create environment-specific configuration
    env_config = {
        "environment": env,
        "timestamp": datetime.now().isoformat(),
        **config
    }
    
    # Save environment configuration
    with open(f"config/env_{env}.json", 'w') as f:
        json.dump(env_config, f, indent=2)
    
    logger.info(f"{env} environment set up successfully.")
    return True

def main():
    """Main deployment function."""
    args = parse_arguments()
    
    logger.info(f"Starting deployment for environment: {args.env}")
    
    # Check prerequisites
    if not check_prerequisites():
        logger.error("Prerequisites check failed. Aborting deployment.")
        return 1
    
    # Load configuration
    config = load_config(args.config, args.env)
    if not config:
        logger.error("Failed to load configuration. Aborting deployment.")
        return 1
    
    # Validate configuration
    if not validate_configuration(config):
        logger.warning("Configuration validation failed. Proceeding with caution.")
    
    # Create backup if requested
    if args.backup and not create_backup(config):
        logger.error("Backup creation failed. Aborting deployment.")
        return 1
    
    # Install dependencies
    if not install_dependencies(args.skip_deps):
        logger.error("Dependency installation failed. Aborting deployment.")
        return 1
    
    # Initialize database
    if not initialize_database(args.skip_db, config):
        logger.error("Database initialization failed. Aborting deployment.")
        return 1
    
    # Set up environment
    if not setup_environment(args.env, config):
        logger.error("Environment setup failed. Aborting deployment.")
        return 1
    
    logger.info(f"Deployment for environment {args.env} completed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())