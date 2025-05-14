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
        
        # Add default values if not present
        if "venv_path" not in env_config:
            env_config["venv_path"] = ".venv"
        
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
    
    # Check if Python 3.12 is available for virtual environment
    try:
        result = subprocess.run(["python3.12", "--version"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               check=False)
        if result.returncode != 0:
            logger.warning("Python 3.12 is not available. It will be required for the virtual environment.")
            logger.warning("Please install Python 3.12 before proceeding.")
            return False
    except FileNotFoundError:
        logger.warning("Python 3.12 is not available. It will be required for the virtual environment.")
        logger.warning("Please install Python 3.12 before proceeding.")
        return False
    
    # Check if required tools are installed
    required_tools = ["pip", "git"]
    for tool in required_tools:
        try:
            subprocess.run([tool, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error(f"Required tool not found: {tool}")
            return False
    
    # Check if uv is installed, or install it
    try:
        subprocess.run(["uv", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        logger.info("uv package manager is available.")
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.info("uv package manager not found. Installing...")
        try:
            subprocess.run(["pip", "install", "uv"], check=True)
            logger.info("uv package manager installed successfully.")
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to install uv package manager: {e}")
            return False
    
    logger.info("All prerequisites met.")
    return True

def setup_virtual_environment(config):
    """Set up a Python 3.12 virtual environment using uv."""
    logger.info("Setting up virtual environment with Python 3.12 using uv...")
    
    venv_path = config.get("venv_path", ".venv")
    
    try:
        # Check if Python 3.12 is available
        python_cmd = "python3.12"
        try:
            result = subprocess.run([python_cmd, "--version"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   check=False)
            if result.returncode != 0:
                # Try alternative command on some systems
                python_cmd = "python3"
                result = subprocess.run([python_cmd, "--version"],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       check=True)
                version_output = result.stdout.decode().strip() if result.stdout else result.stderr.decode().strip()
                if "3.12" not in version_output:
                    logger.error(f"Python 3.12 is required, but found: {version_output}")
                    return False
        except FileNotFoundError:
            logger.error("Python 3.12 is not available. Please install Python 3.12.")
            return False
        
        # Check if uv is installed
        try:
            result = subprocess.run(["uv", "--version"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   check=False)
            if result.returncode != 0:
                logger.info("Installing uv package manager...")
                subprocess.run([python_cmd, "-m", "pip", "install", "uv"], check=True)
        except FileNotFoundError:
            logger.info("Installing uv package manager...")
            subprocess.run([python_cmd, "-m", "pip", "install", "uv"], check=True)
        
        # Create virtual environment using uv with Python 3.12
        if os.path.exists(venv_path):
            logger.info(f"Virtual environment already exists at {venv_path}")
            # Check if the environment is using Python 3.12
            python_path = os.path.join(venv_path, "bin", "python") if os.name != "nt" else os.path.join(venv_path, "Scripts", "python")
            if os.path.exists(python_path):
                result = subprocess.run([python_path, "--version"],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       check=True)
                version_output = result.stdout.decode().strip() if result.stdout else result.stderr.decode().strip()
                if "3.12" not in version_output:
                    logger.warning(f"Existing environment is not using Python 3.12. Recreating...")
                    shutil.rmtree(venv_path)
                    subprocess.run(["uv", "venv", venv_path, "--python", python_cmd], check=True)
            else:
                logger.warning(f"Existing environment appears to be corrupted. Recreating...")
                shutil.rmtree(venv_path)
                subprocess.run(["uv", "venv", venv_path, "--python", python_cmd], check=True)
        else:
            logger.info(f"Creating virtual environment at {venv_path}")
            subprocess.run(["uv", "venv", venv_path, "--python", python_cmd], check=True)
        
        # Verify the virtual environment was created correctly
        python_path = os.path.join(venv_path, "bin", "python") if os.name != "nt" else os.path.join(venv_path, "Scripts", "python")
        if not os.path.exists(python_path):
            logger.error(f"Failed to create virtual environment: python not found at {python_path}")
            return False
        
        # Verify Python version in the virtual environment
        result = subprocess.run([python_path, "--version"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               check=True)
        version_output = result.stdout.decode().strip() if result.stdout else result.stderr.decode().strip()
        if "3.12" not in version_output:
            logger.error(f"Virtual environment is not using Python 3.12: {version_output}")
            return False
        
        logger.info("Virtual environment set up successfully with Python 3.12.")
        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to set up virtual environment: {e}")
        return False

def install_dependencies(skip_deps, config):
    """Install dependencies using uv."""
    if skip_deps:
        logger.info("Skipping dependency installation.")
        return True
    
    logger.info("Installing dependencies using uv...")
    
    venv_path = config.get("venv_path", ".venv")
    
    try:
        # Install dependencies with uv directly
        logger.info("Installing requirements.txt...")
        subprocess.run(["uv", "pip", "install", "--python", "3.12", "-r", "requirements.txt"], check=True)
        
        if os.path.exists("tests/requirements-test.txt"):
            logger.info("Installing test requirements...")
            subprocess.run(["uv", "pip", "install", "--python", "3.12", "-r", "tests/requirements-test.txt"], check=True)
        
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
        # Get database configuration
        db_config = config.get("database", {})
        db_path = db_config.get("path", "researchdb/llms_metadata.db")
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Run the database initialization script using uv with Python 3.12
        init_script_path = "scripts/init_database.py"
        if os.path.exists(init_script_path):
            logger.info(f"Running database initialization script with uv and Python 3.12...")
            subprocess.run(["uv", "run", "--python", "3.12", init_script_path, "--db-path", db_path], check=True)
        else:
            # Fall back to direct initialization if script doesn't exist
            logger.warning(f"Database initialization script not found at {init_script_path}. Falling back to direct initialization.")
            # Create a temporary script for initialization
            temp_script = "scripts/temp_init_db.py"
            with open(temp_script, 'w') as f:
                f.write("""
import sys
import os
sys.path.append(os.getcwd())
from core.database.connector import DatabaseConnector
from core.database.migration import run_migrations

db_path = sys.argv[1] if len(sys.argv) > 1 else "researchdb/llms_metadata.db"
db = DatabaseConnector({"path": db_path})
run_migrations(db)
print(f'Database initialized successfully at {db_path}.')
""")
            
            # Run the temporary script with uv
            subprocess.run(["uv", "run", "--python", "3.12", temp_script, db_path], check=True)
            
            # Clean up the temporary script
            if os.path.exists(temp_script):
                os.remove(temp_script)
        
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
    
    # Set up virtual environment with Python 3.12
    if not setup_virtual_environment(config):
        logger.error("Virtual environment setup failed. Aborting deployment.")
        return 1
    
    # Install dependencies
    if not install_dependencies(args.skip_deps, config):
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