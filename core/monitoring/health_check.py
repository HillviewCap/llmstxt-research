"""
Health Checker for LLMs.txt Security Analysis Platform

This module provides tools for checking the health of the platform components,
including database connectivity, file system access, and external dependencies.
"""

import os
import time
import logging
import json
import sqlite3
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class HealthChecker:
    """
    Checks the health of the platform components.
    
    This class provides methods to check the health of various components of the
    platform, including database connectivity, file system access, and external
    dependencies.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the health checker with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for health checking.
                   Supported keys:
                   - db_path: Path to the database file
                   - check_interval: Interval between health checks in seconds
                   - external_dependencies: List of external dependencies to check
                   - critical_components: List of components that must be healthy
        """
        self.config = config or {}
        self.db_path = self.config.get("db_path", "researchdb/llms_metadata.db")
        self.check_interval = self.config.get("check_interval", 60)
        self.external_dependencies = self.config.get("external_dependencies", [])
        self.critical_components = self.config.get("critical_components", ["database", "file_system"])
        
        self.last_check_time = 0
        self.last_check_result = {}
        
        logger.info("Health checker initialized")
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of all components.
        
        Returns:
            Dictionary with health check results
        """
        # Check if we need to run a health check
        current_time = time.time()
        if current_time - self.last_check_time < self.check_interval and self.last_check_result:
            logger.debug("Using cached health check results")
            return self.last_check_result
        
        logger.info("Running health check")
        
        # Initialize results
        results = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "components": {}
        }
        
        # Check database
        db_status, db_details = self._check_database()
        results["components"]["database"] = {
            "status": db_status,
            "details": db_details
        }
        
        # Check file system
        fs_status, fs_details = self._check_file_system()
        results["components"]["file_system"] = {
            "status": fs_status,
            "details": fs_details
        }
        
        # Check external dependencies
        for dependency in self.external_dependencies:
            dep_status, dep_details = self._check_external_dependency(dependency)
            results["components"][dependency] = {
                "status": dep_status,
                "details": dep_details
            }
        
        # Check system resources
        sys_status, sys_details = self._check_system_resources()
        results["components"]["system_resources"] = {
            "status": sys_status,
            "details": sys_details
        }
        
        # Determine overall status
        for component, data in results["components"].items():
            if data["status"] != "healthy" and component in self.critical_components:
                results["overall_status"] = "unhealthy"
                break
        
        # Update last check time and result
        self.last_check_time = current_time
        self.last_check_result = results
        
        logger.info(f"Health check complete: {results['overall_status']}")
        
        return results
    
    def _check_database(self) -> Tuple[str, Dict[str, Any]]:
        """
        Check database connectivity and health.
        
        Returns:
            Tuple of (status, details)
        """
        logger.debug("Checking database health")
        
        if not os.path.exists(self.db_path):
            return "unhealthy", {"error": "Database file not found"}
        
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if we can execute a simple query
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            
            if result and result[0] == 1:
                # Check database size
                db_size = os.path.getsize(self.db_path)
                
                # Check if we can access a table
                try:
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = cursor.fetchall()
                    table_count = len(tables)
                    
                    return "healthy", {
                        "size_bytes": db_size,
                        "table_count": table_count
                    }
                except sqlite3.Error as e:
                    return "degraded", {"error": f"Could not query tables: {e}"}
            else:
                return "unhealthy", {"error": "Database query failed"}
            
        except sqlite3.Error as e:
            return "unhealthy", {"error": f"Database connection failed: {e}"}
        finally:
            if 'conn' in locals():
                conn.close()
    
    def _check_file_system(self) -> Tuple[str, Dict[str, Any]]:
        """
        Check file system access and health.
        
        Returns:
            Tuple of (status, details)
        """
        logger.debug("Checking file system health")
        
        # Check if we can write to a temporary file
        try:
            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                tmp.write(b"test")
                tmp.flush()
                
                # Check if we can read from the file
                tmp.seek(0)
                content = tmp.read()
                
                if content == b"test":
                    # Check disk space
                    disk_usage = shutil.disk_usage(os.path.dirname(tmp.name))
                    free_space = disk_usage.free
                    total_space = disk_usage.total
                    
                    return "healthy", {
                        "free_space_bytes": free_space,
                        "total_space_bytes": total_space,
                        "free_space_percent": (free_space / total_space) * 100
                    }
                else:
                    return "degraded", {"error": "File content mismatch"}
        except Exception as e:
            return "unhealthy", {"error": f"File system access failed: {e}"}
    
    def _check_external_dependency(self, dependency: str) -> Tuple[str, Dict[str, Any]]:
        """
        Check external dependency health.
        
        Args:
            dependency: Name of the external dependency to check
            
        Returns:
            Tuple of (status, details)
        """
        logger.debug(f"Checking external dependency: {dependency}")
        
        # Check if dependency is a command-line tool
        if dependency in ["semgrep", "trufflehog", "yara"]:
            try:
                # Run the command with --version flag
                result = subprocess.run([dependency, "--version"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE, 
                                       timeout=5)
                
                if result.returncode == 0:
                    version = result.stdout.decode().strip()
                    return "healthy", {"version": version}
                else:
                    return "degraded", {"error": f"Command returned non-zero exit code: {result.returncode}"}
            except subprocess.TimeoutExpired:
                return "degraded", {"error": "Command timed out"}
            except FileNotFoundError:
                return "unhealthy", {"error": f"Command not found: {dependency}"}
            except Exception as e:
                return "unhealthy", {"error": f"Command execution failed: {e}"}
        
        # For other dependencies, return unknown status
        return "unknown", {"error": f"Unknown dependency type: {dependency}"}
    
    def _check_system_resources(self) -> Tuple[str, Dict[str, Any]]:
        """
        Check system resources health.
        
        Returns:
            Tuple of (status, details)
        """
        logger.debug("Checking system resources")
        
        try:
            import psutil
            
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Get disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Determine status based on resource usage
            if cpu_percent > 90 or memory_percent > 90 or disk_percent > 90:
                status = "degraded"
            else:
                status = "healthy"
            
            return status, {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_percent": disk_percent
            }
        except ImportError:
            logger.warning("psutil not installed, skipping system resources check")
            return "unknown", {"error": "psutil not installed"}
        except Exception as e:
            return "unknown", {"error": f"System resources check failed: {e}"}
    
    def get_health_report(self) -> Dict[str, Any]:
        """
        Get a comprehensive health report.
        
        Returns:
            Dictionary with health report
        """
        # Run health check
        health_check = self.check_health()
        
        # Create report
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": health_check["overall_status"],
            "components": health_check["components"],
            "summary": {
                "healthy_components": 0,
                "degraded_components": 0,
                "unhealthy_components": 0,
                "unknown_components": 0
            }
        }
        
        # Count component statuses
        for component, data in health_check["components"].items():
            status = data["status"]
            if status == "healthy":
                report["summary"]["healthy_components"] += 1
            elif status == "degraded":
                report["summary"]["degraded_components"] += 1
            elif status == "unhealthy":
                report["summary"]["unhealthy_components"] += 1
            else:
                report["summary"]["unknown_components"] += 1
        
        return report
    
    def start_monitoring(self, interval: Optional[int] = None):
        """
        Start periodic health monitoring.
        
        Args:
            interval: Monitoring interval in seconds (overrides config)
        """
        if interval is not None:
            self.check_interval = interval
        
        logger.info(f"Starting health monitoring with interval {self.check_interval}s")
        
        import threading
        
        def monitor():
            while True:
                try:
                    health = self.check_health()
                    if health["overall_status"] != "healthy":
                        logger.warning(f"System health is {health['overall_status']}")
                        
                        # Log unhealthy components
                        for component, data in health["components"].items():
                            if data["status"] != "healthy":
                                logger.warning(f"Component {component} is {data['status']}: {data['details']}")
                except Exception as e:
                    logger.error(f"Health monitoring failed: {e}")
                
                time.sleep(self.check_interval)
        
        # Start monitoring in a background thread
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        
        return thread