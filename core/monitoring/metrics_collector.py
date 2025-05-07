"""
Metrics Collector for LLMs.txt Security Analysis Platform

This module provides tools for collecting and storing metrics about the platform's
performance, usage, and health.
"""

import os
import time
import logging
import json
import sqlite3
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

class MetricsCollector:
    """
    Collects and stores metrics about the platform.
    
    This class provides methods to collect, store, and retrieve metrics about
    the platform's performance, usage, and health.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the metrics collector with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for metrics collection.
                   Supported keys:
                   - db_path: Path to the database file
                   - collection_interval: Interval between metrics collection in seconds
                   - retention_days: Number of days to retain metrics
                   - metrics_types: List of metric types to collect
        """
        self.config = config or {}
        self.db_path = self.config.get("db_path", "researchdb/llms_metadata.db")
        self.collection_interval = self.config.get("collection_interval", 60)
        self.retention_days = self.config.get("retention_days", 30)
        self.metrics_types = self.config.get("metrics_types", [
            "performance", "usage", "health", "analysis"
        ])
        
        self.metrics_cache = {}
        self.collection_thread = None
        self.running = False
        
        # Initialize database
        self._init_database()
        
        logger.info("Metrics collector initialized")
    
    def _init_database(self):
        """Initialize the metrics database tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create metrics table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    metric_data TEXT
                )
            ''')
            
            # Create index on timestamp and metric_type
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp_type
                ON metrics (timestamp, metric_type)
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info("Metrics database initialized")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize metrics database: {e}")
    
    def collect_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics from various sources.
        
        Returns:
            Dictionary with collected metrics
        """
        logger.debug("Collecting metrics")
        
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "metrics": {}
        }
        
        # Collect performance metrics
        if "performance" in self.metrics_types:
            performance_metrics = self._collect_performance_metrics()
            metrics["metrics"]["performance"] = performance_metrics
        
        # Collect usage metrics
        if "usage" in self.metrics_types:
            usage_metrics = self._collect_usage_metrics()
            metrics["metrics"]["usage"] = usage_metrics
        
        # Collect health metrics
        if "health" in self.metrics_types:
            health_metrics = self._collect_health_metrics()
            metrics["metrics"]["health"] = health_metrics
        
        # Collect analysis metrics
        if "analysis" in self.metrics_types:
            analysis_metrics = self._collect_analysis_metrics()
            metrics["metrics"]["analysis"] = analysis_metrics
        
        # Cache the metrics
        self.metrics_cache = metrics
        
        # Store metrics in database
        self._store_metrics(metrics)
        
        logger.debug("Metrics collection complete")
        
        return metrics
    
    def _collect_performance_metrics(self) -> Dict[str, Any]:
        """
        Collect performance metrics.
        
        Returns:
            Dictionary with performance metrics
        """
        metrics = {}
        
        try:
            import psutil
            
            # CPU usage
            metrics["cpu_percent"] = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            metrics["memory_percent"] = memory.percent
            metrics["memory_used_mb"] = memory.used / (1024 * 1024)
            metrics["memory_available_mb"] = memory.available / (1024 * 1024)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            metrics["disk_percent"] = disk.percent
            metrics["disk_used_gb"] = disk.used / (1024 * 1024 * 1024)
            metrics["disk_free_gb"] = disk.free / (1024 * 1024 * 1024)
            
            # Process information
            process = psutil.Process()
            metrics["process_cpu_percent"] = process.cpu_percent(interval=1)
            metrics["process_memory_mb"] = process.memory_info().rss / (1024 * 1024)
            metrics["process_threads"] = process.num_threads()
            
            # Network information
            network = psutil.net_io_counters()
            metrics["network_bytes_sent"] = network.bytes_sent
            metrics["network_bytes_recv"] = network.bytes_recv
            
        except ImportError:
            logger.warning("psutil not installed, using limited performance metrics")
            
            # Basic metrics without psutil
            metrics["timestamp"] = time.time()
            
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
        
        return metrics
    
    def _collect_usage_metrics(self) -> Dict[str, Any]:
        """
        Collect usage metrics.
        
        Returns:
            Dictionary with usage metrics
        """
        metrics = {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count total analyses
            cursor.execute("SELECT COUNT(*) FROM analyses")
            metrics["total_analyses"] = cursor.fetchone()[0]
            
            # Count analyses in the last 24 hours
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM analyses WHERE timestamp > ?", (yesterday,))
            metrics["analyses_last_24h"] = cursor.fetchone()[0]
            
            # Count unique files analyzed
            cursor.execute("SELECT COUNT(DISTINCT file_path) FROM analyses")
            metrics["unique_files_analyzed"] = cursor.fetchone()[0]
            
            # Count findings by severity
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM findings 
                GROUP BY severity
            """)
            severity_counts = {}
            for severity, count in cursor.fetchall():
                severity_counts[severity] = count
            metrics["findings_by_severity"] = severity_counts
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error collecting usage metrics from database: {e}")
        except Exception as e:
            logger.error(f"Error collecting usage metrics: {e}")
        
        return metrics
    
    def _collect_health_metrics(self) -> Dict[str, Any]:
        """
        Collect health metrics.
        
        Returns:
            Dictionary with health metrics
        """
        metrics = {}
        
        try:
            # Check if health checker is available
            from core.monitoring.health_check import HealthChecker
            
            # Create health checker with same database path
            health_checker = HealthChecker({"db_path": self.db_path})
            
            # Get health report
            health_report = health_checker.get_health_report()
            
            # Extract key health metrics
            metrics["overall_status"] = health_report["overall_status"]
            metrics["healthy_components"] = health_report["summary"]["healthy_components"]
            metrics["degraded_components"] = health_report["summary"]["degraded_components"]
            metrics["unhealthy_components"] = health_report["summary"]["unhealthy_components"]
            
            # Add component statuses
            component_statuses = {}
            for component, data in health_report["components"].items():
                component_statuses[component] = data["status"]
            metrics["component_statuses"] = component_statuses
            
        except ImportError:
            logger.warning("Health checker not available, skipping health metrics")
        except Exception as e:
            logger.error(f"Error collecting health metrics: {e}")
        
        return metrics
    
    def _collect_analysis_metrics(self) -> Dict[str, Any]:
        """
        Collect analysis-specific metrics.
        
        Returns:
            Dictionary with analysis metrics
        """
        metrics = {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count findings by type
            cursor.execute("""
                SELECT finding_type, COUNT(*) 
                FROM findings 
                GROUP BY finding_type
            """)
            type_counts = {}
            for finding_type, count in cursor.fetchall():
                type_counts[finding_type] = count
            metrics["findings_by_type"] = type_counts
            
            # Count findings by analyzer
            cursor.execute("""
                SELECT analyzer, COUNT(*) 
                FROM findings 
                GROUP BY analyzer
            """)
            analyzer_counts = {}
            for analyzer, count in cursor.fetchall():
                analyzer_counts[analyzer] = count
            metrics["findings_by_analyzer"] = analyzer_counts
            
            # Get average analysis time
            cursor.execute("""
                SELECT AVG(duration) 
                FROM analyses 
                WHERE duration IS NOT NULL
            """)
            avg_duration = cursor.fetchone()[0]
            metrics["avg_analysis_duration"] = avg_duration if avg_duration else 0
            
            # Get max analysis time
            cursor.execute("""
                SELECT MAX(duration) 
                FROM analyses 
                WHERE duration IS NOT NULL
            """)
            max_duration = cursor.fetchone()[0]
            metrics["max_analysis_duration"] = max_duration if max_duration else 0
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error collecting analysis metrics from database: {e}")
        except Exception as e:
            logger.error(f"Error collecting analysis metrics: {e}")
        
        return metrics
    
    def _store_metrics(self, metrics: Dict[str, Any]):
        """
        Store metrics in the database.
        
        Args:
            metrics: Dictionary with metrics to store
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            timestamp = metrics["timestamp"]
            
            # Store each metric
            for metric_type, type_metrics in metrics["metrics"].items():
                for metric_name, metric_value in type_metrics.items():
                    # Handle nested metrics
                    if isinstance(metric_value, dict):
                        # Store as JSON string
                        cursor.execute('''
                            INSERT INTO metrics (timestamp, metric_type, metric_name, metric_data)
                            VALUES (?, ?, ?, ?)
                        ''', (timestamp, metric_type, metric_name, json.dumps(metric_value)))
                    else:
                        # Store as numeric value
                        cursor.execute('''
                            INSERT INTO metrics (timestamp, metric_type, metric_name, metric_value)
                            VALUES (?, ?, ?, ?)
                        ''', (timestamp, metric_type, metric_name, metric_value))
            
            conn.commit()
            
            # Clean up old metrics
            self._cleanup_old_metrics(cursor)
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error storing metrics in database: {e}")
        except Exception as e:
            logger.error(f"Error storing metrics: {e}")
    
    def _cleanup_old_metrics(self, cursor):
        """
        Clean up old metrics from the database.
        
        Args:
            cursor: SQLite cursor
        """
        try:
            # Calculate cutoff date
            cutoff_date = (datetime.now() - timedelta(days=self.retention_days)).isoformat()
            
            # Delete old metrics
            cursor.execute('''
                DELETE FROM metrics
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old metrics")
                
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up old metrics: {e}")
    
    def get_metrics(self, metric_type: Optional[str] = None, 
                   start_time: Optional[str] = None, 
                   end_time: Optional[str] = None) -> Dict[str, Any]:
        """
        Get metrics from the database.
        
        Args:
            metric_type: Type of metrics to retrieve (optional)
            start_time: Start time for metrics (ISO format, optional)
            end_time: End time for metrics (ISO format, optional)
            
        Returns:
            Dictionary with metrics
        """
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "metrics": {}
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable row factory for named columns
            cursor = conn.cursor()
            
            # Build query
            query = "SELECT * FROM metrics"
            params = []
            
            conditions = []
            if metric_type:
                conditions.append("metric_type = ?")
                params.append(metric_type)
            
            if start_time:
                conditions.append("timestamp >= ?")
                params.append(start_time)
            
            if end_time:
                conditions.append("timestamp <= ?")
                params.append(end_time)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            # Add order by timestamp
            query += " ORDER BY timestamp"
            
            # Execute query
            cursor.execute(query, params)
            
            # Process results
            for row in cursor:
                row_dict = dict(row)
                metric_type = row_dict["metric_type"]
                metric_name = row_dict["metric_name"]
                
                # Initialize metric type if not exists
                if metric_type not in metrics["metrics"]:
                    metrics["metrics"][metric_type] = {}
                
                # Initialize metric name if not exists
                if metric_name not in metrics["metrics"][metric_type]:
                    metrics["metrics"][metric_type][metric_name] = []
                
                # Add metric value or data
                if row_dict["metric_value"] is not None:
                    value = row_dict["metric_value"]
                else:
                    # Parse JSON data
                    value = json.loads(row_dict["metric_data"]) if row_dict["metric_data"] else None
                
                # Add to metrics list
                metrics["metrics"][metric_type][metric_name].append({
                    "timestamp": row_dict["timestamp"],
                    "value": value
                })
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error retrieving metrics from database: {e}")
        except Exception as e:
            logger.error(f"Error retrieving metrics: {e}")
        
        return metrics
    
    def start_collection(self, interval: Optional[int] = None):
        """
        Start periodic metrics collection.
        
        Args:
            interval: Collection interval in seconds (overrides config)
        """
        if interval is not None:
            self.collection_interval = interval
        
        logger.info(f"Starting metrics collection with interval {self.collection_interval}s")
        
        self.running = True
        
        def collect_loop():
            while self.running:
                try:
                    self.collect_metrics()
                except Exception as e:
                    logger.error(f"Metrics collection failed: {e}")
                
                time.sleep(self.collection_interval)
        
        # Start collection in a background thread
        self.collection_thread = threading.Thread(target=collect_loop, daemon=True)
        self.collection_thread.start()
        
        return self.collection_thread
    
    def stop_collection(self):
        """Stop periodic metrics collection."""
        logger.info("Stopping metrics collection")
        self.running = False
        
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
            self.collection_thread = None