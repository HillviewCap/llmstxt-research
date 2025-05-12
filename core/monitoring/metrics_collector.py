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
from contextlib import contextmanager

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
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Enable WAL mode for better concurrency
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=10000")
                
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
                
            logger.info("Metrics database initialized with WAL mode")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize metrics database: {e}")
            
    @contextmanager
    def _get_db_connection(self, timeout=20.0):
        """Get a database connection with proper timeout settings."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=timeout)
            # Enable immediate transaction mode to reduce lock contention
            conn.isolation_level = 'IMMEDIATE'
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
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
            
            # Collect semgrep process metrics
            semgrep_metrics = self._collect_semgrep_process_metrics()
            metrics.update(semgrep_metrics)
            
        except ImportError:
            logger.warning("psutil not installed, using limited performance metrics")
            
            # Basic metrics without psutil
            metrics["timestamp"] = time.time()
            
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
        
        return metrics
    
    def _collect_semgrep_process_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics specifically for semgrep processes.
        
        Returns:
            Dictionary with semgrep process metrics
        """
        metrics = {}
        
        try:
            import psutil
            
            # Find all semgrep processes
            semgrep_processes = []
            total_memory_percent = 0.0
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'cpu_percent']):
                try:
                    # Check if this is a semgrep process
                    if proc.info['name'] == 'semgrep' or (
                        proc.info['cmdline'] and
                        any('semgrep' in cmd for cmd in proc.info['cmdline'] if cmd)
                    ):
                        # Get detailed process info
                        proc_info = {
                            'pid': proc.info['pid'],
                            'memory_percent': proc.info['memory_percent'],
                            'cpu_percent': proc.info['cpu_percent'] or proc.cpu_percent(interval=0.1),
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                            'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                            'running_time': time.time() - proc.create_time()
                        }
                        semgrep_processes.append(proc_info)
                        total_memory_percent += proc.info['memory_percent']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Store metrics
            metrics["semgrep_process_count"] = len(semgrep_processes)
            metrics["semgrep_memory_percent"] = total_memory_percent
            metrics["semgrep_processes"] = semgrep_processes
            
            # Log warning if there are lingering semgrep processes
            if len(semgrep_processes) > 0:
                long_running_processes = [p for p in semgrep_processes if p['running_time'] > 120]  # > 2 minutes
                if long_running_processes:
                    logger.warning(f"Found {len(long_running_processes)} long-running semgrep processes: {long_running_processes}")
                else:
                    logger.info(f"Found {len(semgrep_processes)} semgrep processes")
            
        except ImportError:
            logger.warning("psutil not installed, cannot collect semgrep process metrics")
        except Exception as e:
            logger.error(f"Error collecting semgrep process metrics: {e}")
        
        return metrics
    
    def _collect_usage_metrics(self) -> Dict[str, Any]:
        """
        Collect usage metrics.
        
        Returns:
            Dictionary with usage metrics
        """
        metrics = {}
        
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if tables exist before querying
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_analysis_results'")
                has_analysis_table = cursor.fetchone() is not None
                
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_findings'")
                has_findings_table = cursor.fetchone() is not None
                
                if has_analysis_table:
                    # Count total analyses
                    cursor.execute("SELECT COUNT(*) FROM security_analysis_results")
                    metrics["total_analyses"] = cursor.fetchone()[0]
                    
                    # Count analyses in the last 24 hours
                    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
                    cursor.execute("SELECT COUNT(*) FROM security_analysis_results WHERE analysis_timestamp > ?", (yesterday,))
                    metrics["analyses_last_24h"] = cursor.fetchone()[0]
                    
                    # Count unique files analyzed
                    cursor.execute("SELECT COUNT(DISTINCT url_id) FROM security_analysis_results")
                    metrics["unique_files_analyzed"] = cursor.fetchone()[0]
                else:
                    logger.warning("Table 'security_analysis_results' does not exist. Skipping related metrics.")
                    metrics["total_analyses"] = 0
                    metrics["analyses_last_24h"] = 0
                    metrics["unique_files_analyzed"] = 0
                
                if has_findings_table:
                    # Count findings by severity
                    cursor.execute("""
                        SELECT severity, COUNT(*)
                        FROM security_findings
                        GROUP BY severity
                    """)
                    severity_counts = {}
                    for severity, count in cursor.fetchall():
                        severity_counts[severity] = count
                    metrics["findings_by_severity"] = severity_counts
                else:
                    logger.warning("Table 'security_findings' does not exist. Skipping related metrics.")
                    metrics["findings_by_severity"] = {}
            
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
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if tables exist before querying
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_findings'")
                has_findings_table = cursor.fetchone() is not None
                
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_analysis_results'")
                has_analysis_table = cursor.fetchone() is not None
                
                if has_findings_table:
                    # Count findings by type
                    cursor.execute("""
                        SELECT finding_type, COUNT(*)
                        FROM security_findings
                        GROUP BY finding_type
                    """)
                    type_counts = {}
                    for finding_type, count in cursor.fetchall():
                        type_counts[finding_type] = count
                    metrics["findings_by_type"] = type_counts
                    
                    # Count findings by analyzer (if column exists)
                    try:
                        cursor.execute("""
                            SELECT analysis_id, COUNT(*)
                            FROM security_findings
                            GROUP BY analysis_id
                        """)
                        analyzer_counts = {}
                        for analyzer, count in cursor.fetchall():
                            analyzer_counts[f"analysis_{analyzer}"] = count
                        metrics["findings_by_analyzer"] = analyzer_counts
                    except sqlite3.OperationalError:
                        logger.warning("Column 'analyzer' does not exist in security_findings table")
                        metrics["findings_by_analyzer"] = {}
                else:
                    logger.warning("Table 'security_findings' does not exist. Skipping related metrics.")
                    metrics["findings_by_type"] = {}
                    metrics["findings_by_analyzer"] = {}
                
                if has_analysis_table:
                    # Get average analysis time
                    try:
                        cursor.execute("""
                            SELECT AVG(julianday(analysis_timestamp) - julianday(analysis_timestamp))
                            FROM security_analysis_results
                        """)
                        avg_duration = cursor.fetchone()[0]
                        metrics["avg_analysis_duration"] = avg_duration if avg_duration else 0
                        
                        # Get max analysis time
                        cursor.execute("""
                            SELECT MAX(julianday(analysis_timestamp) - julianday(analysis_timestamp))
                            FROM security_analysis_results
                        """)
                        max_duration = cursor.fetchone()[0]
                        metrics["max_analysis_duration"] = max_duration if max_duration else 0
                    except sqlite3.OperationalError:
                        logger.warning("Could not calculate duration metrics")
                        metrics["avg_analysis_duration"] = 0
                        metrics["max_analysis_duration"] = 0
                else:
                    logger.warning("Table 'security_analysis_results' does not exist. Skipping related metrics.")
                    metrics["avg_analysis_duration"] = 0
                    metrics["max_analysis_duration"] = 0
            
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
        max_retries = 5
        retry_delay = 0.5  # Start with 0.5 second delay
        
        for attempt in range(max_retries):
            try:
                with self._get_db_connection(timeout=30.0) as conn:
                    cursor = conn.cursor()
                    
                    timestamp = metrics["timestamp"]
                    start_time = time.time()
                    
                    # Store each metric in batches to reduce lock time
                    batch_size = 20  # Increased batch size for better performance
                    metric_batch = []
                    
                    for metric_type, type_metrics in metrics["metrics"].items():
                        for metric_name, metric_value in type_metrics.items():
                            # Handle different data types
                            if isinstance(metric_value, (dict, list)):
                                # Serialize complex data structures to JSON
                                metric_batch.append((timestamp, metric_type, metric_name, json.dumps(metric_value), None))
                            elif metric_value is not None and not isinstance(metric_value, (int, float, str, bool)):
                                # Convert any other non-standard types to string representation
                                metric_batch.append((timestamp, metric_type, metric_name, str(metric_value), None))
                            else:
                                # Store as numeric value
                                metric_batch.append((timestamp, metric_type, metric_name, None, metric_value))
                            
                            # Execute in batches
                            if len(metric_batch) >= batch_size:
                                self._execute_metric_batch(cursor, metric_batch)
                                metric_batch = []
                    
                    # Insert any remaining metrics
                    if metric_batch:
                        self._execute_metric_batch(cursor, metric_batch)
                    
                    # Log metrics storage time
                    metrics_time = time.time() - start_time
                    if metrics_time > 1.0:
                        logger.info(f"Metrics storage took {metrics_time:.2f}s")
                    
                    # Clean up old metrics in a separate transaction to avoid long locks
                    if attempt == 0:  # Only try cleanup on first attempt
                        self._cleanup_old_metrics_separate_connection()
                
                # If we get here, the operation was successful
                return
                
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    # Database is locked, retry after a delay
                    logger.warning(f"Database is locked, retrying in {retry_delay} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(retry_delay)
                    # Exponential backoff
                    retry_delay *= 2
                else:
                    # Either it's not a lock error or we've exhausted our retries
                    logger.error(f"Error storing metrics in database: {e}")
                    break
            except sqlite3.Error as e:
                logger.error(f"Error storing metrics in database: {e}")
                break
            except Exception as e:
                logger.error(f"Error storing metrics: {e}")
                break
    
    def _execute_metric_batch(self, cursor, metric_batch):
        """Execute a batch of metric insertions."""
        # Insert metrics with data (serialized complex types)
        data_metrics = [(t, mt, mn, md) for t, mt, mn, md, mv in metric_batch if md is not None]
        if data_metrics:
            cursor.executemany('''
                INSERT INTO metrics (timestamp, metric_type, metric_name, metric_data)
                VALUES (?, ?, ?, ?)
            ''', data_metrics)
        
        # Insert metrics with values (numeric types)
        value_metrics = [(t, mt, mn, mv) for t, mt, mn, md, mv in metric_batch if mv is not None]
        if value_metrics:
            cursor.executemany('''
                INSERT INTO metrics (timestamp, metric_type, metric_name, metric_value)
                VALUES (?, ?, ?, ?)
            ''', value_metrics)
    
    def _cleanup_old_metrics_separate_connection(self):
        """Clean up old metrics using a separate connection to avoid holding locks."""
        try:
            # Run cleanup in a separate thread to avoid blocking
            cleanup_thread = threading.Thread(target=self._cleanup_old_metrics_thread)
            cleanup_thread.daemon = True
            cleanup_thread.start()
        except Exception as e:
            logger.error(f"Failed to start cleanup thread: {e}")
    
    def _cleanup_old_metrics_thread(self):
        """Thread function to clean up old metrics."""
        try:
            with self._get_db_connection(timeout=10.0) as conn:
                cursor = conn.cursor()
                
                # Calculate cutoff date
                cutoff_date = (datetime.now() - timedelta(days=self.retention_days)).isoformat()
                
                # Delete old metrics in smaller batches to reduce lock time
                batch_size = 500  # Smaller batch size to reduce lock time
                total_deleted = 0
                max_batches = 5  # Limit the number of batches per cleanup to avoid long operations
                
                for batch in range(max_batches):
                    start_time = time.time()
                    
                    cursor.execute('''
                        DELETE FROM metrics
                        WHERE rowid IN (
                            SELECT rowid FROM metrics
                            WHERE timestamp < ?
                            LIMIT ?
                        )
                    ''', (cutoff_date, batch_size))
                    
                    deleted_count = cursor.rowcount
                    total_deleted += deleted_count
                    conn.commit()  # Commit after each batch
                    
                    # Log cleanup time if it's slow
                    batch_time = time.time() - start_time
                    if batch_time > 1.0:
                        logger.info(f"Metrics cleanup batch took {batch_time:.2f}s")
                    
                    # If we deleted less than the batch size, we're done
                    if deleted_count < batch_size:
                        break
                
                if total_deleted > 0:
                    logger.info(f"Cleaned up {total_deleted} old metrics")
                    
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up old metrics: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in cleanup thread: {e}")
    
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
            with self._get_db_connection() as conn:
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