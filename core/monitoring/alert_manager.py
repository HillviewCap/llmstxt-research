"""
Alert Manager for LLMs.txt Security Analysis Platform

This module provides tools for managing alerts based on metrics and health checks,
including alert generation, notification, and tracking.
"""

import os
import time
import logging
import json
import smtplib
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

class AlertManager:
    """
    Manages alerts for the platform.
    
    This class provides methods to generate, notify, and track alerts based on
    metrics and health checks.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the alert manager with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for alert management.
                   Supported keys:
                   - db_path: Path to the database file
                   - check_interval: Interval between alert checks in seconds
                   - alert_rules: List of alert rules
                   - notification_channels: List of notification channels
                   - notification_throttle: Minimum time between notifications in seconds
        """
        self.config = config or {}
        self.db_path = self.config.get("db_path", "researchdb/llms_metadata.db")
        self.check_interval = self.config.get("check_interval", 300)  # 5 minutes
        self.alert_rules = self.config.get("alert_rules", [])
        self.notification_channels = self.config.get("notification_channels", [])
        self.notification_throttle = self.config.get("notification_throttle", 3600)  # 1 hour
        
        self.last_notifications = {}  # Track last notification time for each alert
        self.active_alerts = {}  # Track currently active alerts
        self.check_thread = None
        self.running = False
        
        # Initialize database
        self._init_database()
        
        logger.info("Alert manager initialized")
    
    def _init_database(self):
        """Initialize the alerts database tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create alerts table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    alert_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_at TEXT
                )
            ''')
            
            # Create notifications table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    details TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info("Alerts database initialized")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize alerts database: {e}")
    
    def check_alerts(self) -> List[Dict[str, Any]]:
        """
        Check for alerts based on metrics and health checks.
        
        Returns:
            List of triggered alerts
        """
        logger.debug("Checking for alerts")
        
        triggered_alerts = []
        
        try:
            # Check if metrics collector is available
            from core.monitoring.metrics_collector import MetricsCollector
            metrics_collector = MetricsCollector({"db_path": self.db_path})
            
            # Get latest metrics
            metrics = metrics_collector.collect_metrics()
            
            # Check if health checker is available
            from core.monitoring.health_check import HealthChecker
            health_checker = HealthChecker({"db_path": self.db_path})
            
            # Get health report
            health = health_checker.check_health()
            
            # Check each alert rule
            for rule in self.alert_rules:
                alert_id = rule.get("id")
                alert_name = rule.get("name")
                alert_type = rule.get("type")
                severity = rule.get("severity", "warning")
                conditions = rule.get("conditions", [])
                
                # Skip rules without ID or conditions
                if not alert_id or not conditions:
                    continue
                
                # Check conditions based on alert type
                if alert_type == "metric":
                    # Check metric conditions
                    for condition in conditions:
                        metric_type = condition.get("metric_type")
                        metric_name = condition.get("metric_name")
                        operator = condition.get("operator")
                        threshold = condition.get("threshold")
                        
                        # Skip incomplete conditions
                        if not all([metric_type, metric_name, operator, threshold is not None]):
                            continue
                        
                        # Get metric value
                        try:
                            metric_value = metrics["metrics"][metric_type][metric_name]
                            
                            # Handle dict metrics
                            if isinstance(metric_value, dict):
                                # Use specified key or skip
                                metric_key = condition.get("metric_key")
                                if not metric_key or metric_key not in metric_value:
                                    continue
                                metric_value = metric_value[metric_key]
                            
                            # Compare with threshold
                            if operator == ">" and metric_value > threshold:
                                triggered_alerts.append(self._create_alert(
                                    alert_id, alert_name, severity,
                                    f"{metric_type}.{metric_name} ({metric_value}) > {threshold}",
                                    {"metric_value": metric_value, "threshold": threshold}
                                ))
                            elif operator == ">=" and metric_value >= threshold:
                                triggered_alerts.append(self._create_alert(
                                    alert_id, alert_name, severity,
                                    f"{metric_type}.{metric_name} ({metric_value}) >= {threshold}",
                                    {"metric_value": metric_value, "threshold": threshold}
                                ))
                            elif operator == "<" and metric_value < threshold:
                                triggered_alerts.append(self._create_alert(
                                    alert_id, alert_name, severity,
                                    f"{metric_type}.{metric_name} ({metric_value}) < {threshold}",
                                    {"metric_value": metric_value, "threshold": threshold}
                                ))
                            elif operator == "<=" and metric_value <= threshold:
                                triggered_alerts.append(self._create_alert(
                                    alert_id, alert_name, severity,
                                    f"{metric_type}.{metric_name} ({metric_value}) <= {threshold}",
                                    {"metric_value": metric_value, "threshold": threshold}
                                ))
                            elif operator == "==" and metric_value == threshold:
                                triggered_alerts.append(self._create_alert(
                                    alert_id, alert_name, severity,
                                    f"{metric_type}.{metric_name} ({metric_value}) == {threshold}",
                                    {"metric_value": metric_value, "threshold": threshold}
                                ))
                            elif operator == "!=" and metric_value != threshold:
                                triggered_alerts.append(self._create_alert(
                                    alert_id, alert_name, severity,
                                    f"{metric_type}.{metric_name} ({metric_value}) != {threshold}",
                                    {"metric_value": metric_value, "threshold": threshold}
                                ))
                        except (KeyError, TypeError):
                            # Metric not found or not a comparable type
                            pass
                
                elif alert_type == "health":
                    # Check health conditions
                    for condition in conditions:
                        component = condition.get("component")
                        status = condition.get("status")
                        
                        # Skip incomplete conditions
                        if not component or not status:
                            continue
                        
                        # Check overall health
                        if component == "overall" and health["overall_status"] == status:
                            triggered_alerts.append(self._create_alert(
                                alert_id, alert_name, severity,
                                f"Overall health status is {status}",
                                {"health_status": health["overall_status"]}
                            ))
                        # Check component health
                        elif component in health["components"] and health["components"][component]["status"] == status:
                            triggered_alerts.append(self._create_alert(
                                alert_id, alert_name, severity,
                                f"Component {component} health status is {status}",
                                {"component": component, "health_status": status}
                            ))
        
        except ImportError:
            logger.warning("Metrics collector or health checker not available, skipping some alert checks")
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
        
        # Process triggered alerts
        if triggered_alerts:
            self._process_alerts(triggered_alerts)
        
        return triggered_alerts
    
    def _create_alert(self, alert_id: str, alert_name: str, severity: str, 
                     message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create an alert object.
        
        Args:
            alert_id: Unique identifier for the alert rule
            alert_name: Human-readable name for the alert
            severity: Severity level (critical, high, medium, low)
            message: Alert message
            details: Additional details about the alert
            
        Returns:
            Alert object
        """
        # Generate unique instance ID for this alert occurrence
        instance_id = f"{alert_id}-{int(time.time())}"
        
        return {
            "id": instance_id,
            "alert_id": alert_id,
            "alert_name": alert_name,
            "severity": severity,
            "status": "active",
            "message": message,
            "details": details or {},
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
    
    def _process_alerts(self, alerts: List[Dict[str, Any]]):
        """
        Process triggered alerts.
        
        Args:
            alerts: List of triggered alerts
        """
        # Store alerts in database
        for alert in alerts:
            self._store_alert(alert)
            
            # Check if alert is already active
            if alert["alert_id"] in self.active_alerts:
                # Update existing alert
                self.active_alerts[alert["alert_id"]]["updated_at"] = alert["updated_at"]
                logger.info(f"Updated active alert: {alert['alert_name']} ({alert['severity']})")
            else:
                # New alert
                self.active_alerts[alert["alert_id"]] = alert
                logger.warning(f"New alert triggered: {alert['alert_name']} ({alert['severity']})")
                
                # Send notification for new alert
                self._send_notifications(alert)
    
    def _store_alert(self, alert: Dict[str, Any]):
        """
        Store alert in the database.
        
        Args:
            alert: Alert object to store
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if alert with this ID already exists
            cursor.execute('''
                SELECT id FROM alerts
                WHERE alert_id = ? AND status = 'active'
            ''', (alert["alert_id"],))
            
            existing_alert = cursor.fetchone()
            
            if existing_alert:
                # Update existing alert
                cursor.execute('''
                    UPDATE alerts
                    SET message = ?, details = ?, updated_at = ?
                    WHERE alert_id = ? AND status = 'active'
                ''', (
                    alert["message"],
                    json.dumps(alert["details"]),
                    alert["updated_at"],
                    alert["alert_id"]
                ))
            else:
                # Insert new alert
                cursor.execute('''
                    INSERT INTO alerts (
                        alert_id, alert_name, severity, status, message, 
                        details, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert["alert_id"],
                    alert["alert_name"],
                    alert["severity"],
                    alert["status"],
                    alert["message"],
                    json.dumps(alert["details"]),
                    alert["created_at"],
                    alert["updated_at"]
                ))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error storing alert in database: {e}")
    
    def _send_notifications(self, alert: Dict[str, Any]):
        """
        Send notifications for an alert.
        
        Args:
            alert: Alert object to send notifications for
        """
        # Check notification throttling
        current_time = time.time()
        last_notification_time = self.last_notifications.get(alert["alert_id"], 0)
        
        if current_time - last_notification_time < self.notification_throttle:
            logger.info(f"Skipping notification for alert {alert['alert_id']} due to throttling")
            return
        
        # Update last notification time
        self.last_notifications[alert["alert_id"]] = current_time
        
        # Send notifications to each channel
        for channel in self.notification_channels:
            channel_type = channel.get("type")
            channel_config = channel.get("config", {})
            
            if channel_type == "email":
                self._send_email_notification(alert, channel_config)
            elif channel_type == "webhook":
                self._send_webhook_notification(alert, channel_config)
            elif channel_type == "log":
                self._send_log_notification(alert, channel_config)
            else:
                logger.warning(f"Unknown notification channel type: {channel_type}")
    
    def _send_email_notification(self, alert: Dict[str, Any], config: Dict[str, Any]):
        """
        Send email notification for an alert.
        
        Args:
            alert: Alert object to send notification for
            config: Email configuration
        """
        try:
            # Get email configuration
            smtp_server = config.get("smtp_server")
            smtp_port = config.get("smtp_port", 587)
            smtp_username = config.get("smtp_username")
            smtp_password = config.get("smtp_password")
            sender = config.get("sender")
            recipients = config.get("recipients", [])
            
            # Skip if missing required configuration
            if not all([smtp_server, smtp_username, smtp_password, sender, recipients]):
                logger.warning("Missing required email configuration, skipping email notification")
                return
            
            # Create email message
            msg = MIMEMultipart()
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"Alert: {alert['alert_name']} ({alert['severity'].upper()})"
            
            # Create email body
            body = f"""
            <html>
            <body>
                <h2>Alert: {alert['alert_name']}</h2>
                <p><strong>Severity:</strong> {alert['severity'].upper()}</p>
                <p><strong>Status:</strong> {alert['status']}</p>
                <p><strong>Message:</strong> {alert['message']}</p>
                <p><strong>Time:</strong> {alert['created_at']}</p>
                <h3>Details:</h3>
                <pre>{json.dumps(alert['details'], indent=2)}</pre>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, "html"))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Sent email notification for alert {alert['alert_id']}")
            
            # Record notification
            self._record_notification(alert["id"], "email", "sent")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            self._record_notification(alert["id"], "email", "failed", str(e))
    
    def _send_webhook_notification(self, alert: Dict[str, Any], config: Dict[str, Any]):
        """
        Send webhook notification for an alert.
        
        Args:
            alert: Alert object to send notification for
            config: Webhook configuration
        """
        try:
            import requests
            
            # Get webhook configuration
            url = config.get("url")
            headers = config.get("headers", {})
            
            # Skip if missing required configuration
            if not url:
                logger.warning("Missing webhook URL, skipping webhook notification")
                return
            
            # Create payload
            payload = {
                "alert": alert
            }
            
            # Send webhook request
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Sent webhook notification for alert {alert['alert_id']}")
                self._record_notification(alert["id"], "webhook", "sent")
            else:
                logger.warning(f"Webhook notification failed with status {response.status_code}: {response.text}")
                self._record_notification(alert["id"], "webhook", "failed", f"Status {response.status_code}: {response.text}")
            
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            self._record_notification(alert["id"], "webhook", "failed", str(e))
    
    def _send_log_notification(self, alert: Dict[str, Any], config: Dict[str, Any]):
        """
        Send log notification for an alert.
        
        Args:
            alert: Alert object to send notification for
            config: Log configuration
        """
        try:
            # Get log configuration
            log_level = config.get("level", "warning").upper()
            
            # Get logger
            alert_logger = logging.getLogger("AlertNotification")
            
            # Log alert
            log_message = f"ALERT [{alert['severity'].upper()}]: {alert['alert_name']} - {alert['message']}"
            
            if log_level == "DEBUG":
                alert_logger.debug(log_message)
            elif log_level == "INFO":
                alert_logger.info(log_message)
            elif log_level == "WARNING":
                alert_logger.warning(log_message)
            elif log_level == "ERROR":
                alert_logger.error(log_message)
            elif log_level == "CRITICAL":
                alert_logger.critical(log_message)
            else:
                alert_logger.warning(log_message)
            
            logger.info(f"Sent log notification for alert {alert['alert_id']}")
            self._record_notification(alert["id"], "log", "sent")
            
        except Exception as e:
            logger.error(f"Error sending log notification: {e}")
            self._record_notification(alert["id"], "log", "failed", str(e))
    
    def _record_notification(self, alert_id: str, channel: str, status: str, details: Optional[str] = None):
        """
        Record notification in the database.
        
        Args:
            alert_id: Alert ID
            channel: Notification channel
            status: Notification status
            details: Additional details
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert notification record
            cursor.execute('''
                INSERT INTO alert_notifications (
                    alert_id, channel, status, sent_at, details
                )
                VALUES (?, ?, ?, ?, ?)
            ''', (
                alert_id,
                channel,
                status,
                datetime.now().isoformat(),
                details
            ))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error recording notification in database: {e}")
    
    def resolve_alert(self, alert_id: str):
        """
        Resolve an active alert.
        
        Args:
            alert_id: ID of the alert to resolve
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update alert status
            cursor.execute('''
                UPDATE alerts
                SET status = 'resolved', resolved_at = ?
                WHERE alert_id = ? AND status = 'active'
            ''', (
                datetime.now().isoformat(),
                alert_id
            ))
            
            conn.commit()
            conn.close()
            
            # Remove from active alerts
            if alert_id in self.active_alerts:
                del self.active_alerts[alert_id]
                logger.info(f"Resolved alert: {alert_id}")
            
        except sqlite3.Error as e:
            logger.error(f"Error resolving alert in database: {e}")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all active alerts.
        
        Returns:
            List of active alerts
        """
        alerts = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable row factory for named columns
            cursor = conn.cursor()
            
            # Query active alerts
            cursor.execute('''
                SELECT * FROM alerts
                WHERE status = 'active'
                ORDER BY created_at DESC
            ''')
            
            # Process results
            for row in cursor:
                row_dict = dict(row)
                
                # Parse JSON details
                if row_dict["details"]:
                    row_dict["details"] = json.loads(row_dict["details"])
                else:
                    row_dict["details"] = {}
                
                alerts.append(row_dict)
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Error retrieving active alerts from database: {e}")
        
        return alerts
    
    def start_monitoring(self, interval: Optional[int] = None):
        """
        Start periodic alert checking.
        
        Args:
            interval: Check interval in seconds (overrides config)
        """
        if interval is not None:
            self.check_interval = interval
        
        logger.info(f"Starting alert monitoring with interval {self.check_interval}s")
        
        self.running = True
        
        def check_loop():
            while self.running:
                try:
                    self.check_alerts()
                except Exception as e:
                    logger.error(f"Alert checking failed: {e}")
                
                time.sleep(self.check_interval)
        
        # Start checking in a background thread
        self.check_thread = threading.Thread(target=check_loop, daemon=True)
        self.check_thread.start()
        
        return self.check_thread
    
    def stop_monitoring(self):
        """Stop periodic alert checking."""
        logger.info("Stopping alert monitoring")
        self.running = False
        
        if self.check_thread:
            self.check_thread.join(timeout=5)
            self.check_thread = None