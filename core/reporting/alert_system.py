"""
Alert System for LLMs.txt Security Analysis Platform

Responsibilities:
- Severity-based alerting
- Notification system (mocked)
- Threshold configuration
- Integration hooks for external systems (mocked)
"""

from typing import List, Dict, Any, Callable, Optional
import yaml
import logging
import smtplib
from email.mime.text import MIMEText
from pathlib import Path

# Setup basic logger for alerts
alert_logger = logging.getLogger("AlertSystem")
alert_logger.setLevel(logging.INFO)
# Prevent duplicate handlers if this module is reloaded
if not alert_logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    alert_logger.addHandler(console_handler)


class AlertSystem:
    DEFAULT_CONFIG_PATH = "config/reporting.yaml"
    SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path or self.DEFAULT_CONFIG_PATH)
        self.config = self._load_config()
        
        alert_settings = self.config.get("alert_system", {})
        self.severity_threshold = alert_settings.get("severity_threshold", "HIGH").upper()
        if self.severity_threshold not in self.SEVERITY_LEVELS:
            alert_logger.warning(f"Invalid severity_threshold '{self.severity_threshold}' in config. Defaulting to HIGH.")
            self.severity_threshold = "HIGH"

        self.notification_config = alert_settings.get("notifications", {})
        self._setup_log_notifier()

        self.notifiers: List[Callable[[str, Dict[str, Any]], None]] = []
        self._configure_notifiers()
        
        self.external_hooks: List[Callable[[Dict[str, Any]], None]] = []

    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            alert_logger.error(f"Configuration file not found at {self.config_path}. Using default settings.")
            return {}
        except yaml.YAMLError as e:
            alert_logger.error(f"Error parsing YAML configuration at {self.config_path}: {e}. Using default settings.")
            return {}

    def _setup_log_notifier(self):
        log_conf = self.notification_config.get("log", {})
        if log_conf.get("enabled", True): # Enabled by default if not specified
            log_file_path = log_conf.get("log_file", "alerts.log")
            
            # Ensure only one file handler is added, even if re-initialized
            if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(Path(log_file_path).resolve()) for h in alert_logger.handlers):
                file_handler = logging.FileHandler(log_file_path)
                file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                alert_logger.addHandler(file_handler)
            alert_logger.info(f"Alert logging enabled. Writing to {log_file_path}")

    def _configure_notifiers(self):
        # Log notifier (always active if logging is enabled)
        if self.notification_config.get("log", {}).get("enabled", True):
            self.notifiers.append(self.log_notifier)

        # Email notifier
        email_conf = self.notification_config.get("email", {})
        if email_conf.get("enabled", False):
            self.notifiers.append(self.email_notifier)
            alert_logger.info("Email notifications enabled.")
        else:
            alert_logger.info("Email notifications disabled by config.")
            
        # Add mock notifier if no other notifiers are configured, for basic feedback
        if not self.notifiers:
            self.notifiers.append(self.mock_notifier)
            alert_logger.info("No specific notifiers configured. Using mock notifier.")


    def set_threshold(self, severity: str):
        sev_upper = severity.upper()
        if sev_upper in self.SEVERITY_LEVELS:
            self.severity_threshold = sev_upper
            alert_logger.info(f"Alert severity threshold set to: {self.severity_threshold}")
        else:
            alert_logger.warning(f"Attempted to set invalid severity threshold: {severity}")

    def register_external_hook(self, hook: Callable[[Dict[str, Any]], None]):
        """Register an integration hook for external systems."""
        self.external_hooks.append(hook)

    def process_findings(self, findings: List[Dict[str, Any]]):
        """Process findings and trigger alerts as needed."""
        threshold_idx = self.SEVERITY_LEVELS.index(self.severity_threshold)
        for finding in findings:
            sev = finding.get("severity", "INFO").upper()
            if sev not in self.SEVERITY_LEVELS:
                alert_logger.warning(f"Finding {finding.get('id')} has unknown severity '{sev}'. Treating as INFO.")
                sev_idx = self.SEVERITY_LEVELS.index("INFO")
            else:
                sev_idx = self.SEVERITY_LEVELS.index(sev)
            
            if sev_idx >= threshold_idx:
                self.trigger_alert(finding)

    def trigger_alert(self, finding: Dict[str, Any]):
        """Trigger an alert and notify via all configured channels."""
        severity = finding.get('severity', 'INFO').upper()
        title = finding.get('title', 'Untitled Finding')
        description = finding.get('description', 'No description provided.')
        finding_id = finding.get('id', 'N/A')
        
        message = (
            f"ALERT ID: {finding_id}\n"
            f"Severity: {severity}\n"
            f"Title: {title}\n"
            f"Description: {description}\n"
            f"Source: {finding.get('source', 'Unknown')}\n"
            f"Timestamp: {finding.get('timestamp', 'N/A')}"
        )
        
        subject = f"LLMs.txt Security Alert: [{severity}] {title}"

        alert_logger.info(f"Triggering alert for finding ID {finding_id} (Severity: {severity})")
        for notifier_func in self.notifiers:
            try:
                notifier_func(subject, finding) # Pass full finding for more context
            except Exception as e:
                alert_logger.error(f"Error in notifier {notifier_func.__name__}: {e}")
        
        for hook in self.external_hooks:
            try:
                hook(finding)
            except Exception as e:
                alert_logger.error(f"Error in external hook {hook.__name__}: {e}")

    def log_notifier(self, subject: str, finding: Dict[str, Any]):
        """Logs alert details using the configured logger."""
        # The main trigger_alert method already logs the core alert.
        # This specific notifier could add more structured log data if needed,
        # but for now, the main log in trigger_alert is sufficient.
        # alert_logger.info(f"LOG NOTIFICATION: {subject}\nFinding Details: {finding}")
        pass # Primary logging is handled in trigger_alert

    def email_notifier(self, subject: str, finding: Dict[str, Any]):
        """Sends an email notification for an alert."""
        email_conf = self.notification_config.get("email", {})
        if not email_conf.get("enabled", False):
            return

        smtp_server = email_conf.get("smtp_server")
        smtp_port = email_conf.get("smtp_port", 587)
        smtp_user = email_conf.get("smtp_user")
        smtp_password = email_conf.get("smtp_password")
        sender_email = email_conf.get("sender_email")
        recipient_emails = email_conf.get("recipient_emails", [])

        if not all([smtp_server, sender_email, recipient_emails]):
            alert_logger.error("Email notifier is enabled but not fully configured (server, sender, or recipients missing).")
            return

        # Construct email body
        body_lines = [
            f"LLMs.txt Security Alert System has detected a new finding:",
            f"-------------------------------------------------------",
            f"Finding ID: {finding.get('id', 'N/A')}",
            f"Title: {finding.get('title', 'Untitled')}",
            f"Severity: {finding.get('severity', 'INFO').upper()}",
            f"Description: {finding.get('description', 'No description provided.')}",
            f"Source: {finding.get('source', 'Unknown')}",
            f"Timestamp: {finding.get('timestamp', 'N/A')}",
        ]
        if finding.get('evidence'):
            body_lines.append(f"Evidence: {finding.get('evidence')}")
        if finding.get('context'):
            body_lines.append(f"Context: {finding.get('context')}")
        if finding.get('remediation'):
            body_lines.append(f"Suggested Remediation: {finding.get('remediation')}")
        
        body = "\n".join(body_lines)
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipient_emails)

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_user and smtp_password: # Check if authentication is needed
                    server.starttls() # Upgrade connection to secure
                    server.login(smtp_user, smtp_password)
                server.sendmail(sender_email, recipient_emails, msg.as_string())
            alert_logger.info(f"Email alert sent to {', '.join(recipient_emails)} for finding ID {finding.get('id')}.")
        except smtplib.SMTPAuthenticationError as e:
            alert_logger.error(f"SMTP Authentication Error for email notifier: {e}. Check credentials for {smtp_user}.")
        except Exception as e:
            alert_logger.error(f"Failed to send email alert: {e}")

    @staticmethod
    def mock_notifier(subject: str, finding: Dict[str, Any]):
        """Mock notification system (prints to console via logger)."""
        alert_logger.info(f"[MockNotification] Subject: {subject}\nFinding: {finding.get('id')}")

    # Example: mock integration with an external system
    @staticmethod
    def mock_external_integration(finding: Dict[str, Any]):
        alert_logger.info(f"[MockExternalIntegration] Finding sent to external system: {finding.get('id')}")