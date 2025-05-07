# LLMs.txt Security Analysis Platform: Configuration Guide

This guide explains how to configure the LLMs.txt Security Analysis Platform to customize its behavior for your specific needs.

## Configuration Files

The platform uses YAML configuration files located in the `config/` directory:

- `scoring_config.yaml`: Configure risk scoring parameters
- `reporting.yaml`: Configure reporting and alerting options
- `report_template.html`: HTML template for report generation

## Scoring Configuration

The `scoring_config.yaml` file controls how the platform scores and classifies security findings.

### Example Configuration

```yaml
# Sample configuration for the Risk Scoring System

scoring_model:
  dimensions:
    impact: 0.5
    likelihood: 0.3
    exposure: 0.2
  confidence_weight: 1.0

severity_thresholds:
  critical: 0.85
  high: 0.7
  medium: 0.5
  low: 0.3
  info: 0.0

category_keywords:
  credential_exposure:
    - password
    - api_key
    - secret
  prompt_injection:
    - prompt
    - injection
    - instruction
  code_execution:
    - exec
    - eval
    - code
  documentation_issue:
    - documentation
    - overview
    - introduction
```

### Configuration Options

#### Scoring Model

- `dimensions`: Weights for different risk dimensions
  - `impact`: Weight for the impact of a finding (0.0-1.0)
  - `likelihood`: Weight for the likelihood of exploitation (0.0-1.0)
  - `exposure`: Weight for the exposure level (0.0-1.0)
- `confidence_weight`: Multiplier for confidence level (0.0-1.0)

#### Severity Thresholds

- `critical`: Threshold for Critical severity (0.0-1.0)
- `high`: Threshold for High severity (0.0-1.0)
- `medium`: Threshold for Medium severity (0.0-1.0)
- `low`: Threshold for Low severity (0.0-1.0)
- `info`: Threshold for Informational severity (0.0-1.0)

#### Category Keywords

- Define keywords that help classify findings into categories
- Each category can have multiple keywords
- Add custom categories as needed

## Reporting Configuration

The `reporting.yaml` file controls how the platform generates reports and alerts.

### Example Configuration

```yaml
# Configuration for the Reporting System

# Alert System Settings
alert_system:
  # Default severity threshold for triggering alerts.
  # Possible values: INFO, LOW, MEDIUM, HIGH, CRITICAL
  severity_threshold: "HIGH"

  # Notification channels
  # Enable or disable specific channels and configure their parameters.
  notifications:
    log:
      enabled: true
      log_file: "alerts.log" # Path relative to the project root or absolute
    email:
      enabled: false # Disabled by default, requires mail server setup
      smtp_server: "smtp.example.com"
      smtp_port: 587
      smtp_user: "user@example.com"
      smtp_password: "password"
      sender_email: "alerts@llmstxt.example.com"
      recipient_emails: # List of emails
        - "admin1@example.com"
        - "security_team@example.com"

# Dashboard Settings
dashboard:
  # Example: default_time_range: "7d"
  pass

# Report Generator Settings
report_generator:
  # Example: custom_logo_path: "path/to/logo.png"
  pass
```

### Configuration Options

#### Alert System

- `severity_threshold`: Minimum severity level for triggering alerts
- `notifications`: Configuration for notification channels
  - `log`: Log file configuration
  - `email`: Email notification configuration
  - Add other channels as needed (Slack, Teams, webhooks, etc.)

#### Dashboard

- Future configuration options for the dashboard

#### Report Generator

- Future configuration options for the report generator

## Pipeline Configuration

You can pass a custom configuration file to the pipeline using the `--config` parameter:

```bash
python main.py --mode all --config path/to/custom_config.yaml
```

## Rules Configuration

### Semgrep Rules

Semgrep rules are stored in the `rules/semgrep/` directory as YAML files.

Example rule (`python_eval_injection.yml`):

```yaml
rules:
  - id: python-eval-injection
    pattern: eval(...) 
    message: "Potential code injection via eval()"
    languages: [python]
    severity: ERROR
```

### YARA Rules

YARA rules are stored in the `rules/yara/` directory as `.yar` files.

Example rule (`sample_llm_prompt_injection.yar`):

```
rule LLM_Prompt_Injection {
    meta:
        description = "Detects potential prompt injection attempts"
        severity = "high"
    strings:
        $s1 = "ignore previous instructions" nocase
        $s2 = "disregard all instructions" nocase
    condition:
        any of them
}
```

### Pattern Rules

Custom pattern rules are stored in the `rules/patterns/` directory as YAML files.

Example rule (`sample_llm_credential_patterns.yaml`):

```yaml
patterns:
  - id: api-key-pattern
    regex: 'api[_-]?key[_-]?[=:]\s*["'']([a-zA-Z0-9]{16,})["'']'
    description: "Potential API key exposure"
    severity: "high"
```

## Advanced Configuration

### Database Configuration

Database settings can be configured in your custom config file:

```yaml
db:
  path: "path/to/custom/database.db"
  # Additional database settings
```

### Performance Tuning

Performance settings can be configured in your custom config file:

```yaml
pipeline_workers: 8  # Number of parallel workers for analysis
batch_size: 100      # Batch size for processing
```

### Logging Configuration

Logging can be configured using Python's logging configuration:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)
```

## Configuration Best Practices

1. **Start with defaults**: Use the default configuration files as a starting point
2. **Make incremental changes**: Change one setting at a time and test
3. **Version control**: Keep your configuration files in version control
4. **Document changes**: Comment your configuration files to explain changes
5. **Test thoroughly**: Test configuration changes before deploying to production