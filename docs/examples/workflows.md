# LLMs.txt Security Analysis Platform: Example Workflows

This document provides detailed examples of common workflows and use cases for the LLMs.txt Security Analysis Platform. These examples demonstrate how to use the platform effectively for various security analysis scenarios.

## Table of Contents

1. [Full Analysis and Reporting](#example-1-full-analysis-and-reporting)
2. [Analysis Only](#example-2-analysis-only)
3. [Reporting Only](#example-3-reporting-only)
4. [Custom Content Query](#example-4-custom-content-query)
5. [Batch Processing](#example-5-batch-processing)
6. [Continuous Monitoring](#example-6-continuous-monitoring)
7. [Integration with CI/CD](#example-7-integration-with-cicd)
8. [Custom Rule Development](#example-8-custom-rule-development)

## Example 1: Full Analysis and Reporting

**Goal:** Run the full pipeline to analyze all LLMs.txt files and generate a comprehensive report.

### Command

```sh
python main.py --mode all --config config/scoring_config.yaml
```

### Expected Output

- Console output showing pipeline progress and performance metrics.
- Report file generated in the output directory (see logs for path).
- Summary of findings, risk scores, and recommendations.

### Detailed Workflow

1. The platform connects to the database and retrieves all LLMs.txt content.
2. Content is processed and normalized for analysis.
3. Multiple analyzers run in parallel:
   - Static analyzer examines code blocks
   - Pattern analyzer applies YARA rules
   - Secrets analyzer detects credentials
   - Markdown analyzer validates structure
4. Results are scored and risk is assessed.
5. A comprehensive report is generated with findings and recommendations.
6. Performance metrics are displayed.

### Example Console Output

```
2025-05-07 17:30:00 INFO Pipeline started.
2025-05-07 17:30:01 INFO Retrieved 10 content items.
2025-05-07 17:30:02 INFO Processed 10 items.
2025-05-07 17:30:10 INFO Analysis stage completed.
2025-05-07 17:30:11 INFO Scoring and risk assessment completed.
2025-05-07 17:30:12 INFO Reporting completed.
2025-05-07 17:30:12 INFO Pipeline completed in 12.34s.

--- PIPELINE EXECUTION SUCCEEDED ---
Report output/path: /path/to/report.html

Performance metrics: {
  'content_retrieval': 0.5,
  'content_processing': 1.2,
  'analysis': 8.1,
  'scoring': 0.8,
  'reporting': 1.7,
  'total': 12.3
}
```

## Example 2: Analysis Only

**Goal:** Run only the analysis phase and review findings without generating a full report.

### Command

```sh
python main.py --mode analysis --config config/scoring_config.yaml
```

### Expected Output

- Console output with analysis results for each file.
- No report file generated.
- Performance metrics for the analysis phase.

### Detailed Workflow

1. The platform connects to the database and retrieves all LLMs.txt content.
2. Content is processed and normalized for analysis.
3. Multiple analyzers run in parallel.
4. Results are scored and risk is assessed.
5. Analysis results are displayed in the console.
6. Performance metrics are displayed.

### Example Console Output

```
2025-05-07 17:35:00 INFO Pipeline started.
2025-05-07 17:35:01 INFO Retrieved 10 content items.
2025-05-07 17:35:02 INFO Processed 10 items.
2025-05-07 17:35:10 INFO Analysis stage completed.
2025-05-07 17:35:11 INFO Scoring and risk assessment completed.
2025-05-07 17:35:11 INFO Pipeline completed in 11.23s.

--- PIPELINE EXECUTION SUCCEEDED ---
Analysis results: 15 findings (3 critical, 5 high, 7 medium)

Performance metrics: {
  'content_retrieval': 0.5,
  'content_processing': 1.2,
  'analysis': 8.1,
  'scoring': 0.8,
  'total': 11.2
}
```

## Example 3: Reporting Only

**Goal:** Generate a report from existing analysis results.

### Command

```sh
python main.py --mode reporting --config config/scoring_config.yaml
```

### Expected Output

- Console output indicating report generation.
- Report file created in the output directory.

### Detailed Workflow

1. The platform loads existing analysis results from the database.
2. A comprehensive report is generated with findings and recommendations.
3. Performance metrics for the reporting phase are displayed.

### Example Console Output

```
2025-05-07 17:40:00 INFO Pipeline started.
2025-05-07 17:40:01 INFO Loading existing analysis results.
2025-05-07 17:40:02 INFO Found results for 10 content items.
2025-05-07 17:40:03 INFO Reporting completed.
2025-05-07 17:40:03 INFO Pipeline completed in 3.45s.

--- PIPELINE EXECUTION SUCCEEDED ---
Report output/path: /path/to/report.html

Performance metrics: {
  'reporting': 1.7,
  'total': 3.4
}
```

## Example 4: Custom Content Query

**Goal:** Analyze a specific subset of content using a custom query.

### Command

```sh
python main.py --mode all --config config/scoring_config.yaml --query "domain:example.com AND quality:high"
```

### Expected Output

- Analysis results for content matching the query.
- Report file generated for the filtered content.
- Performance metrics for the filtered run.

### Detailed Workflow

1. The platform connects to the database and retrieves content matching the query.
2. Content is processed and analyzed as in the full pipeline.
3. A report is generated for the filtered content.
4. Performance metrics are displayed.

### Example Console Output

```
2025-05-07 17:45:00 INFO Pipeline started.
2025-05-07 17:45:01 INFO Retrieved 3 content items matching query "domain:example.com AND quality:high".
2025-05-07 17:45:02 INFO Processed 3 items.
2025-05-07 17:45:05 INFO Analysis stage completed.
2025-05-07 17:45:06 INFO Scoring and risk assessment completed.
2025-05-07 17:45:07 INFO Reporting completed.
2025-05-07 17:45:07 INFO Pipeline completed in 7.12s.

--- PIPELINE EXECUTION SUCCEEDED ---
Report output/path: /path/to/filtered_report.html

Performance metrics: {
  'content_retrieval': 0.3,
  'content_processing': 0.4,
  'analysis': 3.1,
  'scoring': 0.3,
  'reporting': 0.7,
  'total': 7.1
}
```

## Example 5: Batch Processing

**Goal:** Process a large number of files in batches to optimize memory usage.

### Command

```sh
python main.py --mode all --config config/batch_processing.yaml
```

### Configuration (batch_processing.yaml)

```yaml
# Batch processing configuration
batch_size: 100  # Process 100 items at a time
pipeline_workers: 8  # Use 8 parallel workers

# Other configuration options...
```

### Expected Output

- Console output showing batch processing progress.
- Report file generated for all processed content.
- Performance metrics for the batch processing run.

### Detailed Workflow

1. The platform connects to the database and retrieves content in batches.
2. Each batch is processed and analyzed separately.
3. Results are aggregated and a comprehensive report is generated.
4. Performance metrics are displayed.

### Example Console Output

```
2025-05-07 17:50:00 INFO Pipeline started.
2025-05-07 17:50:01 INFO Retrieved 500 content items (total).
2025-05-07 17:50:01 INFO Processing batch 1/5 (100 items).
2025-05-07 17:50:10 INFO Batch 1/5 completed.
2025-05-07 17:50:10 INFO Processing batch 2/5 (100 items).
2025-05-07 17:50:19 INFO Batch 2/5 completed.
2025-05-07 17:50:19 INFO Processing batch 3/5 (100 items).
2025-05-07 17:50:28 INFO Batch 3/5 completed.
2025-05-07 17:50:28 INFO Processing batch 4/5 (100 items).
2025-05-07 17:50:37 INFO Batch 4/5 completed.
2025-05-07 17:50:37 INFO Processing batch 5/5 (100 items).
2025-05-07 17:50:46 INFO Batch 5/5 completed.
2025-05-07 17:50:47 INFO Aggregating results from all batches.
2025-05-07 17:50:48 INFO Scoring and risk assessment completed.
2025-05-07 17:50:50 INFO Reporting completed.
2025-05-07 17:50:50 INFO Pipeline completed in 50.12s.

--- PIPELINE EXECUTION SUCCEEDED ---
Report output/path: /path/to/batch_report.html

Performance metrics: {
  'content_retrieval': 1.5,
  'content_processing': 5.2,
  'analysis': 38.1,
  'scoring': 1.8,
  'reporting': 2.7,
  'total': 50.1
}
```

## Example 6: Continuous Monitoring

**Goal:** Set up continuous monitoring of LLMs.txt files for security issues.

### Script (monitor.py)

```python
#!/usr/bin/env python3
"""
Continuous monitoring script for LLMs.txt Security Analysis Platform.
"""

import time
import subprocess
import logging
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("monitor.log"),
        logging.StreamHandler()
    ]
)

def run_analysis():
    """Run the analysis pipeline and return the result."""
    cmd = ["python", "main.py", "--mode", "all", "--config", "config/monitoring.yaml"]
    
    logging.info(f"Running analysis: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info("Analysis completed successfully.")
            return True, result.stdout
        else:
            logging.error(f"Analysis failed with exit code {result.returncode}.")
            logging.error(f"Error output: {result.stderr}")
            return False, result.stderr
    except Exception as e:
        logging.error(f"Error running analysis: {e}")
        return False, str(e)

def main():
    """Main monitoring loop."""
    interval_hours = 24  # Run once per day
    
    logging.info(f"Starting continuous monitoring (interval: {interval_hours} hours).")
    
    while True:
        # Run analysis
        success, output = run_analysis()
        
        # Log the timestamp of the run
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"Analysis run at {timestamp}: {'Success' if success else 'Failed'}")
        
        # Sleep until next run
        next_run = datetime.datetime.now() + datetime.timedelta(hours=interval_hours)
        logging.info(f"Next run scheduled at {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        
        time.sleep(interval_hours * 3600)

if __name__ == "__main__":
    main()
```

### Command

```sh
python monitor.py
```

### Expected Output

- Periodic analysis runs at the specified interval.
- Log file with analysis results and timestamps.
- Reports generated for each run.

### Detailed Workflow

1. The monitoring script runs at the specified interval.
2. Each run executes the full pipeline.
3. Results are logged and reports are generated.
4. The script sleeps until the next scheduled run.

### Example Log Output

```
2025-05-07 00:00:00 INFO Starting continuous monitoring (interval: 24 hours).
2025-05-07 00:00:01 INFO Running analysis: python main.py --mode all --config config/monitoring.yaml
2025-05-07 00:10:23 INFO Analysis completed successfully.
2025-05-07 00:10:23 INFO Analysis run at 2025-05-07 00:10:23: Success
2025-05-07 00:10:23 INFO Next run scheduled at 2025-05-08 00:10:23
2025-05-08 00:10:23 INFO Running analysis: python main.py --mode all --config config/monitoring.yaml
2025-05-08 00:20:45 INFO Analysis completed successfully.
2025-05-08 00:20:45 INFO Analysis run at 2025-05-08 00:20:45: Success
2025-05-08 00:20:45 INFO Next run scheduled at 2025-05-09 00:20:45
```

## Example 7: Integration with CI/CD

**Goal:** Integrate the platform with a CI/CD pipeline to analyze LLMs.txt files during the build process.

### GitHub Actions Workflow (.github/workflows/security-analysis.yml)

```yaml
name: LLMs.txt Security Analysis

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * *'  # Run daily at midnight

jobs:
  security-analysis:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install uv
        uv pip install -r requirements.txt
    
    - name: Run security analysis
      run: |
        python main.py --mode all --config config/ci_config.yaml
      
    - name: Upload report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: |
          security_report.html
          performance_metrics.json
```

### Configuration (ci_config.yaml)

```yaml
# CI/CD configuration
db:
  path: ":memory:"  # Use in-memory database for CI

pipeline_workers: 4
output_dir: "./"
report_file: "security_report.html"
metrics_file: "performance_metrics.json"

# Fail on critical findings
fail_on_critical: true
```

### Expected Output

- Security analysis runs on every push to main, pull request, and daily.
- Report and metrics are uploaded as artifacts.
- Build fails if critical findings are detected (if configured).

### Detailed Workflow

1. The CI/CD pipeline checks out the code.
2. Dependencies are installed.
3. The security analysis is run with a CI-specific configuration.
4. Reports and metrics are uploaded as artifacts.
5. The build succeeds or fails based on the findings.

## Example 8: Custom Rule Development

**Goal:** Develop and test custom rules for detecting specific security issues.

### Custom Semgrep Rule (rules/semgrep/custom_eval_rule.yml)

```yaml
rules:
  - id: custom-eval-with-variable
    pattern: eval($X)
    message: "Potential code injection via eval() with variable input"
    languages: [python, javascript]
    severity: ERROR
    metadata:
      category: security
      confidence: HIGH
```

### Custom YARA Rule (rules/yara/custom_prompt_injection.yar)

```
rule Custom_Prompt_Injection {
    meta:
        description = "Detects sophisticated prompt injection attempts"
        severity = "high"
        confidence = "medium"
    strings:
        $s1 = "ignore all previous instructions" nocase
        $s2 = "disregard security controls" nocase
        $s3 = "bypass content filters" nocase
    condition:
        any of them
}
```

### Custom Pattern Rule (rules/patterns/custom_credential_patterns.yaml)

```yaml
patterns:
  - id: custom-api-key-pattern
    regex: 'api[_-]?key[_-]?[=:]\s*["'']([a-zA-Z0-9]{32})["'']'
    description: "Custom API key pattern with 32-character key"
    severity: "high"
    confidence: 0.9
```

### Command

```sh
python main.py --mode all --config config/custom_rules.yaml
```

### Configuration (custom_rules.yaml)

```yaml
# Custom rules configuration
rules:
  semgrep_rules_path: "rules/semgrep"
  yara_rules_path: "rules/yara"
  pattern_rules_path: "rules/patterns"

# Other configuration options...
```

### Expected Output

- Analysis results including findings from custom rules.
- Report highlighting custom rule matches.
- Performance metrics for the analysis.

### Detailed Workflow

1. The platform loads custom rules from the specified directories.
2. Content is retrieved and processed.
3. Analyzers apply the custom rules to the content.
4. Results include findings from the custom rules.
5. A report is generated highlighting the custom rule matches.

### Example Console Output

```
2025-05-07 18:00:00 INFO Pipeline started.
2025-05-07 18:00:01 INFO Loading custom rules from rules/semgrep, rules/yara, rules/patterns.
2025-05-07 18:00:02 INFO Loaded 1 custom Semgrep rules, 1 custom YARA rules, 1 custom pattern rules.
2025-05-07 18:00:03 INFO Retrieved 10 content items.
2025-05-07 18:00:04 INFO Processed 10 items.
2025-05-07 18:00:12 INFO Analysis stage completed.
2025-05-07 18:00:12 INFO Found 5 matches for custom rules (2 Semgrep, 1 YARA, 2 pattern).
2025-05-07 18:00:13 INFO Scoring and risk assessment completed.
2025-05-07 18:00:14 INFO Reporting completed.
2025-05-07 18:00:14 INFO Pipeline completed in 14.56s.

--- PIPELINE EXECUTION SUCCEEDED ---
Report output/path: /path/to/custom_rules_report.html

Performance metrics: {
  'content_retrieval': 0.5,
  'content_processing': 1.2,
  'analysis': 8.1,
  'scoring': 0.8,
  'reporting': 1.7,
  'total': 14.5
}
```

## Notes

- All commands assume you are in the project root directory.
- For more CLI options, run:
  ```sh
  python main.py --help
  ```
- See [User Guide](../user/running_analysis.md) for more details on running the platform.
- See [Configuration Guide](../user/configuration.md) for more details on configuration options.
- See [Plugin Development Guide](../developer/plugin_development.md) for more details on developing custom plugins and rules.