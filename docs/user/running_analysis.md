# LLMs.txt Security Analysis Platform: Running Analysis Guide

This guide explains how to run security analysis on LLMs.txt files using the platform.

## Overview

The LLMs.txt Security Analysis Platform provides a command-line interface (CLI) for running security analysis on LLMs.txt files. The platform can operate in different modes and supports various configuration options.

## Command-Line Interface

The main entry point for the platform is the `main.py` script, which accepts various command-line arguments.

### Basic Usage

```bash
python main.py [OPTIONS]
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode` | Operational mode: `analysis`, `reporting`, or `all` | `all` |
| `--config` | Path to configuration file | `config/scoring_config.yaml` |
| `--query` | Custom content query (optional) | None |
| `--help` | Show usage information | N/A |

## Running Modes

### Full Pipeline (Analysis + Reporting)

To run the full pipeline, which includes content retrieval, analysis, scoring, and reporting:

```bash
python main.py --mode all --config config/scoring_config.yaml
```

This will:
1. Retrieve content from the database
2. Process the content
3. Run all analyzers
4. Score and assess risk
5. Generate a report

### Analysis Only

To run only the analysis phase without generating a report:

```bash
python main.py --mode analysis --config config/scoring_config.yaml
```

This will:
1. Retrieve content from the database
2. Process the content
3. Run all analyzers
4. Score and assess risk
5. Output analysis results to the console

### Reporting Only

To generate a report from existing analysis results:

```bash
python main.py --mode reporting --config config/scoring_config.yaml
```

This will:
1. Load existing analysis results from the database
2. Generate a report based on those results

## Content Filtering

You can filter the content to analyze using the `--query` parameter:

```bash
python main.py --mode all --config config/scoring_config.yaml --query "source:external"
```

The query parameter supports various filters:

- `domain:example.com` - Filter by domain
- `source:external` - Filter by source
- `quality:high` - Filter by quality rating
- `topic:security` - Filter by topic
- `purpose:documentation` - Filter by purpose

Multiple filters can be combined with AND/OR operators:

```bash
python main.py --query "domain:example.com AND quality:high"
```

## Example Workflows

### Analyze All Content

```bash
python main.py --mode all
```

### Analyze Specific Domain

```bash
python main.py --mode all --query "domain:example.com"
```

### Analyze High-Quality Content Only

```bash
python main.py --mode all --query "quality:high"
```

### Generate Report for Previously Analyzed Content

```bash
python main.py --mode reporting
```

## Performance Considerations

### Batch Processing

For large datasets, the platform processes content in batches to optimize memory usage. The batch size can be configured in the configuration file:

```yaml
batch_size: 100  # Process 100 items at a time
```

### Parallel Processing

The platform uses parallel processing to speed up analysis. The number of parallel workers can be configured in the configuration file:

```yaml
pipeline_workers: 8  # Use 8 parallel workers
```

### Incremental Analysis

To save time, the platform can perform incremental analysis, only analyzing content that has changed since the last run. This is enabled by default.

## Monitoring Progress

The platform provides progress information during execution:

```
2025-05-07 17:30:00 INFO Pipeline started.
2025-05-07 17:30:01 INFO Retrieved 10 content items.
2025-05-07 17:30:02 INFO Processed 10 items.
2025-05-07 17:30:10 INFO Analysis stage completed.
2025-05-07 17:30:11 INFO Scoring and risk assessment completed.
2025-05-07 17:30:12 INFO Reporting completed.
2025-05-07 17:30:12 INFO Pipeline completed in 12.34s.
```

## Performance Metrics

After execution, the platform outputs performance metrics:

```
Performance metrics: {
  'content_retrieval': 0.5,
  'content_processing': 1.2,
  'analysis': 8.1,
  'scoring': 0.8,
  'reporting': 1.7,
  'total': 12.3
}
```

These metrics can help identify bottlenecks and optimize performance.

## Output

### Console Output

The platform outputs information to the console, including:

- Progress information
- Error messages
- Performance metrics
- Summary of findings

### Report Output

When running in `all` or `reporting` mode, the platform generates a report. The report location is displayed in the console output:

```
Report output/path: /path/to/report.html
```

## Troubleshooting

### Common Issues

#### No Content Retrieved

If no content is retrieved, check:

- Database connection
- Content query
- Database schema

#### Analysis Failures

If analysis fails, check:

- External tool dependencies (Semgrep, YARA, etc.)
- Rule syntax
- Content format

#### Performance Issues

If performance is slow, consider:

- Reducing batch size
- Adjusting number of workers
- Using incremental analysis
- Filtering content with queries

### Logs

For more detailed information, check the logs:

```bash
tail -f debug.log
```

## Advanced Usage

### Custom Configuration

You can create custom configuration files for different analysis scenarios:

```bash
python main.py --mode all --config custom_configs/high_sensitivity.yaml
```

### Integration with Other Tools

The platform can be integrated with other tools using its output:

```bash
# Run analysis and pipe output to jq for JSON processing
python main.py --mode analysis | jq '.findings'

# Run analysis and generate a report, then open it
python main.py --mode all && open $(tail -n 1 debug.log | grep -o '/path/to/report.html')
```

### Scheduled Execution

You can schedule regular analysis using cron or other scheduling tools:

```bash
# Add to crontab to run daily at midnight
0 0 * * * cd /path/to/llmstxt-research && python main.py --mode all >> /var/log/llmstxt-analysis.log 2>&1
```

## Next Steps

After running analysis, you can:

- [Interpret the results](interpreting_results.md) to understand the findings
- [Configure the platform](configuration.md) to customize analysis
- [Develop plugins](../developer/plugin_development.md) to extend functionality