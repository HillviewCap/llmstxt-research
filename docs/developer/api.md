# LLMs.txt Security Analysis Platform: API Documentation

This document provides comprehensive documentation for the APIs and interfaces of the LLMs.txt Security Analysis Platform. It covers the main classes, methods, and CLI options for developers who want to extend or integrate with the platform.

## Core API Components

### Pipeline Orchestrator

**Location:** `core/pipeline.py`

The Pipeline class is the main orchestrator that integrates all components and manages the workflow.

#### `Pipeline(config=None)`

Initializes the pipeline with the given configuration.

**Parameters:**
- `config` (dict, optional): Configuration dictionary. Defaults to empty dict.

**Returns:**
- Pipeline instance

**Example:**
```python
from core.pipeline import Pipeline

# Initialize with default configuration
pipeline = Pipeline()

# Initialize with custom configuration
config = {
    "db": {"path": "custom/path/to/db.sqlite"},
    "pipeline_workers": 8,
    "batch_size": 100
}
pipeline = Pipeline(config=config)
```

#### `run(content_query=None)`

Orchestrates the full workflow: content retrieval, processing, analysis, scoring, reporting.

**Parameters:**
- `content_query` (str, optional): Query string to filter content. Defaults to None.

**Returns:**
- Report object or path, or error dictionary if execution failed.

**Example:**
```python
# Run with default settings (all content)
report = pipeline.run()

# Run with content filter
report = pipeline.run(content_query="domain:example.com")

# Check for errors
if isinstance(report, dict) and report.get("status") == "failed":
    print(f"Pipeline failed: {report.get('error')}")
else:
    print(f"Report generated: {report}")
```

#### `get_performance_metrics()`

Returns a dictionary of timing and performance metrics.

**Returns:**
- dict: Performance metrics for each stage of the pipeline.

**Example:**
```python
metrics = pipeline.get_performance_metrics()
print(f"Content retrieval: {metrics.get('content_retrieval', 0):.2f}s")
print(f"Analysis: {metrics.get('analysis', 0):.2f}s")
print(f"Total: {metrics.get('total', 0):.2f}s")
```

#### `reset()`

Resets the pipeline state.

**Example:**
```python
pipeline.reset()  # Reset pipeline for a new run
```

#### `_analyze_item(item)`

Helper method to analyze a single item, called by the thread pool.

**Parameters:**
- `item` (dict): Processed content item to analyze.

**Returns:**
- dict: Analysis results from all analyzers.

**Note:** This is an internal method not typically called directly.

### Database Connector

**Location:** `core/database/connector.py`

#### `DatabaseConnector(config=None)`

Initializes the database connector with the given configuration.

**Parameters:**
- `config` (dict, optional): Database configuration. Defaults to None.

**Returns:**
- DatabaseConnector instance

**Example:**
```python
from core.database.connector import DatabaseConnector

# Initialize with default configuration
db = DatabaseConnector()

# Initialize with custom configuration
config = {"path": "custom/path/to/db.sqlite"}
db = DatabaseConnector(config=config)
```

#### `connect()`

Establishes a connection to the database.

**Returns:**
- Connection object

**Example:**
```python
conn = db.connect()
```

#### `execute_query(query, params=None)`

Executes a SQL query with optional parameters.

**Parameters:**
- `query` (str): SQL query string.
- `params` (tuple, optional): Query parameters. Defaults to None.

**Returns:**
- list: Query results.

**Example:**
```python
results = db.execute_query("SELECT * FROM urls WHERE domain_id = ?", (domain_id,))
```

### Content Retriever

**Location:** `core/content/retriever.py`

#### `ContentRetriever(db)`

Initializes the content retriever with the given database connector.

**Parameters:**
- `db` (DatabaseConnector): Database connector instance.

**Returns:**
- ContentRetriever instance

**Example:**
```python
from core.content.retriever import ContentRetriever
from core.database.connector import DatabaseConnector

db = DatabaseConnector()
retriever = ContentRetriever(db)
```

#### `retrieve(query=None)`

Retrieves content items from the database.

**Parameters:**
- `query` (str, optional): Query string to filter content. Defaults to None.

**Returns:**
- list: Content items.

**Example:**
```python
# Retrieve all content
content_items = retriever.retrieve()

# Retrieve filtered content
content_items = retriever.retrieve(query="domain:example.com")
```

### Content Processor

**Location:** `core/content/processor.py`

#### `ContentProcessor()`

Initializes the content processor.

**Returns:**
- ContentProcessor instance

**Example:**
```python
from core.content.processor import ContentProcessor

processor = ContentProcessor()
```

#### `process(item)`

Processes a content item for analysis.

**Parameters:**
- `item` (dict): Raw content item.

**Returns:**
- dict: Processed content item with extracted components.

**Example:**
```python
processed_item = processor.process(content_item)
```

### Analyzers

#### Markdown Analyzer

**Location:** `core/analysis/markdown/analyzer.py`

```python
from core.analysis.markdown.analyzer import MarkdownAnalyzer

analyzer = MarkdownAnalyzer()
results = analyzer.analyze(processed_item)
```

#### Pattern Analyzer

**Location:** `core/analysis/patterns/analyzer.py`

```python
from core.analysis.patterns.analyzer import PatternAnalyzer

analyzer = PatternAnalyzer()
results = analyzer.analyze(processed_item)
```

#### Secrets Analyzer

**Location:** `core/analysis/secrets/analyzer.py`

```python
from core.analysis.secrets.analyzer import SecretsAnalyzer

analyzer = SecretsAnalyzer()
results = analyzer.analyze(processed_item)
```

#### Static Analyzer

**Location:** `core/analysis/static/analyzer.py`

```python
from core.analysis.static.analyzer import StaticAnalyzer

analyzer = StaticAnalyzer()
results = analyzer.analyze(processed_item)
```

### Scoring

#### Scoring Model

**Location:** `core/scoring/scoring_model.py`

```python
from core.scoring.scoring_model import ScoringModel

model = ScoringModel()
score = model.score(analysis_result)
```

#### Risk Assessor

**Location:** `core/scoring/risk_assessor.py`

```python
from core.scoring.risk_assessor import RiskAssessor

assessor = RiskAssessor()
risk = assessor.assess(score)
```

### Reporting

#### Reporting Manager

**Location:** `core/reporting/reporting_manager.py`

```python
from core.reporting.reporting_manager import ReportingManager

manager = ReportingManager()
report = manager.generate_report(
    content_items=content_items,
    analysis_results=analysis_results,
    scores=scores,
    risks=risks
)
```

## CLI Entry Point

**Location:** `main.py`

The main.py script provides a command-line interface to the platform.

### Usage

```bash
python main.py [OPTIONS]
```

### Options

- `--mode [analysis|reporting|all]`: Select operational mode. Default: `all`
- `--config <path>`: Specify a custom configuration file. Default: `config/scoring_config.yaml`
- `--query <query>`: Custom content query. Default: None
- `--help`: Show usage information

### Example

```bash
python main.py --mode analysis --config config/scoring_config.yaml --query "domain:example.com"
```

## Integration Examples

### Basic Integration

```python
from core.pipeline import Pipeline

# Initialize pipeline
pipeline = Pipeline()

# Run analysis
report = pipeline.run()

# Print performance metrics
metrics = pipeline.get_performance_metrics()
print(f"Total execution time: {metrics.get('total', 0):.2f}s")
```

### Custom Analysis

```python
from core.database.connector import DatabaseConnector
from core.content.retriever import ContentRetriever
from core.content.processor import ContentProcessor
from core.analysis.markdown.analyzer import MarkdownAnalyzer

# Initialize components
db = DatabaseConnector()
retriever = ContentRetriever(db)
processor = ContentProcessor()
analyzer = MarkdownAnalyzer()

# Retrieve content
content_items = retriever.retrieve(query="quality:high")

# Process and analyze
for item in content_items:
    processed_item = processor.process(item)
    results = analyzer.analyze(processed_item)
    print(f"Analysis results for {item.get('url')}: {len(results.get('findings', []))} findings")
```

### Custom Reporting

```python
from core.reporting.reporting_manager import ReportingManager
from core.reporting.report_generator import ReportGenerator

# Initialize components
manager = ReportingManager()
generator = ReportGenerator()

# Generate custom report
report = generator.generate(
    title="Custom Security Report",
    content_items=content_items,
    analysis_results=analysis_results,
    template="custom_template.html"
)

# Save report
with open("custom_report.html", "w") as f:
    f.write(report)
```

## Error Handling

The platform uses exceptions for error handling. Common exceptions include:

- `ValueError`: Invalid input parameters
- `ConnectionError`: Database connection issues
- `FileNotFoundError`: Missing files or configurations
- `RuntimeError`: Execution failures

Example error handling:

```python
try:
    report = pipeline.run()
except ValueError as e:
    print(f"Invalid input: {e}")
except ConnectionError as e:
    print(f"Database connection failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Configuration

The platform uses YAML configuration files. See [Configuration Guide](../user/configuration.md) for details.

Example configuration loading:

```python
import yaml

with open("config/custom_config.yaml", "r") as f:
    config = yaml.safe_load(f)

pipeline = Pipeline(config=config)
```

## Extending the Platform

### Adding a Custom Analyzer

1. Create a new analyzer class that implements the `analyze` method
2. Register the analyzer with the pipeline

Example:

```python
class CustomAnalyzer:
    def analyze(self, item):
        # Implement custom analysis
        findings = []
        # ... analysis logic ...
        return {"findings": findings}

# Register with pipeline
pipeline = Pipeline()
pipeline.custom_analyzer = CustomAnalyzer()

# Modify _analyze_item method to include custom analyzer
def _analyze_item(self, item):
    results = super()._analyze_item(item)
    results["custom"] = self.custom_analyzer.analyze(item)
    return results

# Monkey patch the method
import types
pipeline._analyze_item = types.MethodType(_analyze_item, pipeline)
```

### Adding Custom Rules

See [Plugin Development Guide](plugin_development.md) for details on adding custom rules.

## Performance Considerations

- Use batch processing for large datasets
- Configure appropriate number of workers
- Consider memory usage for large files
- Profile performance using the metrics API

## Thread Safety

The platform uses thread pools for parallel processing. Components should be designed to be thread-safe or use appropriate synchronization mechanisms.

## Logging

The platform uses the standard Python logging module. Configure logging as needed:

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

## Further Resources

- [System Architecture](../system/architecture.md)
- [Component Descriptions](../system/components.md)
- [Data Flow](../system/data_flow.md)
- [Database Schema](../system/database_schema.md)
- [Plugin Development Guide](plugin_development.md)