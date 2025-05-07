# LLMs.txt Security Analysis Platform: API Documentation

## Overview

This document describes the main classes, methods, and CLI options for the LLMs.txt Security Analysis Platform.

---

## Pipeline Orchestrator

**Location:** `core/pipeline.py`

### `Pipeline(config=None)`

- Initializes the pipeline with the given configuration.
- Integrates database, content, analysis, scoring, and reporting modules.

#### Methods

- `run(content_query=None)`
  - Orchestrates the full workflow: content retrieval, processing, analysis, scoring, reporting.
  - Returns: report object or path.

- `get_performance_metrics()`
  - Returns a dictionary of timing and performance metrics.

- `reset()`
  - Resets the pipeline state.

---

## Reporting

**Location:** `core/reporting/reporting_manager.py`

### `ReportingManager`

- `generate_report(content_items, analysis_results, scores, risks)`
  - Generates a report from the pipeline results.

---

## CLI Entry Point

**Location:** `main.py`

### Usage

```sh
python main.py [OPTIONS]
```

#### Options

- `--mode [analysis|reporting|all]` : Select operational mode
- `--config <path>` : Specify a custom configuration file
- `--help` : Show usage information

---

## Configuration

- **Config files:** Located in `config/`
- **Rule files:** Located in `rules/`
- **Plugins:** Located in `plugins/`

---

## Extending the Platform

- Add new analyzers in `core/analysis/`
- Add new rules in `rules/`
- Add new plugins in `plugins/`

---

## For more details, see:

- [User Guide](user_guide.md)
- [System Architecture](architecture.md)
- [Example Workflows](example_workflow.md)