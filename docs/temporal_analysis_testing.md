 # Temporal Analysis Pipeline Testing

This document provides instructions for testing the temporal analysis pipeline in isolation, without running the entire workflow.

## Overview

The temporal analysis pipeline is responsible for:

1. **Version Tracking**: Detecting and tracking different versions of content
2. **Change Detection**: Identifying suspicious changes and gradual modifications
3. **Historical Analysis**: Analyzing trends in risk scores and changes over time

Testing these components in isolation can help you validate changes to the temporal analysis pipeline without having to run the entire workflow.

## Prerequisites

- Python 3.6 or higher
- Required packages: sqlalchemy, pyyaml, pandas, numpy

You can install the required packages using:

```bash
uv pip install sqlalchemy pyyaml pandas numpy
```

The test script will automatically install these dependencies for you.

## Testing Scripts

We've provided two scripts to help you test the temporal analysis pipeline:

1. `scripts/run_temporal_analysis.py`: A standalone script for running the temporal analysis pipeline
2. `scripts/test_temporal_pipeline.sh`: A shell script that demonstrates how to use the temporal analysis pipeline with test files

## Running the Temporal Analysis Pipeline Directly

### Basic Usage

```bash
uv run scripts/run_temporal_analysis.py --url "https://example.com/test" --content "This is test content" --pretty
```

### Using a Content File

```bash
uv run scripts/run_temporal_analysis.py --url "https://example.com/test" --content-file tests/data/temporal_test_sample.llms.txt --pretty
```

### All Available Options

```
usage: run_temporal_analysis.py [-h] --url URL [--content CONTENT] [--content-file CONTENT_FILE] [--db-url DB_URL] [--processed-content-id PROCESSED_CONTENT_ID] [--pretty]

Run temporal analysis pipeline

options:
  -h, --help            show this help message and exit
  --url URL             URL or identifier for the content to analyze
  --content CONTENT     Content to analyze (if not provided, will attempt to load from file)
  --content-file CONTENT_FILE
                        File containing content to analyze
  --db-url DB_URL       Database URL (default: sqlite:///researchdb/llms_metadata.db)
  --processed-content-id PROCESSED_CONTENT_ID
                        ID of already processed content (optional)
  --pretty              Pretty print JSON output
```

## Running the Test Script

The test script demonstrates how to use the temporal analysis pipeline with test files. It runs the pipeline three times:

1. With initial content
2. With modified content (to test change detection)
3. With the same modified content again (to test that no new version is detected)

```bash
./scripts/test_temporal_pipeline.sh
```

## Test Files

We've provided two test files:

1. `tests/data/temporal_test_sample.llms.txt`: Initial content
2. `tests/data/temporal_test_sample_modified.llms.txt`: Modified content with changes

You can modify these files or create your own test files to test different scenarios.

## Testing Your Changes

To test changes to the temporal analysis pipeline:

1. Make your changes to the temporal analysis components
2. Run the test script to see how your changes affect the pipeline
3. Check the output to ensure that your changes are working as expected

## Troubleshooting

### Database Issues

If you encounter database-related errors, you may need to initialize the database first:

```bash
uv run scripts/init_database.py
```

### Missing Dependencies

If you encounter dependency-related errors, install the required packages manually:

```bash
uv pip install sqlalchemy pyyaml pandas numpy
```

The script will check for missing dependencies and provide instructions if any are missing.

### Other Issues

If you encounter other issues, check the error messages for clues. The script includes detailed error handling to help you diagnose problems.