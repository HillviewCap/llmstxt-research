#!/bin/bash
# Test script for the temporal analysis pipeline
# This script demonstrates how to use the temporal analysis pipeline
# with the test files

# Set the URL for testing
TEST_URL="https://example.com/test-content"

# Set the database URL
DB_URL="sqlite:///researchdb/temporal_test.db"

# Create the database directory if it doesn't exist
mkdir -p researchdb

# Install required dependencies
echo "===== Installing required dependencies ====="
uv pip install sqlalchemy pyyaml pandas numpy

echo "===== STEP 1: Run temporal analysis with initial content ====="
uv run scripts/run_temporal_analysis.py \
  --url "$TEST_URL" \
  --content-file tests/data/temporal_test_sample.llms.txt \
  --db-url "$DB_URL" \
  --pretty

echo ""
echo "===== STEP 2: Run temporal analysis with modified content ====="
echo "This should detect changes from the previous version"
uv run scripts/run_temporal_analysis.py \
  --url "$TEST_URL" \
  --content-file tests/data/temporal_test_sample_modified.llms.txt \
  --db-url "$DB_URL" \
  --pretty

echo ""
echo "===== STEP 3: Run temporal analysis with the same content again ====="
echo "This should NOT detect a new version since the content hasn't changed"
uv run scripts/run_temporal_analysis.py \
  --url "$TEST_URL" \
  --content-file tests/data/temporal_test_sample_modified.llms.txt \
  --db-url "$DB_URL" \
  --pretty

echo ""
echo "===== Test Complete ====="
echo "The temporal analysis pipeline has been tested with initial content,"
echo "modified content, and repeated content. Check the output above to see"
echo "how the pipeline detected and analyzed changes."