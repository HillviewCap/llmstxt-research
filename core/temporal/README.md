# Temporal Analysis Module

This module provides functionality for tracking content versions, detecting changes, and analyzing historical trends in security analysis results.

## Components

### 1. Version Tracking System
- Implemented in `analyzer.py` as the `VersionTracker` class
- Tracks content versions with unique version numbers
- Detects changes between versions
- Calculates suspicion scores for changes

### 2. Change Detection
- Implemented in `change_detector.py` as the `ChangeDetector` class
- Detects suspicious changes based on patterns and heuristics
- Tracks gradual modifications that might indicate evasion attempts
- Provides version comparison visualization

### 3. Historical Analysis
- Implemented in `historical_analyzer.py` as the `HistoricalAnalyzer` class
- Analyzes trends in risk scores over time
- Detects anomalies in risk score trends
- Provides visualizations of historical data

### 4. Integration
- Implemented in `integration.py` as the `TemporalAnalysis` class
- Provides a unified interface for temporal analysis
- Integrates with the main pipeline

## Database Schema

The temporal analysis module uses the following database tables:
- `ContentVersion`: Stores versions of content
- `ContentChange`: Records changes between versions
- `HistoricalRiskScore`: Tracks risk scores over time
- `TemporalAnomaly`: Records detected anomalies

## Usage

The temporal analysis module is integrated into the main pipeline and is automatically used when processing content. The results are included in the generated reports and dashboards.

### Example:

```python
from core.temporal.integration import TemporalAnalysis
from core.database.connector import DatabaseConnector

# Initialize
db = DatabaseConnector()
temporal_analyzer = TemporalAnalysis(db)

# Process content
result = temporal_analyzer.process_content(
    url="https://example.com",
    content="Example content",
    processed_content_id=123
)

# Track analysis result
temporal_analyzer.track_analysis_result(
    url="https://example.com",
    analysis_result=security_analysis_result
)

# Get version history
history = temporal_analyzer.get_version_history("https://example.com")

# Get version diff
diff = temporal_analyzer.get_version_diff("https://example.com", 1, 2)

# Generate dashboard
html = temporal_analyzer.generate_historical_dashboard("https://example.com")