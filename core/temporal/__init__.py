"""
Temporal Analysis Package

This package provides functionality for:
1. Version tracking
2. Change detection
3. Historical analysis

Components:
- analyzer.py: Version tracking and basic change detection
- change_detector.py: Advanced change detection and suspicious change identification
- historical_analyzer.py: Historical trend analysis and visualization
- integration.py: Integration with the main pipeline
- schema.py: Database schema extensions for temporal analysis
"""

from core.temporal.analyzer import VersionTracker
from core.temporal.change_detector import ChangeDetector
from core.temporal.historical_analyzer import HistoricalAnalyzer
from core.temporal.integration import TemporalAnalysis

__all__ = [
    'VersionTracker',
    'ChangeDetector',
    'HistoricalAnalyzer',
    'TemporalAnalysis'
]