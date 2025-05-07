"""
Temporal Analysis Integration Module

This module integrates the temporal analysis components with the main pipeline.
It provides a unified interface for:
1. Version tracking
2. Change detection
3. Historical analysis
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from core.database.connector import DatabaseConnector
from core.temporal.analyzer import VersionTracker
from core.temporal.change_detector import ChangeDetector
from core.temporal.historical_analyzer import HistoricalAnalyzer
from core.database.schema import SecurityAnalysisResult


class TemporalAnalysis:
    """
    Main integration class for temporal analysis.
    """
    
    def __init__(self, db_connector: DatabaseConnector):
        """
        Initialize the temporal analysis with a database connector.
        
        Args:
            db_connector: Database connector for accessing the database
        """
        self._db_connector = db_connector
        self._version_tracker = VersionTracker(db_connector)
        self._change_detector = ChangeDetector(db_connector)
        self._historical_analyzer = HistoricalAnalyzer(db_connector)
    
    def process_content(self, url: str, content: str, processed_content_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Process content for temporal analysis.
        
        Args:
            url: The URL of the content
            content: The raw content
            processed_content_id: ID of the processed content record (optional)
            
        Returns:
            Dictionary with temporal analysis results
        """
        try:
            # Track version
            version, is_new_version = self._version_tracker.track_version(url, content, processed_content_id)
            
            # Extract version data while still in session
            version_number = version.version_number
            timestamp = version.timestamp.isoformat() if version.timestamp else datetime.now().isoformat()
            
            results = {
                'url': url,
                'version': version_number,
                'timestamp': timestamp,
                'is_new_version': is_new_version,
                'changes_detected': False,
                'suspicious_changes': [],
                'gradual_modifications': [],
                'trend_analysis': {}
            }
        except Exception as e:
            # Handle database errors gracefully
            print(f"Error in temporal analysis version tracking: {e}")
            results = {
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'is_new_version': False,
                'changes_detected': False,
                'suspicious_changes': [],
                'gradual_modifications': [],
                'trend_analysis': {}
            }
            return results
        
        # If this is a new version, perform change detection
        if is_new_version and version.version_number > 1:
            # Detect suspicious changes
            suspicious_changes = self._change_detector.detect_suspicious_changes(
                url, time_window=timedelta(days=30)
            )
            
            # Track gradual modifications
            gradual_modifications = self._change_detector.track_gradual_modifications(url)
            
            results['changes_detected'] = bool(suspicious_changes or gradual_modifications)
            results['suspicious_changes'] = suspicious_changes
            results['gradual_modifications'] = gradual_modifications
        
        # Perform trend analysis if we have enough data
        try:
            trend_analysis = self._historical_analyzer.analyze_trends(url)
            if 'error' not in trend_analysis:
                results['trend_analysis'] = trend_analysis
        except Exception as e:
            results['trend_analysis_error'] = str(e)
        
        return results
    
    def track_analysis_result(self, url: str, analysis_result: SecurityAnalysisResult) -> Dict[str, Any]:
        """
        Track a security analysis result for historical analysis.
        
        Args:
            url: The URL
            analysis_result: Security analysis result
            
        Returns:
            Dictionary with tracking information
        """
        # Get the latest version for this URL
        with self._db_connector.session_scope() as session:
            from core.database.schema import Urls
            from core.temporal.schema import ContentVersion
            from sqlalchemy import desc
            
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return {'error': 'URL not found'}
            
            latest_version = session.query(ContentVersion).filter_by(
                url_id=url_record.id
            ).order_by(desc(ContentVersion.version_number)).first()
            
            version_id = latest_version.id if latest_version else None
        
        # Track risk score
        try:
            from core.temporal.schema import HistoricalRiskScore
            
            risk_score = HistoricalRiskScore(
                url_id=url_record.id,
                version_id=version_id,
                analysis_id=analysis_result.id,
                overall_risk_score=analysis_result.overall_risk_score,
                malicious_confidence=analysis_result.malicious_confidence
            )
            
            with self._db_connector.session_scope() as session:
                session.add(risk_score)
                session.commit()
            
            return {
                'url': url,
                'version_id': version_id,
                'analysis_id': analysis_result.id,
                'overall_risk_score': analysis_result.overall_risk_score,
                'malicious_confidence': analysis_result.malicious_confidence,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': f'Failed to track analysis result: {str(e)}'}
    
    def get_version_history(self, url: str) -> List[Dict[str, Any]]:
        """
        Get the version history for a URL.
        
        Args:
            url: The URL to get history for
            
        Returns:
            List of version records with change information
        """
        return self._version_tracker.get_version_history(url)
    
    def get_version_diff(self, url: str, version1: int, version2: int) -> Dict[str, Any]:
        """
        Get a detailed diff between two versions.
        
        Args:
            url: The URL
            version1: First version number
            version2: Second version number
            
        Returns:
            Dictionary with diff information
        """
        return self._change_detector.generate_version_comparison(url, version1, version2)
    
    def generate_historical_dashboard(self, url: str) -> Optional[str]:
        """
        Generate a historical analysis dashboard.
        
        Args:
            url: The URL to analyze
            
        Returns:
            HTML string with the dashboard
        """
        return self._historical_analyzer.generate_risk_trend_visualization(url)
    
    def detect_anomalies(self, url: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies in risk score trends.
        
        Args:
            url: The URL to analyze
            
        Returns:
            List of detected anomalies
        """
        return self._historical_analyzer.detect_anomalies_in_trends(url)