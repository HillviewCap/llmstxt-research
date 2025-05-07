"""
Historical Analysis Module for Temporal Analysis

This module provides functionality for:
1. Historical data visualization
2. Trend analysis algorithms
3. Predictive change modeling
4. Anomaly detection for changes
"""

import json
import numpy as np
from typing import Dict, Any, List, Tuple, Optional, Union
from datetime import datetime, timedelta
from sqlalchemy import desc, func, and_, or_
from sqlalchemy.orm import Session
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures

from core.database.connector import DatabaseConnector
from core.database.schema import Urls, SecurityAnalysisResult
from core.temporal.schema import ContentVersion, ContentChange, HistoricalRiskScore, TemporalAnomaly


class HistoricalAnalyzer:
    """
    Analyzes historical data for trends and anomalies.
    """
    
    def __init__(self, db_connector: DatabaseConnector):
        """
        Initialize the historical analyzer with a database connector.
        
        Args:
            db_connector: Database connector for accessing the database
        """
        self._db_connector = db_connector
    
    def get_risk_score_history(self, url: str) -> Dict[str, Any]:
        """
        Get the history of risk scores for a URL.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with risk score history data
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return {'error': 'URL not found'}
            
            # Get historical risk scores
            risk_scores = session.query(HistoricalRiskScore).filter_by(
                url_id=url_record.id
            ).order_by(HistoricalRiskScore.timestamp).all()
            
            if not risk_scores:
                return {'error': 'No historical risk scores found'}
            
            # Extract data for plotting
            timestamps = [score.timestamp.isoformat() for score in risk_scores]
            overall_scores = [score.overall_risk_score for score in risk_scores]
            malicious_confidence = [score.malicious_confidence for score in risk_scores]
            
            # Component scores
            markdown_scores = [score.markdown_risk or 0 for score in risk_scores]
            pattern_scores = [score.pattern_risk or 0 for score in risk_scores]
            secrets_scores = [score.secrets_risk or 0 for score in risk_scores]
            static_scores = [score.static_risk or 0 for score in risk_scores]
            
            # Get versions for reference
            versions = []
            for score in risk_scores:
                if score.version_id:
                    version = session.query(ContentVersion).filter_by(id=score.version_id).first()
                    versions.append(version.version_number if version else None)
                else:
                    versions.append(None)
            
            return {
                'url': url,
                'timestamps': timestamps,
                'versions': versions,
                'overall_scores': overall_scores,
                'malicious_confidence': malicious_confidence,
                'component_scores': {
                    'markdown': markdown_scores,
                    'pattern': pattern_scores,
                    'secrets': secrets_scores,
                    'static': static_scores
                }
            }
    
    def analyze_trends(self, url: str) -> Dict[str, Any]:
        """
        Analyze trends in risk scores and changes.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with trend analysis results
        """
        history = self.get_risk_score_history(url)
        if 'error' in history:
            return {'error': history['error']}
        
        # Convert timestamps to numerical values for regression
        timestamps = [datetime.fromisoformat(ts) for ts in history['timestamps']]
        days_since_start = [(ts - timestamps[0]).total_seconds() / (24 * 3600) for ts in timestamps]
        
        # Analyze overall risk score trend
        overall_trend = self._analyze_score_trend(days_since_start, history['overall_scores'])
        
        # Analyze component trends
        component_trends = {}
        for component, scores in history['component_scores'].items():
            component_trends[component] = self._analyze_score_trend(days_since_start, scores)
        
        # Analyze change frequency
        change_frequency = self._analyze_change_frequency(url)
        
        return {
            'url': url,
            'data_points': len(history['timestamps']),
            'time_span_days': days_since_start[-1] if days_since_start else 0,
            'overall_trend': overall_trend,
            'component_trends': component_trends,
            'change_frequency': change_frequency
        }
    
    def _analyze_score_trend(self, x_values: List[float], scores: List[float]) -> Dict[str, Any]:
        """
        Analyze the trend in a series of scores.
        
        Args:
            x_values: X values (days since start)
            scores: Y values (scores)
            
        Returns:
            Dictionary with trend analysis
        """
        if len(x_values) < 2:
            return {'status': 'insufficient_data'}
        
        # Convert to numpy arrays
        x = np.array(x_values).reshape(-1, 1)
        y = np.array(scores)
        
        # Linear regression
        model = LinearRegression()
        model.fit(x, y)
        
        # Calculate slope and determine trend direction
        slope = model.coef_[0]
        
        # Calculate R-squared
        y_pred = model.predict(x)
        ss_total = np.sum((y - np.mean(y)) ** 2)
        ss_residual = np.sum((y - y_pred) ** 2)
        r_squared = 1 - (ss_residual / ss_total) if ss_total != 0 else 0
        
        # Determine trend strength and direction
        if abs(slope) < 0.001:
            direction = 'stable'
            strength = 'none'
        else:
            direction = 'increasing' if slope > 0 else 'decreasing'
            if abs(slope) < 0.01:
                strength = 'weak'
            elif abs(slope) < 0.05:
                strength = 'moderate'
            else:
                strength = 'strong'
        
        # Predict future value (30 days ahead)
        future_x = np.array([[x_values[-1] + 30]])
        future_prediction = float(model.predict(future_x)[0])
        future_prediction = max(0, min(1, future_prediction))  # Clamp between 0 and 1
        
        return {
            'direction': direction,
            'strength': strength,
            'slope': float(slope),
            'r_squared': float(r_squared),
            'current_value': scores[-1],
            'prediction_30_days': future_prediction
        }
    
    def _analyze_change_frequency(self, url: str) -> Dict[str, Any]:
        """
        Analyze the frequency of changes for a URL.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with change frequency analysis
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return {'status': 'url_not_found'}
            
            # Get all versions
            versions = session.query(ContentVersion).filter_by(
                url_id=url_record.id
            ).order_by(ContentVersion.version_number).all()
            
            if len(versions) < 2:
                return {'status': 'insufficient_data'}
            
            # Calculate time deltas between versions
            time_deltas = []
            for i in range(1, len(versions)):
                delta = (versions[i].timestamp - versions[i-1].timestamp).total_seconds() / (24 * 3600)  # in days
                time_deltas.append(delta)
            
            # Calculate statistics
            avg_delta = sum(time_deltas) / len(time_deltas)
            median_delta = sorted(time_deltas)[len(time_deltas) // 2]
            min_delta = min(time_deltas)
            max_delta = max(time_deltas)
            
            # Calculate change frequency (changes per month)
            total_days = (versions[-1].timestamp - versions[0].timestamp).total_seconds() / (24 * 3600)
            changes_per_month = (len(versions) - 1) / (total_days / 30) if total_days > 0 else 0
            
            return {
                'versions_count': len(versions),
                'first_version_date': versions[0].timestamp.isoformat(),
                'latest_version_date': versions[-1].timestamp.isoformat(),
                'avg_days_between_changes': avg_delta,
                'median_days_between_changes': median_delta,
                'min_days_between_changes': min_delta,
                'max_days_between_changes': max_delta,
                'changes_per_month': changes_per_month
            }
    
    def generate_risk_trend_visualization(self, url: str) -> Optional[str]:
        """
        Generate a visualization of risk score trends.
        
        Args:
            url: The URL to analyze
            
        Returns:
            HTML string with the visualization
        """
        history = self.get_risk_score_history(url)
        if 'error' in history:
            return None
        
        # Create a subplot with 2 rows
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=("Overall Risk Score Trend", "Component Risk Scores"),
            vertical_spacing=0.15
        )
        
        # Add overall risk score trace
        fig.add_trace(
            go.Scatter(
                x=history['timestamps'],
                y=history['overall_scores'],
                mode='lines+markers',
                name='Overall Risk Score',
                line=dict(color='red', width=2)
            ),
            row=1, col=1
        )
        
        # Add malicious confidence trace
        fig.add_trace(
            go.Scatter(
                x=history['timestamps'],
                y=history['malicious_confidence'],
                mode='lines+markers',
                name='Malicious Confidence',
                line=dict(color='orange', width=2)
            ),
            row=1, col=1
        )
        
        # Add component score traces
        components = history['component_scores']
        colors = {'markdown': 'blue', 'pattern': 'green', 'secrets': 'purple', 'static': 'brown'}
        
        for component, scores in components.items():
            fig.add_trace(
                go.Scatter(
                    x=history['timestamps'],
                    y=scores,
                    mode='lines+markers',
                    name=f'{component.capitalize()} Risk',
                    line=dict(color=colors.get(component, 'gray'))
                ),
                row=2, col=1
            )
        
        # Add version annotations
        for i, (timestamp, version) in enumerate(zip(history['timestamps'], history['versions'])):
            if version is not None:
                fig.add_annotation(
                    x=timestamp,
                    y=history['overall_scores'][i],
                    text=f"v{version}",
                    showarrow=True,
                    arrowhead=1,
                    row=1, col=1
                )
        
        # Update layout
        fig.update_layout(
            title_text=f"Risk Score Trends for {url}",
            height=800,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        # Update y-axes
        fig.update_yaxes(title_text="Risk Score", range=[0, 1], row=1, col=1)
        fig.update_yaxes(title_text="Component Risk", range=[0, 1], row=2, col=1)
        
        # Return as HTML
        return fig.to_html(include_plotlyjs='cdn')
    
    def detect_anomalies_in_trends(self, url: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies in risk score trends.
        
        Args:
            url: The URL to analyze
            
        Returns:
            List of detected anomalies
        """
        history = self.get_risk_score_history(url)
        if 'error' in history:
            return []
        
        anomalies = []
        
        # Need at least 5 data points for meaningful anomaly detection
        if len(history['timestamps']) < 5:
            return []
        
        # Convert timestamps to datetime objects
        timestamps = [datetime.fromisoformat(ts) for ts in history['timestamps']]
        
        # Detect sudden spikes in overall risk score
        overall_anomalies = self._detect_score_anomalies(
            timestamps, 
            history['overall_scores'], 
            'overall_risk'
        )
        anomalies.extend(overall_anomalies)
        
        # Detect anomalies in component scores
        for component, scores in history['component_scores'].items():
            component_anomalies = self._detect_score_anomalies(
                timestamps, 
                scores, 
                f'{component}_risk'
            )
            anomalies.extend(component_anomalies)
        
        return anomalies
    
    def _detect_score_anomalies(
        self, 
        timestamps: List[datetime], 
        scores: List[float], 
        score_type: str
    ) -> List[Dict[str, Any]]:
        """
        Detect anomalies in a score series.
        
        Args:
            timestamps: List of timestamps
            scores: List of scores
            score_type: Type of score (for labeling)
            
        Returns:
            List of anomalies
        """
        anomalies = []
        
        # Calculate moving average and standard deviation
        window_size = min(3, len(scores) - 1)
        
        for i in range(window_size, len(scores)):
            # Get window of previous scores
            window = scores[i-window_size:i]
            
            # Calculate statistics
            window_avg = sum(window) / len(window)
            window_std = (sum((s - window_avg) ** 2 for s in window) / len(window)) ** 0.5
            
            # Detect if current score is an anomaly (more than 2 standard deviations from moving average)
            if window_std > 0 and abs(scores[i] - window_avg) > 2 * window_std:
                anomalies.append({
                    'timestamp': timestamps[i].isoformat(),
                    'score_type': score_type,
                    'value': scores[i],
                    'expected_value': window_avg,
                    'deviation': scores[i] - window_avg,
                    'standard_deviations': abs(scores[i] - window_avg) / window_std if window_std > 0 else 0,
                    'severity': 'high' if abs(scores[i] - window_avg) > 3 * window_std else 'medium'
                })
        
        return anomalies