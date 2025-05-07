"""
Change Detection Module for Temporal Analysis

This module provides functionality for:
1. Content difference algorithm
2. Suspicious change detection
3. Gradual modification tracking
4. Version comparison visualization
"""

import re
import json
import difflib
from typing import Dict, Any, List, Tuple, Optional, Set
from datetime import datetime, timedelta
from sqlalchemy import desc, func, and_
from sqlalchemy.orm import Session

from core.database.connector import DatabaseConnector
from core.database.schema import Urls
from core.temporal.schema import ContentVersion, ContentChange, TemporalAnomaly


class ChangeDetector:
    """
    Detects and analyzes changes between content versions.
    """
    
    def __init__(self, db_connector: DatabaseConnector):
        """
        Initialize the change detector with a database connector.
        
        Args:
            db_connector: Database connector for accessing the database
        """
        self._db_connector = db_connector
        
        # Patterns that are considered suspicious when added
        self._suspicious_patterns = [
            # JavaScript eval and execution
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            
            # Python execution
            r'exec\s*\(',
            r'eval\s*\(',
            r'__import__\s*\(',
            r'subprocess\.',
            r'os\.system\s*\(',
            
            # Network requests
            r'fetch\s*\(',
            r'XMLHttpRequest',
            r'\.ajax\s*\(',
            r'http\.request\s*\(',
            r'urllib\.request',
            r'requests\.',
            
            # Data exfiltration
            r'localStorage\.',
            r'sessionStorage\.',
            r'document\.cookie',
            r'navigator\.sendBeacon',
            
            # Obfuscation techniques
            r'atob\s*\(',
            r'btoa\s*\(',
            r'String\.fromCharCode',
            r'unescape\s*\(',
            r'decodeURIComponent\s*\(',
            r'\\x[0-9a-fA-F]{2}',  # Hex escapes
            r'\\u[0-9a-fA-F]{4}'   # Unicode escapes
        ]
    
    def detect_suspicious_changes(self, url: str, time_window: Optional[timedelta] = None) -> List[Dict[str, Any]]:
        """
        Detect suspicious changes for a URL within a time window.
        
        Args:
            url: The URL to analyze
            time_window: Optional time window to limit the analysis (e.g., last 7 days)
            
        Returns:
            List of suspicious changes with details
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return []
            
            # Build query for content changes
            query = session.query(ContentChange).join(
                ContentVersion, ContentChange.version_id == ContentVersion.id
            ).filter(
                ContentVersion.url_id == url_record.id
            )
            
            # Apply time window if specified
            if time_window:
                cutoff_time = datetime.now() - time_window
                query = query.filter(ContentVersion.timestamp >= cutoff_time)
            
            # Order by suspicion score
            changes = query.order_by(desc(ContentChange.suspicion_score)).all()
            
            suspicious_changes = []
            for change in changes:
                # Only include changes with a suspicion score above threshold
                if change.suspicion_score >= 0.3:
                    version = session.query(ContentVersion).filter_by(id=change.version_id).first()
                    
                    suspicious_changes.append({
                        'change_id': change.id,
                        'version': version.version_number if version else None,
                        'timestamp': version.timestamp.isoformat() if version else None,
                        'change_type': change.change_type,
                        'section_type': change.section_type,
                        'suspicion_score': change.suspicion_score,
                        'content_before': change.content_before,
                        'content_after': change.content_after,
                        'detected_patterns': self._find_suspicious_patterns(change.content_after)
                    })
            
            return suspicious_changes
    
    def _find_suspicious_patterns(self, content: Optional[str]) -> List[str]:
        """
        Find suspicious patterns in content.
        
        Args:
            content: The content to analyze
            
        Returns:
            List of detected suspicious patterns
        """
        if not content:
            return []
        
        detected = []
        for pattern in self._suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(pattern)
        
        return detected
    
    def track_gradual_modifications(self, url: str, min_versions: int = 3) -> List[Dict[str, Any]]:
        """
        Track gradual modifications that might indicate evasion attempts.
        
        Args:
            url: The URL to analyze
            min_versions: Minimum number of versions required for tracking
            
        Returns:
            List of gradual modification tracks
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return []
            
            # Get all versions for this URL
            versions = session.query(ContentVersion).filter_by(
                url_id=url_record.id
            ).order_by(ContentVersion.version_number).all()
            
            if len(versions) < min_versions:
                return []  # Not enough versions to track gradual changes
            
            # Track modifications across code blocks
            code_block_changes = self._track_code_block_evolution(versions, session)
            
            # Track modifications across specific sections
            section_changes = self._track_section_evolution(versions, session)
            
            # Combine results
            return code_block_changes + section_changes
    
    def _track_code_block_evolution(
        self, 
        versions: List[ContentVersion], 
        session: Session
    ) -> List[Dict[str, Any]]:
        """
        Track the evolution of code blocks across versions.
        
        Args:
            versions: List of content versions
            session: Database session
            
        Returns:
            List of code block evolution tracks
        """
        evolution_tracks = []
        
        # Get all code block changes
        code_changes = session.query(ContentChange).filter(
            ContentChange.version_id.in_([v.id for v in versions]),
            ContentChange.section_type == 'code_block'
        ).order_by(ContentChange.version_id).all()
        
        # Group changes by location
        location_groups = {}
        for change in code_changes:
            if not change.location:
                continue
                
            location = json.loads(change.location)
            key = f"{location['old_start']}:{location['old_end']}"
            
            if key not in location_groups:
                location_groups[key] = []
            
            location_groups[key].append(change)
        
        # Analyze each location group for gradual changes
        for location, changes in location_groups.items():
            if len(changes) < 2:
                continue
                
            # Check if changes are gradual (small modifications over time)
            is_gradual = True
            total_change_size = 0
            
            for i in range(1, len(changes)):
                prev_change = changes[i-1]
                curr_change = changes[i]
                
                # If any change is too large, it's not considered gradual
                if curr_change.change_size and curr_change.change_size > 100:
                    is_gradual = False
                    break
                
                total_change_size += curr_change.change_size or 0
            
            if is_gradual and total_change_size > 0:
                # Get the first and last version
                first_version = session.query(ContentVersion).filter_by(
                    id=changes[0].version_id
                ).first()
                
                last_version = session.query(ContentVersion).filter_by(
                    id=changes[-1].version_id
                ).first()
                
                if first_version and last_version:
                    evolution_tracks.append({
                        'type': 'gradual_code_modification',
                        'location': location,
                        'start_version': first_version.version_number,
                        'end_version': last_version.version_number,
                        'start_timestamp': first_version.timestamp.isoformat(),
                        'end_timestamp': last_version.timestamp.isoformat(),
                        'change_count': len(changes),
                        'total_change_size': total_change_size,
                        'initial_content': changes[0].content_before,
                        'final_content': changes[-1].content_after
                    })
        
        return evolution_tracks
    
    def _track_section_evolution(
        self, 
        versions: List[ContentVersion], 
        session: Session
    ) -> List[Dict[str, Any]]:
        """
        Track the evolution of specific sections across versions.
        
        Args:
            versions: List of content versions
            session: Database session
            
        Returns:
            List of section evolution tracks
        """
        # Similar to code block evolution but for other section types
        # Implementation would be similar to _track_code_block_evolution
        # For brevity, returning an empty list for now
        return []
    
    def generate_version_comparison(
        self, 
        url: str, 
        version1: int, 
        version2: int
    ) -> Dict[str, Any]:
        """
        Generate a comparison between two versions.
        
        Args:
            url: The URL
            version1: First version number
            version2: Second version number
            
        Returns:
            Dictionary with comparison information
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return {'error': 'URL not found'}
            
            v1 = session.query(ContentVersion).filter_by(
                url_id=url_record.id, version_number=version1
            ).first()
            
            v2 = session.query(ContentVersion).filter_by(
                url_id=url_record.id, version_number=version2
            ).first()
            
            if not v1 or not v2:
                return {'error': 'One or both versions not found'}
            
            # Generate HTML diff for visualization
            html_diff = self._generate_html_diff(v1.raw_content, v2.raw_content)
            
            # Get all changes between these versions
            changes = []
            for v in range(version1 + 1, version2 + 1):
                version = session.query(ContentVersion).filter_by(
                    url_id=url_record.id, version_number=v
                ).first()
                
                if version:
                    version_changes = session.query(ContentChange).filter_by(
                        version_id=version.id
                    ).all()
                    
                    for change in version_changes:
                        changes.append({
                            'version': v,
                            'timestamp': version.timestamp.isoformat(),
                            'change_type': change.change_type,
                            'section_type': change.section_type,
                            'suspicion_score': change.suspicion_score,
                            'content_before': change.content_before,
                            'content_after': change.content_after
                        })
            
            return {
                'url': url,
                'version1': version1,
                'version2': version2,
                'timestamp1': v1.timestamp.isoformat(),
                'timestamp2': v2.timestamp.isoformat(),
                'html_diff': html_diff,
                'changes': changes
            }
    
    def _generate_html_diff(self, text1: str, text2: str) -> str:
        """
        Generate an HTML diff between two texts.
        
        Args:
            text1: First text
            text2: Second text
            
        Returns:
            HTML string with diff visualization
        """
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()
        
        # Create a diff using difflib's HtmlDiff
        differ = difflib.HtmlDiff()
        html_diff = differ.make_file(lines1, lines2, context=True, numlines=3)
        
        return html_diff