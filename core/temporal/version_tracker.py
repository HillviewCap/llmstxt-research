"""
Version Tracking Implementation for Temporal Analysis

This module provides functionality for:
1. Content versioning system
2. Change detection between versions
3. Differential analysis
4. Historical trend tracking
"""

import hashlib
import difflib
import json
from typing import Dict, Any, List, Tuple, Optional, Union
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc

from core.database.connector import DatabaseConnector
from core.database.schema import Urls, ProcessedMarkdownContent, SecurityAnalysisResult
from core.temporal.schema import ContentVersion, ContentChange, HistoricalRiskScore


class VersionTracker:
    """
    Manages content versioning and change detection for temporal analysis.
    """
    
    def __init__(self, db_connector: DatabaseConnector):
        """
        Initialize the version tracker with a database connector.
        
        Args:
            db_connector: Database connector for accessing the database
        """
        self._db_connector = db_connector
    
    def _calculate_hash(self, content: str) -> str:
        """
        Calculate a SHA-256 hash for the given content.
        
        Args:
            content: The content to hash
            
        Returns:
            The SHA-256 hash as a hexadecimal string
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def track_version(self, url: str, content: str, processed_content_id: Optional[int] = None) -> Tuple[ContentVersion, bool]:
        """
        Track a new version of content for a URL.
        
        Args:
            url: The URL of the content
            content: The raw content
            processed_content_id: ID of the processed content record (optional)
            
        Returns:
            Tuple of (ContentVersion, is_new_version)
        """
        content_hash = self._calculate_hash(content)
        
        with self._db_connector.session_scope() as session:
            # Get or create URL record
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                url_record = Urls(url_string=url)
                session.add(url_record)
                session.flush()
            
            # Check if this exact content version already exists
            existing_version = session.query(ContentVersion).filter_by(
                url_id=url_record.id,
                content_hash=content_hash
            ).first()
            
            if existing_version:
                return existing_version, False
            
            # Get the latest version number for this URL
            latest_version = session.query(ContentVersion).filter_by(
                url_id=url_record.id
            ).order_by(desc(ContentVersion.version_number)).first()
            
            new_version_number = 1
            previous_version = None
            
            if latest_version:
                new_version_number = latest_version.version_number + 1
                previous_version = latest_version
            
            # Create new version record
            new_version = ContentVersion(
                url_id=url_record.id,
                content_hash=content_hash,
                version_number=new_version_number,
                raw_content=content,
                processed_content_id=processed_content_id
            )
            session.add(new_version)
            session.flush()
            
            # If there's a previous version, detect and record changes
            if previous_version:
                changes = self.detect_changes(
                    previous_version.raw_content,
                    content,
                    previous_version.id,
                    new_version.id,
                    session
                )
                
                # Update analysis history
                self._update_analysis_history(url_record.id, bool(changes), session)
            
            return new_version, True
    
    def detect_changes(
        self, 
        old_content: str, 
        new_content: str, 
        old_version_id: int, 
        new_version_id: int,
        session: Session
    ) -> List[ContentChange]:
        """
        Detect changes between two versions of content.
        
        Args:
            old_content: Previous version content
            new_content: New version content
            old_version_id: ID of the previous version
            new_version_id: ID of the new version
            session: Database session
            
        Returns:
            List of ContentChange records
        """
        changes = []
        
        # Split content into lines for comparison
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        
        # Use difflib to get a sequence matcher
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
        
        # Process the opcodes to identify changes
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                continue
                
            # Extract the changed content
            old_section = '\n'.join(old_lines[i1:i2]) if i1 < i2 else None
            new_section = '\n'.join(new_lines[j1:j2]) if j1 < j2 else None
            
            # Determine change type
            change_type = {
                'replace': 'modification',
                'delete': 'deletion',
                'insert': 'addition'
            }.get(tag, 'unknown')
            
            # Create a change record
            change = ContentChange(
                version_id=new_version_id,
                previous_version_id=old_version_id,
                change_type=change_type,
                section_type=self._guess_section_type(old_section, new_section),
                location=json.dumps({
                    'old_start': i1,
                    'old_end': i2,
                    'new_start': j1,
                    'new_end': j2
                }),
                content_before=old_section,
                content_after=new_section,
                change_size=self._calculate_change_size(old_section, new_section),
                suspicion_score=self._calculate_suspicion_score(old_section, new_section, change_type)
            )
            
            session.add(change)
            changes.append(change)
        
        return changes
    
    def _guess_section_type(self, old_section: Optional[str], new_section: Optional[str]) -> str:
        """
        Guess the type of section that was changed based on content.
        
        Args:
            old_section: The content before the change
            new_section: The content after the change
            
        Returns:
            Section type as a string
        """
        # Use the non-None section for detection
        section = new_section if new_section is not None else old_section
        if section is None:
            return 'unknown'
        
        # Check for code block markers
        if '```' in section:
            return 'code_block'
        
        # Check for URL patterns
        if 'http://' in section or 'https://' in section:
            return 'url'
        
        # Check for heading patterns
        if section.strip().startswith('#'):
            return 'heading'
        
        # Default to text
        return 'text'
    
    def _calculate_change_size(self, old_section: Optional[str], new_section: Optional[str]) -> int:
        """
        Calculate the size of a change in characters.
        
        Args:
            old_section: Content before the change
            new_section: Content after the change
            
        Returns:
            Size of the change in characters
        """
        old_len = len(old_section) if old_section else 0
        new_len = len(new_section) if new_section else 0
        
        if old_section is None:  # Addition
            return new_len
        elif new_section is None:  # Deletion
            return old_len
        else:  # Modification
            return abs(new_len - old_len)
    
    def _calculate_suspicion_score(
        self, 
        old_section: Optional[str], 
        new_section: Optional[str],
        change_type: str
    ) -> float:
        """
        Calculate a suspicion score for a change based on heuristics.
        
        Args:
            old_section: Content before the change
            new_section: Content after the change
            change_type: Type of change (addition, deletion, modification)
            
        Returns:
            Suspicion score between 0.0 and 1.0
        """
        score = 0.0
        
        # Large deletions are suspicious
        if change_type == 'deletion' and old_section and len(old_section) > 500:
            score += 0.4
        
        # Check for suspicious patterns in additions
        if new_section:
            suspicious_patterns = [
                'eval(', 'exec(', 'document.write(', 'innerHTML', 
                'fetch(', 'XMLHttpRequest', 'new Function(', 'setTimeout(',
                'setInterval(', 'WebSocket(', 'localStorage', 'sessionStorage'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in new_section:
                    score += 0.3
                    break
        
        # Gradual modifications (small changes) might be evasion attempts
        if change_type == 'modification' and old_section and new_section:
            similarity = difflib.SequenceMatcher(None, old_section, new_section).ratio()
            if similarity > 0.8:  # Very similar but not identical
                score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _update_analysis_history(self, url_id: int, changes_detected: bool, session: Session) -> None:
        """
        Update the analysis history record for a URL.
        
        Args:
            url_id: ID of the URL
            changes_detected: Whether changes were detected
            session: Database session
        """
        from core.database.schema import AnalysisHistory
        
        history_entry = AnalysisHistory(
            url_id=url_id,
            changes_detected=changes_detected,
            change_summary="Content changes detected" if changes_detected else "No changes detected"
        )
        session.add(history_entry)
    
    def get_version_history(self, url: str) -> List[Dict[str, Any]]:
        """
        Get the version history for a URL.
        
        Args:
            url: The URL to get history for
            
        Returns:
            List of version records with change information
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                return []
            
            versions = session.query(ContentVersion).filter_by(
                url_id=url_record.id
            ).order_by(ContentVersion.version_number).all()
            
            result = []
            for version in versions:
                changes = session.query(ContentChange).filter_by(
                    version_id=version.id
                ).all()
                
                change_summary = []
                for change in changes:
                    change_summary.append({
                        'type': change.change_type,
                        'section_type': change.section_type,
                        'size': change.change_size,
                        'suspicion_score': change.suspicion_score
                    })
                
                result.append({
                    'version': version.version_number,
                    'timestamp': version.timestamp.isoformat(),
                    'changes': change_summary
                })
            
            return result
    
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
            
            # Generate a unified diff
            diff_lines = list(difflib.unified_diff(
                v1.raw_content.splitlines(),
                v2.raw_content.splitlines(),
                fromfile=f'Version {version1}',
                tofile=f'Version {version2}',
                lineterm=''
            ))
            
            # Get changes between these versions
            changes = session.query(ContentChange).filter_by(
                version_id=v2.id, previous_version_id=v1.id
            ).all()
            
            change_details = []
            for change in changes:
                change_details.append({
                    'type': change.change_type,
                    'section_type': change.section_type,
                    'location': json.loads(change.location) if change.location else None,
                    'content_before': change.content_before,
                    'content_after': change.content_after,
                    'suspicion_score': change.suspicion_score
                })
            
            return {
                'url': url,
                'version1': version1,
                'version2': version2,
                'timestamp1': v1.timestamp.isoformat(),
                'timestamp2': v2.timestamp.isoformat(),
                'unified_diff': diff_lines,
                'changes': change_details
            }
    
    def track_risk_score(
        self, 
        url: str, 
        version_id: Optional[int], 
        analysis_result: SecurityAnalysisResult
    ) -> HistoricalRiskScore:
        """
        Track a risk score for historical analysis.
        
        Args:
            url: The URL
            version_id: ID of the content version (optional)
            analysis_result: Security analysis result
            
        Returns:
            The created HistoricalRiskScore record
        """
        with self._db_connector.session_scope() as session:
            url_record = session.query(Urls).filter_by(url_string=url).first()
            if not url_record:
                raise ValueError(f"URL not found: {url}")
            
            # Extract component scores from analysis result findings
            component_scores = {
                'markdown_risk': 0.0,
                'pattern_risk': 0.0,
                'secrets_risk': 0.0,
                'static_risk': 0.0
            }
            
            # This assumes findings are organized by component
            for finding in analysis_result.findings:
                if 'markdown' in finding.finding_type.lower():
                    component_scores['markdown_risk'] = max(component_scores['markdown_risk'], finding.severity_score)
                elif 'pattern' in finding.finding_type.lower():
                    component_scores['pattern_risk'] = max(component_scores['pattern_risk'], finding.severity_score)
                elif 'secret' in finding.finding_type.lower():
                    component_scores['secrets_risk'] = max(component_scores['secrets_risk'], finding.severity_score)
                elif 'static' in finding.finding_type.lower():
                    component_scores['static_risk'] = max(component_scores['static_risk'], finding.severity_score)
            
            # Create historical risk score record
            risk_score = HistoricalRiskScore(
                url_id=url_record.id,
                version_id=version_id,
                analysis_id=analysis_result.id,
                overall_risk_score=analysis_result.overall_risk_score,
                malicious_confidence=analysis_result.malicious_confidence,
                **component_scores
            )
            
            session.add(risk_score)
            session.commit()
            
            return risk_score