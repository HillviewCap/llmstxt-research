"""
Feature Extraction Module for ML-based Analysis

This module provides functionality to extract features from content for use in machine learning models.
Features include text-based features, code structure features, and metadata features.
"""

import re
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union
from collections import Counter

class FeatureExtractor:
    """
    Extracts features from content for machine learning models.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the feature extractor with optional configuration.
        
        Args:
            config: Configuration dictionary with feature extraction parameters
        """
        self.config = config or {}
        self.feature_version = "1.0.0"
        
        # Default feature sets to extract (can be overridden in config)
        self.enabled_feature_sets = self.config.get("enabled_feature_sets", [
            "text_statistics", 
            "code_patterns", 
            "markdown_structure",
            "security_indicators",
            "metadata"
        ])
        
        # Load any pre-trained vectorizers or encoders if specified in config
        self._load_vectorizers()
    
    def _load_vectorizers(self):
        """Load any pre-trained vectorizers or encoders from disk"""
        # This would load any saved scikit-learn vectorizers or encoders
        # For now, we'll just initialize empty placeholders
        self.vectorizers = {}
    
    def extract_features(self, content_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all enabled feature sets from a content item.
        
        Args:
            content_item: Dictionary containing content and metadata
                Expected keys: 'raw_content', 'url', 'processed_id', etc.
                
        Returns:
            Dictionary of extracted features
        """
        features = {
            "feature_version": self.feature_version,
            "content_id": content_item.get("processed_id", "unknown"),
            "feature_sets": {}
        }
        
        raw_content = content_item.get("raw_content", "")
        if not raw_content:
            return features
        
        # Extract each enabled feature set
        if "text_statistics" in self.enabled_feature_sets:
            features["feature_sets"]["text_statistics"] = self._extract_text_statistics(raw_content)
            
        if "code_patterns" in self.enabled_feature_sets:
            features["feature_sets"]["code_patterns"] = self._extract_code_patterns(raw_content)
            
        if "markdown_structure" in self.enabled_feature_sets:
            features["feature_sets"]["markdown_structure"] = self._extract_markdown_structure(raw_content)
            
        if "security_indicators" in self.enabled_feature_sets:
            features["feature_sets"]["security_indicators"] = self._extract_security_indicators(raw_content)
            
        if "metadata" in self.enabled_feature_sets:
            features["feature_sets"]["metadata"] = self._extract_metadata(content_item)
        
        # Add feature vector for ML models
        features["feature_vector"] = self._create_feature_vector(features["feature_sets"])
        
        return features
    
    def _extract_text_statistics(self, content: str) -> Dict[str, Any]:
        """Extract statistical features from text content"""
        lines = content.split("\n")
        words = re.findall(r'\b\w+\b', content.lower())
        
        return {
            "line_count": len(lines),
            "char_count": len(content),
            "word_count": len(words),
            "avg_line_length": np.mean([len(line) for line in lines]) if lines else 0,
            "avg_word_length": np.mean([len(word) for word in words]) if words else 0,
            "unique_words": len(set(words)),
            "lexical_diversity": len(set(words)) / len(words) if words else 0,
            "special_char_ratio": len(re.findall(r'[^a-zA-Z0-9\s]', content)) / len(content) if content else 0
        }
    
    def _extract_code_patterns(self, content: str) -> Dict[str, Any]:
        """Extract features related to code patterns"""
        # Extract code blocks
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)\n```', content, re.DOTALL)
        
        # Count code-related patterns
        patterns = {
            "eval_exec_count": len(re.findall(r'\b(eval|exec|subprocess\.call|os\.system)\b', content)),
            "import_count": len(re.findall(r'\b(import|require|from\s+\w+\s+import)\b', content)),
            "function_count": len(re.findall(r'\b(function|def)\s+\w+\s*\(', content)),
            "url_count": len(re.findall(r'https?://[^\s"\']+', content)),
            "code_block_count": len(code_blocks),
            "has_obfuscated_code": bool(re.search(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-7]{3}', content))
        }
        
        # Language detection (simplified)
        languages = []
        for block in re.findall(r'```(\w+)', content):
            if block and block.lower() not in ('', 'text', 'markdown', 'md'):
                languages.append(block.lower())
        
        patterns["detected_languages"] = Counter(languages)
        patterns["language_count"] = len(patterns["detected_languages"])
        
        return patterns
    
    def _extract_markdown_structure(self, content: str) -> Dict[str, Any]:
        """Extract features related to markdown document structure"""
        structure = {
            "heading_count": len(re.findall(r'^#+\s+.+$', content, re.MULTILINE)),
            "list_item_count": len(re.findall(r'^[\s]*[-*+]\s+.+$', content, re.MULTILINE)),
            "table_count": len(re.findall(r'\|.+\|.+\|\n\|[-:|\s]+\|', content)),
            "link_count": len(re.findall(r'\[.+?\]\(.+?\)', content)),
            "image_count": len(re.findall(r'!\[.+?\]\(.+?\)', content)),
            "blockquote_count": len(re.findall(r'^>\s+.+$', content, re.MULTILINE)),
            "section_count": len(re.findall(r'^#{2,3}\s+.+$', content, re.MULTILINE))
        }
        
        # Extract headings to analyze document structure
        headings = re.findall(r'^(#+)\s+(.+)$', content, re.MULTILINE)
        heading_levels = [len(h[0]) for h in headings]
        
        structure["max_heading_depth"] = max(heading_levels) if heading_levels else 0
        structure["has_proper_structure"] = bool(re.search(r'^#\s+.+\n+^#{2}\s+.+', content, re.MULTILINE))
        
        return structure
    
    def _extract_security_indicators(self, content: str) -> Dict[str, Any]:
        """Extract features related to security indicators"""
        indicators = {
            "has_credentials": bool(re.search(r'\b(password|api[_\s]?key|secret|token|auth)[_\s]?(=|:)\s*[\'"][^\'"]+[\'"]', content, re.IGNORECASE)),
            "has_ip_addresses": bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)),
            "has_base64": bool(re.search(r'[a-zA-Z0-9+/]{30,}={0,2}', content)),
            "has_script_tags": bool(re.search(r'<script\b[^>]*>(.*?)</script>', content, re.IGNORECASE | re.DOTALL)),
            "has_suspicious_urls": bool(re.search(r'https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?:/[^)\s]*)?', content)),
            "has_command_injection": bool(re.search(r'\b(system|exec|popen|subprocess\.call|child_process\.exec)\b', content)),
            "has_sql_patterns": bool(re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|JOIN)\b.*\b(FROM|INTO|WHERE|TABLE)\b', content, re.IGNORECASE))
        }
        
        # Count potential evasion techniques
        indicators["evasion_techniques"] = {
            "string_splitting": len(re.findall(r'[\'"][^\'"]*[\'"] *\+ *[\'"]', content)),
            "char_encoding": len(re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', content)),
            "indirect_eval": len(re.findall(r'window\[[\'"]eval[\'"]\]|this\[[\'"]eval[\'"]\]', content))
        }
        
        return indicators
    
    def _extract_metadata(self, content_item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from content metadata"""
        return {
            "url_length": len(content_item.get("url", "")),
            "has_suspicious_domain": bool(re.search(r'(\.xyz|\.top|\.cc|\.tk)\b', content_item.get("url", ""))),
            "content_size": len(content_item.get("raw_content", "")),
            "has_analysis_history": bool(content_item.get("analysis_history", False))
        }
    
    def _create_feature_vector(self, feature_sets: Dict[str, Dict[str, Any]]) -> List[float]:
        """
        Convert extracted features into a numerical vector for ML models.
        This is a simplified implementation - in practice, this would use
        proper feature encoding, normalization, etc.
        """
        # This is a simplified vector creation - in practice, you would use
        # scikit-learn's DictVectorizer, OneHotEncoder, etc.
        vector = []
        
        # Text statistics features
        if "text_statistics" in feature_sets:
            stats = feature_sets["text_statistics"]
            vector.extend([
                stats.get("line_count", 0),
                stats.get("char_count", 0),
                stats.get("word_count", 0),
                stats.get("avg_line_length", 0),
                stats.get("avg_word_length", 0),
                stats.get("lexical_diversity", 0),
                stats.get("special_char_ratio", 0)
            ])
        
        # Code pattern features
        if "code_patterns" in feature_sets:
            patterns = feature_sets["code_patterns"]
            vector.extend([
                patterns.get("eval_exec_count", 0),
                patterns.get("import_count", 0),
                patterns.get("function_count", 0),
                patterns.get("url_count", 0),
                patterns.get("code_block_count", 0),
                1 if patterns.get("has_obfuscated_code", False) else 0,
                patterns.get("language_count", 0)
            ])
        
        # Markdown structure features
        if "markdown_structure" in feature_sets:
            structure = feature_sets["markdown_structure"]
            vector.extend([
                structure.get("heading_count", 0),
                structure.get("list_item_count", 0),
                structure.get("table_count", 0),
                structure.get("link_count", 0),
                structure.get("image_count", 0),
                structure.get("blockquote_count", 0),
                structure.get("max_heading_depth", 0),
                1 if structure.get("has_proper_structure", False) else 0
            ])
        
        # Security indicator features
        if "security_indicators" in feature_sets:
            indicators = feature_sets["security_indicators"]
            vector.extend([
                1 if indicators.get("has_credentials", False) else 0,
                1 if indicators.get("has_ip_addresses", False) else 0,
                1 if indicators.get("has_base64", False) else 0,
                1 if indicators.get("has_script_tags", False) else 0,
                1 if indicators.get("has_suspicious_urls", False) else 0,
                1 if indicators.get("has_command_injection", False) else 0,
                1 if indicators.get("has_sql_patterns", False) else 0
            ])
            
            # Add evasion techniques if available
            evasion = indicators.get("evasion_techniques", {})
            vector.extend([
                evasion.get("string_splitting", 0),
                evasion.get("char_encoding", 0),
                evasion.get("indirect_eval", 0)
            ])
        
        # Metadata features
        if "metadata" in feature_sets:
            metadata = feature_sets["metadata"]
            vector.extend([
                metadata.get("url_length", 0),
                1 if metadata.get("has_suspicious_domain", False) else 0,
                metadata.get("content_size", 0),
                1 if metadata.get("has_analysis_history", False) else 0
            ])
        
        return vector
    
    def extract_features_batch(self, content_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract features from a batch of content items.
        
        Args:
            content_items: List of content item dictionaries
                
        Returns:
            List of feature dictionaries
        """
        return [self.extract_features(item) for item in content_items]
    
    def get_feature_names(self) -> List[str]:
        """
        Get the names of features in the feature vector.
        
        Returns:
            List of feature names in the same order as the feature vector
        """
        # This would return the actual feature names in the same order as the vector
        # For now, returning a placeholder
        return [f"feature_{i}" for i in range(len(self._create_feature_vector({})))]