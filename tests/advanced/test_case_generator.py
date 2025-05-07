"""
Test Case Generator for Advanced Testing Framework

This module provides tools for generating comprehensive test cases for the
LLMs.txt Security Analysis Platform, including edge cases, malformed inputs,
and various test scenarios.
"""

import os
import re
import json
import random
import hashlib
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)

class TestCaseGenerator:
    """
    Generates test cases for advanced testing.
    
    This class provides methods to generate various types of test cases for
    testing the platform, including edge cases, malformed inputs, and various
    test scenarios.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the test case generator with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for test case generation.
                   Supported keys:
                   - test_data_dir: Directory containing test data
                   - output_dir: Directory to save generated test cases
                   - seed: Random seed for reproducibility
        """
        self.config = config or {}
        self.test_data_dir = self.config.get("test_data_dir", "tests/data")
        self.output_dir = self.config.get("output_dir", "tests/advanced/test_cases")
        
        # Set random seed if provided
        if "seed" in self.config:
            random.seed(self.config["seed"])
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info("Initialized test case generator")
    
    def generate_test_cases(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Generate a set of test cases.
        
        Args:
            count: Number of test cases to generate
            
        Returns:
            List of test case dictionaries
        """
        logger.info(f"Generating {count} test cases")
        
        test_cases = []
        
        # Generate different types of test cases
        test_cases.extend(self.generate_edge_cases(count // 3))
        test_cases.extend(self.generate_malformed_cases(count // 3))
        test_cases.extend(self.generate_normal_cases(count // 3))
        
        # Fill remaining count with random types
        remaining = count - len(test_cases)
        if remaining > 0:
            test_cases.extend(self.generate_random_cases(remaining))
        
        # Save test cases
        self._save_test_cases(test_cases)
        
        logger.info(f"Generated {len(test_cases)} test cases")
        
        return test_cases
    
    def generate_edge_cases(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate edge cases for testing.
        
        Args:
            count: Number of edge cases to generate
            
        Returns:
            List of edge case dictionaries
        """
        logger.info(f"Generating {count} edge cases")
        
        edge_cases = []
        
        # Define edge case generators
        edge_case_generators = [
            self._generate_empty_case,
            self._generate_minimal_case,
            self._generate_oversized_case,
            self._generate_deeply_nested_case,
            self._generate_malformed_headers_case,
            self._generate_invalid_structure_case,
            self._generate_special_characters_case,
            self._generate_unicode_case,
            self._generate_duplicate_sections_case,
            self._generate_missing_sections_case
        ]
        
        # Generate edge cases
        for i in range(count):
            # Select a random generator
            generator = random.choice(edge_case_generators)
            
            # Generate edge case
            edge_case = generator()
            
            edge_cases.append(edge_case)
        
        logger.info(f"Generated {len(edge_cases)} edge cases")
        
        return edge_cases
    
    def generate_malformed_cases(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate malformed cases for testing.
        
        Args:
            count: Number of malformed cases to generate
            
        Returns:
            List of malformed case dictionaries
        """
        logger.info(f"Generating {count} malformed cases")
        
        malformed_cases = []
        
        # Define malformed case generators
        malformed_case_generators = [
            self._generate_truncated_case,
            self._generate_corrupted_case,
            self._generate_mixed_format_case,
            self._generate_invalid_indentation_case,
            self._generate_unbalanced_quotes_case,
            self._generate_unbalanced_brackets_case,
            self._generate_invalid_code_blocks_case,
            self._generate_html_injection_case,
            self._generate_script_injection_case,
            self._generate_sql_injection_case
        ]
        
        # Generate malformed cases
        for i in range(count):
            # Select a random generator
            generator = random.choice(malformed_case_generators)
            
            # Generate malformed case
            malformed_case = generator()
            
            malformed_cases.append(malformed_case)
        
        logger.info(f"Generated {len(malformed_cases)} malformed cases")
        
        return malformed_cases
    
    def generate_normal_cases(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate normal cases for testing.
        
        Args:
            count: Number of normal cases to generate
            
        Returns:
            List of normal case dictionaries
        """
        logger.info(f"Generating {count} normal cases")
        
        normal_cases = []
        
        # Define normal case generators
        normal_case_generators = [
            self._generate_basic_case,
            self._generate_complex_case,
            self._generate_multi_section_case,
            self._generate_code_heavy_case,
            self._generate_text_heavy_case
        ]
        
        # Generate normal cases
        for i in range(count):
            # Select a random generator
            generator = random.choice(normal_case_generators)
            
            # Generate normal case
            normal_case = generator()
            
            normal_cases.append(normal_case)
        
        logger.info(f"Generated {len(normal_cases)} normal cases")
        
        return normal_cases
    
    def _save_test_cases(self, test_cases: List[Dict[str, Any]]):
        """
        Save test cases to files.
        
        Args:
            test_cases: List of test cases to save
        """
        logger.info(f"Saving {len(test_cases)} test cases")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Save each test case
        for test_case in test_cases:
            # Create file path
            file_path = os.path.join(self.output_dir, f"{test_case['id']}.llms.txt")
            
            # Save test case content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(test_case["content"])
            
            # Save test case metadata
            metadata_path = os.path.join(self.output_dir, f"{test_case['id']}.json")
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(test_case, f, indent=2)
        
        logger.info(f"Saved {len(test_cases)} test cases to {self.output_dir}")
    
    def _generate_empty_case(self) -> Dict[str, Any]:
        """Generate an empty test case."""
        content = ""
        
        return {
            "id": f"empty_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Empty file",
            "edge_case_type": "empty",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_minimal_case(self) -> Dict[str, Any]:
        """Generate a minimal test case."""
        content = "# LLMs.txt\n\n## System Instructions\n\nTest\n\n## User Queries\n\nTest"
        
        return {
            "id": f"minimal_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Minimal valid LLMs.txt file",
            "edge_case_type": "minimal",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_oversized_case(self) -> Dict[str, Any]:
        """Generate an oversized test case."""
        # Create a basic structure
        content = "# LLMs.txt\n\n## System Instructions\n\n"
        
        # Add a large amount of random text
        for _ in range(100):
            content += "".join(random.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(100))
            content += "\n"
        
        content += "\n\n## User Queries\n\nTest"
        
        return {
            "id": f"oversized_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Oversized LLMs.txt file",
            "edge_case_type": "oversized",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_deeply_nested_case(self) -> Dict[str, Any]:
        """Generate a deeply nested test case."""
        content = "# LLMs.txt\n\n## System Instructions\n\n"
        
        # Add deeply nested headers
        for i in range(1, 10):
            content += f"{'#' * (i % 6 + 1)} Nested Level {i}\n\n"
            content += f"Content at level {i}\n\n"
        
        content += "\n\n## User Queries\n\nTest"
        
        return {
            "id": f"nested_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Deeply nested headers in LLMs.txt file",
            "edge_case_type": "deeply_nested",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_malformed_headers_case(self) -> Dict[str, Any]:
        """Generate a test case with malformed headers."""
        content = "# LLMs.txt\n\n"
        
        # Add malformed headers
        headers = [
            "#System Instructions",  # Missing space
            "## System Instructions ",  # Extra space
            "##System Instructions",  # Missing space
            "### System Instructions",  # Wrong level
            " ## System Instructions",  # Leading space
            "## System Instructions#",  # Extra hash
            "## System\nInstructions"  # Line break
        ]
        
        content += random.choice(headers) + "\n\nTest\n\n"
        content += "## User Queries\n\nTest"
        
        return {
            "id": f"malformed_headers_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Malformed headers in LLMs.txt file",
            "edge_case_type": "malformed_headers",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_invalid_structure_case(self) -> Dict[str, Any]:
        """Generate a test case with invalid structure."""
        structures = [
            # Missing LLMs.txt header
            "## System Instructions\n\nTest\n\n## User Queries\n\nTest",
            
            # Missing System Instructions section
            "# LLMs.txt\n\n## User Queries\n\nTest",
            
            # Missing User Queries section
            "# LLMs.txt\n\n## System Instructions\n\nTest",
            
            # Reversed order
            "# LLMs.txt\n\n## User Queries\n\nTest\n\n## System Instructions\n\nTest",
            
            # Duplicate sections
            "# LLMs.txt\n\n## System Instructions\n\nTest\n\n## System Instructions\n\nTest\n\n## User Queries\n\nTest"
        ]
        
        content = random.choice(structures)
        
        return {
            "id": f"invalid_structure_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Invalid structure in LLMs.txt file",
            "edge_case_type": "invalid_structure",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_special_characters_case(self) -> Dict[str, Any]:
        """Generate a test case with special characters."""
        content = "# LLMs.txt\n\n## System Instructions\n\n"
        
        # Add special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?\\~`"
        content += f"Special characters: {special_chars}\n\n"
        
        content += "## User Queries\n\nTest"
        
        return {
            "id": f"special_chars_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Special characters in LLMs.txt file",
            "edge_case_type": "special_characters",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_unicode_case(self) -> Dict[str, Any]:
        """Generate a test case with Unicode characters."""
        content = "# LLMs.txt\n\n## System Instructions\n\n"
        
        # Add Unicode characters
        unicode_chars = "".join([
            "你好",  # Chinese
            "こんにちは",  # Japanese
            "안녕하세요",  # Korean
            "Привет",  # Russian
            "مرحبا",  # Arabic
            "שלום",  # Hebrew
            "Γειά σου",  # Greek
            "नमस्ते",  # Hindi
            "🙂🔥🚀🌍🎉"  # Emoji
        ])
        
        content += f"Unicode characters: {unicode_chars}\n\n"
        content += "## User Queries\n\nTest"
        
        return {
            "id": f"unicode_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Unicode characters in LLMs.txt file",
            "edge_case_type": "unicode",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_basic_case(self) -> Dict[str, Any]:
        """Generate a basic test case."""
        content = "# LLMs.txt\n\n"
        content += "## System Instructions\n\n"
        content += "You are a helpful assistant. Provide accurate and concise information.\n\n"
        content += "## User Queries\n\n"
        content += "Tell me about the weather today."
        
        return {
            "id": f"basic_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Basic LLMs.txt file",
            "edge_case_type": "normal",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_complex_case(self) -> Dict[str, Any]:
        """Generate a complex test case."""
        content = "# LLMs.txt\n\n"
        content += "## System Instructions\n\n"
        content += "You are a helpful assistant with expertise in programming, science, and history. "
        content += "Provide accurate and concise information. When asked about code, provide examples. "
        content += "When asked about science, cite sources. When asked about history, provide context.\n\n"
        content += "## User Queries\n\n"
        content += "1. How do I write a Python function to calculate Fibonacci numbers?\n"
        content += "2. What is the theory of relativity?\n"
        content += "3. Who was the first president of the United States?"
        
        return {
            "id": f"complex_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "Complex LLMs.txt file with multiple queries",
            "edge_case_type": "normal",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_multi_section_case(self) -> Dict[str, Any]:
        """Generate a test case with multiple sections."""
        content = "# LLMs.txt\n\n"
        content += "## System Instructions\n\n"
        content += "You are a helpful assistant.\n\n"
        content += "## User Queries\n\n"
        content += "Tell me about the weather today.\n\n"
        content += "## Expected Responses\n\n"
        content += "I don't have real-time weather data, but I can help you find weather information.\n\n"
        content += "## Metadata\n\n"
        content += "Created: 2023-01-01\nAuthor: Test User\nVersion: 1.0"
        
        return {
            "id": f"multi_section_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "LLMs.txt file with multiple sections",
            "edge_case_type": "normal",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_code_heavy_case(self) -> Dict[str, Any]:
        """Generate a test case with lots of code blocks."""
        content = "# LLMs.txt\n\n"
        content += "## System Instructions\n\n"
        content += "You are a coding assistant. Provide code examples in multiple languages.\n\n"
        content += "## User Queries\n\n"
        content += "Show me how to write a 'Hello, World!' program in different languages.\n\n"
        content += "```python\nprint('Hello, World!')\n```\n\n"
        content += "```javascript\nconsole.log('Hello, World!');\n```\n\n"
        content += "```java\npublic class HelloWorld {\n    public static void main(String[] args) {\n        System.out.println(\"Hello, World!\");\n    }\n}\n```\n\n"
        content += "```c\n#include <stdio.h>\n\nint main() {\n    printf(\"Hello, World!\\n\");\n    return 0;\n}\n```\n\n"
        content += "```go\npackage main\n\nimport \"fmt\"\n\nfunc main() {\n    fmt.Println(\"Hello, World!\")\n}\n```"
        
        return {
            "id": f"code_heavy_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "LLMs.txt file with lots of code blocks",
            "edge_case_type": "normal",
            "timestamp": datetime.now().isoformat()
        }
    
    def _generate_text_heavy_case(self) -> Dict[str, Any]:
        """Generate a test case with lots of text."""
        content = "# LLMs.txt\n\n"
        content += "## System Instructions\n\n"
        content += "You are a helpful assistant specializing in providing detailed explanations on complex topics.\n\n"
        content += "## User Queries\n\n"
        content += "Explain the process of photosynthesis in detail.\n\n"
        content += "Photosynthesis is the process by which green plants, algae, and some bacteria convert light energy, usually from the sun, into chemical energy in the form of glucose or other sugars. This process is essential for life on Earth as it provides the oxygen we breathe and the food we eat.\n\n"
        content += "The process of photosynthesis occurs in two main stages: the light-dependent reactions and the light-independent reactions (Calvin cycle).\n\n"
        content += "In the light-dependent reactions, which take place in the thylakoid membrane of the chloroplast:\n\n"
        content += "1. Light energy is absorbed by chlorophyll and other pigments in protein complexes called photosystems.\n"
        content += "2. This energy is used to split water molecules, releasing oxygen as a byproduct.\n"
        content += "3. The energy is also used to generate ATP (adenosine triphosphate) and NADPH (nicotinamide adenine dinucleotide phosphate), which are energy-carrying molecules.\n\n"
        content += "In the light-independent reactions, also known as the Calvin cycle, which take place in the stroma of the chloroplast:\n\n"
        content += "1. Carbon dioxide from the atmosphere is captured and combined with a 5-carbon sugar called ribulose bisphosphate (RuBP).\n"
        content += "2. This reaction is catalyzed by the enzyme RuBisCO and produces a 6-carbon compound that immediately splits into two 3-carbon compounds.\n"
        content += "3. These 3-carbon compounds are then reduced using the ATP and NADPH from the light-dependent reactions to form glucose and other sugars.\n"
        content += "4. Some of the 3-carbon compounds are used to regenerate RuBP, completing the cycle.\n\n"
        content += "The overall equation for photosynthesis is:\n\n"
        content += "6 CO₂ + 6 H₂O + light energy → C₆H₁₂O₆ + 6 O₂\n\n"
        content += "This equation shows that carbon dioxide and water, with the input of light energy, produce glucose and oxygen."
        
        return {
            "id": f"text_heavy_{hashlib.md5(content.encode()).hexdigest()[:8]}",
            "content": content,
            "description": "LLMs.txt file with lots of text",
            "edge_case_type": "normal",
            "timestamp": datetime.now().isoformat()
        }