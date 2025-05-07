# LLMs.txt Security Analysis Platform: Plugin Development Guide

This guide explains how to develop custom plugins and analyzers for the LLMs.txt Security Analysis Platform. By creating plugins, you can extend the platform's capabilities to detect new types of security issues or integrate with additional tools.

## Overview

The platform is designed with extensibility in mind, allowing developers to create custom analyzers, rules, and integrations. Plugins can be developed for:

1. **Static Analysis**: Detecting code-related security issues
2. **Pattern Matching**: Identifying suspicious patterns
3. **Secrets Detection**: Finding exposed credentials
4. **Markdown Analysis**: Validating document structure
5. **Custom Analysis**: Implementing specialized detection logic

## Plugin Architecture

Plugins in the LLMs.txt Security Analysis Platform follow a modular architecture:

```
plugins/
├── custom/           # Custom plugins
├── semgrep/          # Semgrep integration
├── trufflehog/       # TruffleHog integration
└── yara/             # YARA integration
```

Each plugin type has a specific interface it must implement to integrate with the platform.

## Creating a Basic Plugin

### 1. Create Plugin Directory

Create a new directory for your plugin in the `plugins/custom/` directory:

```bash
mkdir -p plugins/custom/my_plugin
```

### 2. Create Plugin Module

Create a Python module for your plugin:

```bash
touch plugins/custom/my_plugin/__init__.py
touch plugins/custom/my_plugin/analyzer.py
```

### 3. Implement Analyzer Interface

Each analyzer must implement the `analyze` method, which takes a processed content item and returns analysis results.

Example `analyzer.py`:

```python
class MyCustomAnalyzer:
    """Custom analyzer for detecting specific patterns."""
    
    def __init__(self, config=None):
        """
        Initialize the analyzer.
        
        Args:
            config (dict, optional): Configuration options. Defaults to None.
        """
        self.config = config or {}
        self.name = "my_custom_analyzer"
        
    def analyze(self, content_item):
        """
        Analyze a content item and return findings.
        
        Args:
            content_item (dict): Processed content item with structure.
            
        Returns:
            dict: Analysis results with findings.
        """
        findings = []
        
        # Example: Check for a specific pattern in the content
        if "structure" in content_item and "code_blocks" in content_item["structure"]:
            for code_block in content_item["structure"]["code_blocks"]:
                if "dangerous_function(" in code_block["content"]:
                    findings.append({
                        "type": "dangerous_function",
                        "severity": "HIGH",
                        "description": "Use of dangerous function detected",
                        "location": {
                            "line_start": code_block["line_start"],
                            "line_end": code_block["line_end"],
                            "code": code_block["content"]
                        },
                        "confidence": 0.9
                    })
        
        return {
            "findings": findings,
            "analyzer": self.name
        }
```

### 4. Register Plugin

Create an `__init__.py` file to expose your analyzer:

```python
from .analyzer import MyCustomAnalyzer

# This will be imported by the platform
analyzer = MyCustomAnalyzer()
```

## Integrating with the Platform

### Option 1: Direct Integration

You can integrate your plugin directly with the pipeline by modifying `core/pipeline.py`:

```python
# Import your custom analyzer
from plugins.custom.my_plugin import analyzer as my_custom_analyzer

class Pipeline:
    def __init__(self, config=None):
        # ... existing initialization ...
        self.my_custom_analyzer = my_custom_analyzer
        
    def _analyze_item(self, item):
        # ... existing analyzers ...
        my_custom_res = {}
        try:
            my_custom_res = self.my_custom_analyzer.analyze(item)
        except Exception as e:
            self.logger.error(f"Custom analysis for item failed: {e}", exc_info=True)
            my_custom_res = {"error": str(e)}
            
        return {
            "markdown": markdown_res,
            "patterns": patterns_res,
            "secrets": secrets_res,
            "static": static_res,
            "my_custom": my_custom_res,  # Add your analyzer results
        }
```

### Option 2: Plugin Discovery

For a more flexible approach, implement plugin discovery:

1. Create a plugin registry in `core/plugins/registry.py`:

```python
class PluginRegistry:
    """Registry for dynamically loaded plugins."""
    
    def __init__(self):
        self.analyzers = {}
        
    def register_analyzer(self, name, analyzer):
        """Register an analyzer plugin."""
        self.analyzers[name] = analyzer
        
    def get_analyzer(self, name):
        """Get a registered analyzer by name."""
        return self.analyzers.get(name)
        
    def get_all_analyzers(self):
        """Get all registered analyzers."""
        return self.analyzers

# Singleton instance
registry = PluginRegistry()
```

2. Create a plugin loader in `core/plugins/loader.py`:

```python
import importlib
import os
import pkgutil
from core.plugins.registry import registry

def discover_plugins():
    """Discover and load all plugins."""
    plugins_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'plugins')
    
    for _, name, ispkg in pkgutil.iter_modules([plugins_dir]):
        if ispkg:
            # Load the plugin package
            plugin_pkg = importlib.import_module(f'plugins.{name}')
            
            # Check if it has an analyzer attribute
            if hasattr(plugin_pkg, 'analyzer'):
                registry.register_analyzer(name, plugin_pkg.analyzer)
```

3. Update the pipeline to use the registry:

```python
from core.plugins.registry import registry
from core.plugins.loader import discover_plugins

class Pipeline:
    def __init__(self, config=None):
        # ... existing initialization ...
        
        # Discover and load plugins
        discover_plugins()
        self.plugin_analyzers = registry.get_all_analyzers()
        
    def _analyze_item(self, item):
        # ... existing analyzers ...
        
        # Run plugin analyzers
        plugin_results = {}
        for name, analyzer in self.plugin_analyzers.items():
            try:
                plugin_results[name] = analyzer.analyze(item)
            except Exception as e:
                self.logger.error(f"Plugin {name} analysis failed: {e}", exc_info=True)
                plugin_results[name] = {"error": str(e)}
        
        results = {
            "markdown": markdown_res,
            "patterns": patterns_res,
            "secrets": secrets_res,
            "static": static_res,
        }
        
        # Add plugin results
        results.update(plugin_results)
        
        return results
```

## Creating Specialized Plugins

### Static Analysis Plugin

For static code analysis, create a plugin that integrates with tools like Semgrep:

```python
import subprocess
import json
import tempfile
import os

class CustomSemgrepAnalyzer:
    """Custom Semgrep analyzer for detecting security issues in code."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.name = "custom_semgrep"
        self.rules_path = self.config.get("rules_path", "rules/custom_semgrep")
        
    def analyze(self, content_item):
        findings = []
        
        if "structure" not in content_item or "code_blocks" not in content_item["structure"]:
            return {"findings": findings, "analyzer": self.name}
            
        for code_block in content_item["structure"]["code_blocks"]:
            language = code_block.get("language")
            content = code_block.get("content")
            
            if not language or not content:
                continue
                
            # Create temporary file for the code block
            with tempfile.NamedTemporaryFile(suffix=f'.{language}', delete=False) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(content.encode('utf-8'))
                
            try:
                # Run Semgrep on the temporary file
                cmd = [
                    "semgrep",
                    "--config", self.rules_path,
                    "--json",
                    temp_file_path
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout:
                    semgrep_results = json.loads(result.stdout)
                    
                    for finding in semgrep_results.get("results", []):
                        findings.append({
                            "type": finding.get("check_id", "unknown"),
                            "severity": finding.get("extra", {}).get("severity", "MEDIUM").upper(),
                            "description": finding.get("extra", {}).get("message", ""),
                            "location": {
                                "line_start": code_block["line_start"] + finding.get("start", {}).get("line", 0) - 1,
                                "line_end": code_block["line_start"] + finding.get("end", {}).get("line", 0) - 1,
                                "code": finding.get("extra", {}).get("lines", "")
                            },
                            "confidence": 0.8
                        })
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)
                
        return {
            "findings": findings,
            "analyzer": self.name
        }
```

### Pattern Matching Plugin

For pattern matching, create a plugin that uses regular expressions or YARA:

```python
import re
import yaml
import os

class CustomPatternAnalyzer:
    """Custom pattern analyzer for detecting suspicious patterns."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.name = "custom_pattern"
        self.patterns_file = self.config.get("patterns_file", "rules/custom_patterns/patterns.yaml")
        self.patterns = self._load_patterns()
        
    def _load_patterns(self):
        """Load patterns from YAML file."""
        if not os.path.exists(self.patterns_file):
            return []
            
        with open(self.patterns_file, 'r') as f:
            patterns_data = yaml.safe_load(f)
            
        return patterns_data.get("patterns", [])
        
    def analyze(self, content_item):
        findings = []
        
        if "content" not in content_item:
            return {"findings": findings, "analyzer": self.name}
            
        content = content_item["content"]
        
        for pattern in self.patterns:
            pattern_id = pattern.get("id", "unknown")
            regex = pattern.get("regex", "")
            description = pattern.get("description", "")
            severity = pattern.get("severity", "MEDIUM").upper()
            
            if not regex:
                continue
                
            try:
                matches = re.finditer(regex, content, re.MULTILINE)
                
                for match in matches:
                    # Find line number of the match
                    line_number = content[:match.start()].count('\n') + 1
                    
                    findings.append({
                        "type": pattern_id,
                        "severity": severity,
                        "description": description,
                        "location": {
                            "line": line_number,
                            "match": match.group(0)
                        },
                        "confidence": 0.7
                    })
            except re.error as e:
                # Log regex error
                print(f"Error in pattern {pattern_id}: {e}")
                
        return {
            "findings": findings,
            "analyzer": self.name
        }
```

### Secrets Detection Plugin

For secrets detection, create a plugin that looks for credentials:

```python
import re

class CustomSecretsAnalyzer:
    """Custom analyzer for detecting secrets and credentials."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.name = "custom_secrets"
        
        # Common patterns for secrets
        self.patterns = [
            {
                "id": "api_key",
                "regex": r'api[_-]?key[_-]?[=:]\s*["\']([\w\d]{16,})["\'"]',
                "description": "API Key detected",
                "severity": "HIGH"
            },
            {
                "id": "password",
                "regex": r'password[_-]?[=:]\s*["\']([\w\d@$!%*#?&]{8,})["\'"]',
                "description": "Password detected",
                "severity": "HIGH"
            },
            {
                "id": "aws_key",
                "regex": r'(AKIA[0-9A-Z]{16})',
                "description": "AWS Access Key detected",
                "severity": "CRITICAL"
            }
        ]
        
    def analyze(self, content_item):
        findings = []
        
        if "content" not in content_item:
            return {"findings": findings, "analyzer": self.name}
            
        content = content_item["content"]
        
        for pattern in self.patterns:
            pattern_id = pattern.get("id", "unknown")
            regex = pattern.get("regex", "")
            description = pattern.get("description", "")
            severity = pattern.get("severity", "HIGH")
            
            if not regex:
                continue
                
            try:
                matches = re.finditer(regex, content, re.MULTILINE)
                
                for match in matches:
                    # Find line number of the match
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Redact the actual secret value
                    secret_value = match.group(1) if match.groups() else match.group(0)
                    redacted_value = secret_value[:4] + '*' * (len(secret_value) - 4)
                    
                    findings.append({
                        "type": pattern_id,
                        "severity": severity,
                        "description": description,
                        "location": {
                            "line": line_number,
                            "match": match.group(0).replace(secret_value, redacted_value)
                        },
                        "confidence": 0.9
                    })
            except re.error as e:
                # Log regex error
                print(f"Error in pattern {pattern_id}: {e}")
                
        return {
            "findings": findings,
            "analyzer": self.name
        }
```

## Plugin Configuration

Plugins can be configured through the main configuration file:

```yaml
plugins:
  custom_semgrep:
    enabled: true
    rules_path: "rules/custom_semgrep"
  
  custom_pattern:
    enabled: true
    patterns_file: "rules/custom_patterns/patterns.yaml"
  
  custom_secrets:
    enabled: true
    additional_patterns:
      - id: "custom_token"
        regex: "TOKEN[=:]['\"]([a-zA-Z0-9]{32})['\"]"
        description: "Custom token detected"
        severity: "HIGH"
```

## Testing Plugins

Create tests for your plugins to ensure they work correctly:

```python
# tests/unit/plugins/test_custom_plugin.py

import pytest
from plugins.custom.my_plugin.analyzer import MyCustomAnalyzer

def test_custom_analyzer_finds_dangerous_function():
    """Test that the custom analyzer detects dangerous functions."""
    analyzer = MyCustomAnalyzer()
    
    content_item = {
        "structure": {
            "code_blocks": [
                {
                    "language": "python",
                    "content": "def foo():\n    dangerous_function(user_input)\n",
                    "line_start": 10,
                    "line_end": 12
                }
            ]
        }
    }
    
    results = analyzer.analyze(content_item)
    
    assert len(results["findings"]) == 1
    assert results["findings"][0]["type"] == "dangerous_function"
    assert results["findings"][0]["severity"] == "HIGH"
    assert results["findings"][0]["location"]["line_start"] == 10
```

## Packaging Plugins

For sharing plugins with others, create a proper Python package:

1. Create a `setup.py` file in your plugin directory:

```python
from setuptools import setup, find_packages

setup(
    name="llmstxt-custom-plugin",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyyaml",
        "semgrep",  # If needed
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="Custom plugin for LLMs.txt Security Analysis Platform",
    keywords="security, analysis, llms.txt",
    url="https://github.com/yourusername/llmstxt-custom-plugin",
)
```

2. Create a README.md file with installation and usage instructions.

3. Install the plugin:

```bash
pip install -e /path/to/plugin
```

## Best Practices

1. **Focus on a specific concern**: Each plugin should focus on a specific type of security issue.
2. **Minimize dependencies**: Keep external dependencies to a minimum.
3. **Handle errors gracefully**: Catch and log exceptions to prevent crashing the pipeline.
4. **Document your plugin**: Include clear documentation on what the plugin detects and how to configure it.
5. **Include tests**: Write comprehensive tests for your plugin.
6. **Consider performance**: Optimize your plugin for performance, especially for large files.
7. **Follow coding standards**: Adhere to the project's [Code Style Guide](code_style.md).

## Examples

See the `plugins/` directory for examples of existing plugins:

- `plugins/semgrep/`: Integration with Semgrep for static analysis
- `plugins/trufflehog/`: Integration with TruffleHog for secrets detection
- `plugins/yara/`: Integration with YARA for pattern matching

## Conclusion

By developing plugins for the LLMs.txt Security Analysis Platform, you can extend its capabilities to detect new types of security issues or integrate with additional tools. Follow the guidelines in this document to create effective, maintainable plugins that enhance the platform's security analysis capabilities.