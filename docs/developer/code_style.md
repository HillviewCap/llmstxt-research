# LLMs.txt Security Analysis Platform: Code Style Guide

This document outlines the coding standards and style guidelines for the LLMs.txt Security Analysis Platform. Following these guidelines ensures consistency, readability, and maintainability across the codebase.

## Python Style Guidelines

The project follows [PEP 8](https://pep8.org/) with some specific adaptations.

### Formatting

- **Indentation**: Use 4 spaces for indentation, not tabs.
- **Line Length**: Maximum line length is 100 characters.
- **Line Breaks**: Break lines before binary operators.
- **Blank Lines**: 
  - 2 blank lines before top-level function and class definitions
  - 1 blank line before method definitions inside a class
  - Use blank lines to separate logical sections

### Naming Conventions

- **Packages**: Short, lowercase names, no underscores: `core`, `utils`
- **Modules**: Short, lowercase names with underscores: `markdown_parser.py`
- **Classes**: CamelCase: `DatabaseConnector`, `ContentRetriever`
- **Functions/Methods**: lowercase with underscores: `retrieve_content()`, `process_item()`
- **Variables**: lowercase with underscores: `content_items`, `analysis_results`
- **Constants**: UPPERCASE with underscores: `MAX_BATCH_SIZE`, `DEFAULT_CONFIG_PATH`
- **Private Methods/Variables**: Prefix with underscore: `_analyze_item()`, `_performance`

### Imports

- Organize imports in the following order:
  1. Standard library imports
  2. Related third-party imports
  3. Local application/library specific imports
- Use absolute imports for clarity
- Separate import groups with a blank line

Example:

```python
import time
import logging
import concurrent.futures

import yaml
import semgrep
import yara

from core.database.connector import DatabaseConnector
from core.content.retriever import ContentRetriever
```

### Docstrings

- Use triple double-quotes (`"""`) for docstrings
- Follow [Google style docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings)
- Include:
  - Brief description
  - Args (if applicable)
  - Returns (if applicable)
  - Raises (if applicable)
  - Examples (if helpful)

Example:

```python
def process_content(content, options=None):
    """
    Process raw content for analysis.
    
    Args:
        content (str): Raw content text to process
        options (dict, optional): Processing options. Defaults to None.
        
    Returns:
        dict: Processed content with extracted components
        
    Raises:
        ValueError: If content is empty or None
    """
    # Implementation
```

### Comments

- Use comments sparingly, focusing on *why* not *what*
- Keep comments up-to-date with code changes
- Use TODO comments for temporary code or future improvements: `# TODO: Implement caching`

### Error Handling

- Use specific exception types rather than generic exceptions
- Handle exceptions at the appropriate level
- Log exceptions with context information
- Use context managers (`with` statements) when appropriate

Example:

```python
try:
    content_items = self.content_retriever.retrieve(query=content_query)
except ConnectionError as e:
    self.logger.error(f"Database connection failed: {e}", exc_info=True)
    raise
except ValueError as e:
    self.logger.error(f"Invalid query parameter: {e}", exc_info=True)
    raise
```

## Project Structure

### Directory Organization

- Keep related files together in modules
- Use `__init__.py` files to define public APIs
- Separate core functionality from utilities
- Place tests in a parallel structure to the code they test

### File Organization

- One class per file (with exceptions for closely related classes)
- Group related functions in modules
- Keep files focused on a single responsibility
- Limit file size (aim for <500 lines)

## Testing Guidelines

### Test Structure

- Use pytest for testing
- Name test files with `test_` prefix
- Name test functions with `test_` prefix
- Group tests by functionality
- Use fixtures for common setup

Example:

```python
def test_content_retrieval_with_valid_query():
    """Test content retrieval with a valid query."""
    retriever = ContentRetriever(MockDatabase())
    content_items = retriever.retrieve(query="domain:example.com")
    assert len(content_items) > 0
    assert content_items[0]["domain"] == "example.com"
```

### Test Coverage

- Aim for high test coverage (>80%)
- Prioritize testing critical paths and edge cases
- Include both unit and integration tests
- Test error handling and edge cases

## Logging

- Use the standard `logging` module
- Configure appropriate log levels
- Include context in log messages
- Use structured logging when appropriate

Example:

```python
self.logger.info(f"Retrieved {len(content_items)} content items.")
self.logger.error(f"Content processing failed: {e}", exc_info=True)
```

## Configuration

- Use YAML for configuration files
- Provide sensible defaults
- Validate configuration values
- Document configuration options

## Security Practices

- Never hardcode credentials
- Validate all inputs
- Use safe APIs when available
- Follow the principle of least privilege
- Sanitize output to prevent injection

## Performance Considerations

- Profile code to identify bottlenecks
- Use appropriate data structures
- Consider memory usage for large datasets
- Use generators for large data processing
- Implement caching where appropriate

## Documentation

- Document all public APIs
- Keep documentation up-to-date with code changes
- Include examples in documentation
- Document assumptions and limitations

## Version Control

### Commit Messages

- Write clear, concise commit messages
- Use the imperative mood ("Add feature" not "Added feature")
- Reference issue numbers when applicable
- Separate subject from body with a blank line

Example:

```
Add markdown link analyzer

- Implement link extraction from markdown
- Add domain reputation checking
- Create tests for link analyzer

Fixes #42
```

### Branching

- Use feature branches for development
- Keep branches focused on a single feature or fix
- Regularly merge from main to stay up-to-date
- Delete branches after merging

## Code Review

- Review all code before merging
- Look for:
  - Correctness
  - Security issues
  - Performance concerns
  - Adherence to style guidelines
  - Test coverage
  - Documentation

## Tools

### Linting and Formatting

- Use `flake8` for linting
- Use `black` for code formatting
- Use `isort` for import sorting
- Configure tools to match project style

Example configuration (`.flake8`):

```
[flake8]
max-line-length = 100
exclude = .git,__pycache__,build,dist
```

### Type Checking

- Use type hints where appropriate
- Use `mypy` for static type checking
- Document complex types

Example:

```python
def analyze(self, content: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Analyze content and return findings."""
    # Implementation
```

## Conclusion

Following these guidelines ensures a consistent, maintainable, and high-quality codebase. While the guidelines are comprehensive, the primary goals are readability, maintainability, and correctness. When in doubt, prioritize clarity and simplicity over strict adherence to rules.