# LLMs.txt Security Analysis Platform: Component Descriptions

This document provides detailed descriptions of all major components in the LLMs.txt Security Analysis Platform.

## Core Components

### 1. Database Layer

**Location:** `core/database/`

#### Database Connector (`connector.py`)
- Manages connections to the SQLite database
- Provides query interface for other components
- Handles connection pooling and transaction management

#### Schema Manager (`schema.py`)
- Defines the database schema
- Includes tables for domains, URLs, metadata, and security findings
- Manages relationships between tables

#### Migration Manager (`migration.py`)
- Handles database schema migrations
- Ensures backward compatibility
- Manages version tracking

### 2. Content Layer

**Location:** `core/content/`

#### Content Retriever (`retriever.py`)
- Fetches content from the database or external sources
- Supports filtering and querying
- Handles pagination for large datasets

#### Content Processor (`processor.py`)
- Parses and normalizes content
- Extracts code blocks, links, and other elements
- Prepares content for analysis

#### Markdown Parser (`markdown_parser.py`)
- Specialized parser for LLMs.txt markdown format
- Extracts structural elements
- Identifies language-specific code blocks

#### Storage Manager (`storage.py`)
- Manages content storage
- Handles caching and optimization
- Supports versioning of content

### 3. Analysis Layer

**Location:** `core/analysis/`

#### Static Analysis (`static/`)
- **Analyzer (`analyzer.py`)**: Coordinates static code analysis
- **Finding Manager (`finding_manager.py`)**: Manages static analysis findings
- **Rule Manager (`rule_manager.py`)**: Manages static analysis rules
- **Semgrep Runner (`semgrep_runner.py`)**: Interfaces with Semgrep for code analysis

#### Pattern Analysis (`patterns/`)
- **Analyzer (`analyzer.py`)**: Coordinates pattern-based analysis
- **Behavior Analyzer (`behavior_analyzer.py`)**: Analyzes behavioral patterns
- **Rule Library (`rule_library.py`)**: Manages pattern rules
- **YARA Runner (`yara_runner.py`)**: Interfaces with YARA for pattern matching

#### Secrets Analysis (`secrets/`)
- **Analyzer (`analyzer.py`)**: Coordinates secrets detection
- **Finding Manager (`finding_manager.py`)**: Manages secrets findings
- **Pattern Library (`pattern_library.py`)**: Manages secrets patterns
- **Sensitive Detector (`sensitive_detector.py`)**: Detects sensitive information
- **TruffleHog Runner (`trufflehog_runner.py`)**: Interfaces with TruffleHog

#### Markdown Analysis (`markdown/`)
- **Analyzer (`analyzer.py`)**: Coordinates markdown analysis
- **Content Scanner (`content_scanner.py`)**: Scans markdown content
- **Link Analyzer (`link_analyzer.py`)**: Analyzes links in markdown
- **Structural Validator (`structural_validator.py`)**: Validates markdown structure

### 4. Scoring Layer

**Location:** `core/scoring/`

#### Scoring Model (`scoring_model.py`)
- Implements multi-dimensional scoring algorithm
- Assigns weights to different finding types
- Calculates aggregate risk scores

#### Risk Assessor (`risk_assessor.py`)
- Assesses risk based on scores
- Categorizes findings by severity
- Provides risk context

#### Classification (`classification.py`)
- Classifies findings into categories
- Implements taxonomy of security issues
- Supports custom classification rules

#### Context Analyzer (`context_analyzer.py`)
- Analyzes context of findings
- Adjusts scores based on domain reputation
- Considers content purpose and category

### 5. Reporting Layer

**Location:** `core/reporting/`

#### Reporting Manager (`reporting_manager.py`)
- Coordinates report generation
- Manages report templates
- Handles report storage and retrieval

#### Report Generator (`report_generator.py`)
- Generates detailed security reports
- Formats findings for readability
- Supports multiple output formats

#### Dashboard (`dashboard.py`)
- Provides visualization of findings
- Supports interactive filtering
- Displays trends and statistics

#### Alert System (`alert_system.py`)
- Manages security alerts
- Supports multiple notification channels
- Implements severity-based alerting

## Integration Components

### Pipeline Orchestrator

**Location:** `core/pipeline.py`

- Integrates all components into a cohesive workflow
- Manages execution flow and error handling
- Collects performance metrics
- Implements recovery mechanisms

### Plugin System

**Location:** `plugins/`

- Supports custom analyzers via plugins
- Provides integration points for third-party tools
- Includes adapters for Semgrep, TruffleHog, and YARA

### Rule Management

**Location:** `rules/`

- Stores rule definitions for analyzers
- Organizes rules by category and tool
- Supports custom rule development

## Utility Components

**Location:** `core/utils/`

- Database utilities
- Logging and monitoring
- Performance optimization
- Error handling

## Configuration System

**Location:** `config/`

- YAML-based configuration
- Scoring configuration
- Reporting configuration
- Plugin configuration