# LLMs.txt Security Analysis Platform: Data Flow

This document describes the flow of data through the LLMs.txt Security Analysis Platform, from content retrieval to report generation.

## Overview

The platform processes data through a series of stages, with each stage transforming or enriching the data before passing it to the next stage. The diagram below illustrates the high-level data flow:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│              │     │              │     │              │     │              │     │              │
│   Database   │────▶│    Content   │────▶│   Analysis   │────▶│    Scoring   │────▶│   Reporting  │
│    Layer     │     │    Layer     │     │    Layer     │     │    Layer     │     │    Layer     │
│              │     │              │     │              │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
        ▲                                        │                    │                    │
        │                                        │                    │                    │
        └────────────────────────────────────────┴────────────────────┴────────────────────┘
                                      Feedback and Storage Loop
```

## Detailed Data Flow

### 1. Database to Content Layer

**Input:**
- Query parameters (optional)
- Database connection details

**Process:**
1. Database connector establishes connection to SQLite database
2. Content retriever executes query to fetch content items
3. Content items are loaded into memory

**Output:**
- List of content items (raw)
- Metadata for each content item

**Data Structure:**
```python
content_items = [
    {
        "id": "unique_id",
        "url": "https://example.com/llms.txt",
        "domain": "example.com",
        "content": "Raw content text...",
        "metadata": {
            "last_updated": "2025-05-01T12:00:00Z",
            "content_hash": "abc123...",
            # Additional metadata
        }
    },
    # More content items...
]
```

### 2. Content Layer to Analysis Layer

**Input:**
- Raw content items from previous stage

**Process:**
1. Content processor parses each content item
2. Markdown parser extracts structural elements
3. Code blocks are identified and language is detected
4. Links and references are extracted
5. Content is normalized for analysis

**Output:**
- Processed content items with extracted components

**Data Structure:**
```python
processed_items = [
    {
        "id": "unique_id",
        "url": "https://example.com/llms.txt",
        "content": "Raw content text...",
        "structure": {
            "headers": [{"level": 1, "text": "Header", "line": 1}, ...],
            "paragraphs": [{"text": "Paragraph text", "line": 3}, ...],
            "code_blocks": [
                {
                    "language": "python",
                    "content": "print('Hello')",
                    "line_start": 5,
                    "line_end": 7
                },
                # More code blocks...
            ],
            "links": [
                {"text": "Link text", "url": "https://example.com", "line": 10},
                # More links...
            ]
        },
        "metadata": {
            # Metadata from previous stage
        }
    },
    # More processed items...
]
```

### 3. Analysis Layer to Scoring Layer

**Input:**
- Processed content items from previous stage

**Process:**
1. Multiple analyzers process content in parallel:
   - Static analyzer examines code blocks
   - Pattern analyzer applies YARA rules
   - Secrets analyzer detects credentials
   - Markdown analyzer validates structure
2. Each analyzer produces findings
3. Findings are aggregated

**Output:**
- Analysis results for each content item

**Data Structure:**
```python
analysis_results = [
    {
        "id": "unique_id",
        "url": "https://example.com/llms.txt",
        "static": {
            "findings": [
                {
                    "rule_id": "RULE-001",
                    "severity": "HIGH",
                    "description": "Potential code injection",
                    "location": {"line": 5, "code": "print('Hello')"},
                    "confidence": 0.85
                },
                # More static findings...
            ]
        },
        "patterns": {
            "findings": [
                # Pattern findings...
            ]
        },
        "secrets": {
            "findings": [
                # Secrets findings...
            ]
        },
        "markdown": {
            "findings": [
                # Markdown findings...
            ]
        }
    },
    # More analysis results...
]
```

### 4. Scoring Layer to Reporting Layer

**Input:**
- Analysis results from previous stage

**Process:**
1. Scoring model calculates scores for each finding
2. Risk assessor evaluates overall risk
3. Findings are classified by category and severity

**Output:**
- Scores and risk assessments

**Data Structure:**
```python
scores = [
    {
        "id": "unique_id",
        "url": "https://example.com/llms.txt",
        "overall_score": 0.75,
        "dimension_scores": {
            "impact": 0.8,
            "likelihood": 0.7,
            "exposure": 0.6
        },
        "finding_scores": [
            {
                "finding_id": "FINDING-001",
                "score": 0.85,
                "confidence": 0.9
            },
            # More finding scores...
        ]
    },
    # More scores...
]

risks = [
    {
        "id": "unique_id",
        "url": "https://example.com/llms.txt",
        "risk_level": "HIGH",
        "risk_factors": [
            "Contains high-severity code injection",
            "Multiple credential exposures",
            # More risk factors...
        ],
        "recommendations": [
            "Remove eval() usage",
            "Redact credentials",
            # More recommendations...
        ]
    },
    # More risk assessments...
]
```

### 5. Reporting Layer to Output

**Input:**
- Content items, analysis results, scores, and risks from previous stages

**Process:**
1. Reporting manager coordinates report generation
2. Report generator creates formatted reports
3. Dashboard generates visualizations
4. Alert system sends notifications for high-severity findings

**Output:**
- Reports in various formats (HTML, PDF, JSON)
- Dashboard visualizations
- Alerts via configured channels

**Data Structure:**
```python
report = {
    "id": "REPORT-001",
    "timestamp": "2025-05-07T17:30:00Z",
    "summary": {
        "total_items": 10,
        "total_findings": 25,
        "risk_distribution": {
            "CRITICAL": 2,
            "HIGH": 5,
            "MEDIUM": 10,
            "LOW": 8
        }
    },
    "items": [
        {
            "id": "unique_id",
            "url": "https://example.com/llms.txt",
            "risk_level": "HIGH",
            "findings": [
                # Detailed findings...
            ],
            "recommendations": [
                # Recommendations...
            ]
        },
        # More items...
    ],
    "metadata": {
        "platform_version": "1.0.0",
        "config_hash": "def456...",
        # Additional metadata
    }
}
```

## Feedback Loop

The platform implements a feedback loop where analysis results, scores, and reports are stored back in the database for:

1. Historical tracking and trend analysis
2. Comparison of changes over time
3. Continuous improvement of detection rules
4. False positive management

This loop ensures that the platform learns from previous analyses and improves over time.

## Data Persistence

Data is persisted at several points in the workflow:

1. **Raw Content**: Stored in the `url_text_content` table
2. **Analysis Results**: Stored in the `security_analysis_results` and `security_findings` tables
3. **Reports**: Stored as files and referenced in the database

## Performance Considerations

The data flow is designed with performance in mind:

1. **Parallel Processing**: Analysis is performed in parallel using thread pools
2. **Incremental Analysis**: Only changed content is fully analyzed
3. **Caching**: Intermediate results are cached when possible
4. **Batch Processing**: Content is processed in configurable batch sizes