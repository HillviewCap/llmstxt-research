# LLMs.txt Security Analysis Platform: Database Schema

This document describes the database schema used by the LLMs.txt Security Analysis Platform for storing metadata, content, analysis results, and security findings.

## Overview

The platform uses SQLite as its default database engine, with a schema designed for efficient querying and analysis of LLMs.txt files and their security characteristics. The database is located at `researchdb/llms_metadata.db` by default.

## Core Tables

### 1. domains

Stores information about domains hosting LLMs.txt files.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `domain` | TEXT | Domain name (unique) |
| `first_added` | TIMESTAMP | When the domain was first added |
| `last_updated` | TIMESTAMP | When the domain was last updated |

```sql
CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    first_added TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 2. urls

Stores information about specific URLs containing LLMs.txt files.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `domain_id` | INTEGER | Foreign key to domains table |
| `url` | TEXT | URL of the LLM file (unique) |
| `status_code` | INTEGER | HTTP status code |
| `content_hash` | TEXT | Hash of the content |
| `last_checked_utc` | TIMESTAMP | When the URL was last checked |
| `quality` | TEXT | Quality rating |
| `title` | TEXT | Title of the page |
| `summary` | TEXT | Summary of the content |

```sql
CREATE TABLE urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    url TEXT UNIQUE NOT NULL,
    status_code INTEGER,
    content_hash TEXT,
    last_checked_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    quality TEXT,
    title TEXT,
    summary TEXT,
    FOREIGN KEY (domain_id) REFERENCES domains(id)
);
```

### 3. metadata

Stores key-value metadata for URLs.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table |
| `key` | TEXT | Metadata key |
| `value` | TEXT | Metadata value |

```sql
CREATE TABLE metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

### 4. url_text_content

Stores the raw text content of URLs.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table (unique) |
| `text_content` | TEXT | The fetched text content |
| `fetch_status` | TEXT | Status string (`success` or `error`) |
| `error_message` | TEXT | Error message if fetch failed |
| `last_fetched_utc` | TIMESTAMP | Timestamp of the last fetch attempt |

```sql
CREATE TABLE url_text_content (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER UNIQUE NOT NULL,
    text_content TEXT,
    fetch_status TEXT NOT NULL,
    error_message TEXT,
    last_fetched_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

## Security Analysis Tables

### 5. security_analysis_results

Stores the results of security analysis runs.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table |
| `analysis_timestamp` | TIMESTAMP | When the analysis was performed |
| `overall_risk_score` | REAL | Aggregated risk score (0-100) |
| `malicious_confidence` | REAL | Confidence level of malicious content detection |
| `analysis_version` | TEXT | Version of analysis tools used |

```sql
CREATE TABLE security_analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    analysis_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    overall_risk_score REAL,
    malicious_confidence REAL,
    analysis_version TEXT,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

### 6. security_findings

Stores individual security findings from analysis.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `analysis_id` | INTEGER | Foreign key to security_analysis_results table |
| `finding_type` | TEXT | Type of security finding |
| `severity` | TEXT | Critical, High, Medium, Low |
| `description` | TEXT | Description of the finding |
| `location` | TEXT | Location in the file |
| `evidence` | TEXT | Evidence supporting the finding |
| `false_positive_likelihood` | REAL | Estimated likelihood of false positive |
| `remediation_suggestion` | TEXT | Suggested action |

```sql
CREATE TABLE security_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    location TEXT,
    evidence TEXT,
    false_positive_likelihood REAL,
    remediation_suggestion TEXT,
    FOREIGN KEY (analysis_id) REFERENCES security_analysis_results(id)
);
```

### 7. code_blocks

Stores extracted code blocks from LLMs.txt files.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table |
| `language` | TEXT | Programming language |
| `content` | TEXT | Code block content |
| `line_start` | INTEGER | Starting line in the original file |
| `line_end` | INTEGER | Ending line in the original file |
| `context` | TEXT | Surrounding content for context |

```sql
CREATE TABLE code_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    language TEXT,
    content TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    context TEXT,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

### 8. analysis_history

Tracks the history of analysis runs for temporal comparison.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table |
| `analysis_timestamp` | TIMESTAMP | When the analysis was performed |
| `changes_detected` | BOOLEAN | Whether changes were detected since last analysis |
| `change_summary` | TEXT | Summary of changes |

```sql
CREATE TABLE analysis_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    analysis_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    changes_detected BOOLEAN,
    change_summary TEXT,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

## Categorization Tables

### 9. url_purpose_ranking

Categorizes URLs by purpose.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table |
| `purpose` | TEXT | Purpose category |

```sql
CREATE TABLE url_purpose_ranking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

### 10. url_topic_ranking

Categorizes URLs by topic with scores.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls table |
| `topic` | TEXT | Topic category |
| `score` | REAL | Topic score |

```sql
CREATE TABLE url_topic_ranking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    topic TEXT NOT NULL,
    score REAL,
    FOREIGN KEY (url_id) REFERENCES urls(id)
);
```

### 11. domain_purpose_ranking

Categorizes domains by purpose.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `domain_id` | INTEGER | Foreign key to domains table |
| `purpose` | TEXT | Purpose category |

```sql
CREATE TABLE domain_purpose_ranking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id)
);
```

### 12. domain_topic_ranking

Categorizes domains by topic with scores.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `domain_id` | INTEGER | Foreign key to domains table |
| `topic` | TEXT | Topic category |
| `score` | REAL | Topic score |

```sql
CREATE TABLE domain_topic_ranking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    topic TEXT NOT NULL,
    score REAL,
    FOREIGN KEY (domain_id) REFERENCES domains(id)
);
```

## Indexes

The following indexes are created to optimize query performance:

```sql
CREATE INDEX idx_urls_domain_id ON urls(domain_id);
CREATE INDEX idx_metadata_url_id ON metadata(url_id);
CREATE INDEX idx_url_text_content_url_id ON url_text_content(url_id);
CREATE INDEX idx_security_analysis_results_url_id ON security_analysis_results(url_id);
CREATE INDEX idx_security_findings_analysis_id ON security_findings(analysis_id);
CREATE INDEX idx_code_blocks_url_id ON code_blocks(url_id);
CREATE INDEX idx_analysis_history_url_id ON analysis_history(url_id);
CREATE INDEX idx_url_purpose_ranking_url_id ON url_purpose_ranking(url_id);
CREATE INDEX idx_url_topic_ranking_url_id ON url_topic_ranking(url_id);
CREATE INDEX idx_domain_purpose_ranking_domain_id ON domain_purpose_ranking(domain_id);
CREATE INDEX idx_domain_topic_ranking_domain_id ON domain_topic_ranking(domain_id);
```

## Database Maintenance

### Backup

It's recommended to regularly back up the database file:

```bash
cp researchdb/llms_metadata.db researchdb/llms_metadata.db.backup
```

### Optimization

Periodically optimize the database to improve performance:

```sql
VACUUM;
ANALYZE;
```

### Migration

Database migrations are handled by the `core/database/migration.py` module, which ensures schema compatibility across versions.

## Example Queries

### Get all high-risk URLs

```sql
SELECT u.url, s.overall_risk_score
FROM urls u
JOIN security_analysis_results s ON u.id = s.url_id
WHERE s.overall_risk_score > 75
ORDER BY s.overall_risk_score DESC;
```

### Get all findings for a specific URL

```sql
SELECT f.finding_type, f.severity, f.description
FROM security_findings f
JOIN security_analysis_results s ON f.analysis_id = s.id
JOIN urls u ON s.url_id = u.id
WHERE u.url = 'https://example.com/llms.txt'
ORDER BY f.severity;
```

### Get code blocks with potential vulnerabilities

```sql
SELECT c.language, c.content, c.line_start, c.line_end
FROM code_blocks c
JOIN urls u ON c.url_id = u.id
JOIN security_analysis_results s ON u.id = s.url_id
JOIN security_findings f ON s.id = f.analysis_id
WHERE f.severity IN ('Critical', 'High')
AND f.location BETWEEN c.line_start AND c.line_end;