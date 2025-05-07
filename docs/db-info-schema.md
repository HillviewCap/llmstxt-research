# LLMs Metadata Database Import

This document describes the process for importing LLM metadata from the JSON format into a SQLite database.

## Overview

The `import_metadata_to_db.py` script provides a way to import the metadata from the `llms_metadata.json` file into a SQLite database. This allows for more efficient querying and analysis of the metadata.

## Database Schema

The SQLite database uses the following schema:

### Tables

1. **domains**

   - `id`: Primary key
   - `domain`: Domain name (unique)
   - `first_added`: When the domain was first added
   - `last_updated`: When the domain was last updated

2. **urls**

   - `id`: Primary key
   - `domain_id`: Foreign key to domains table
   - `url`: URL of the LLM file (unique)
   - `status_code`: HTTP status code
   - `content_hash`: Hash of the content
   - `last_checked_utc`: When the URL was last checked
   - `quality`: Quality rating
   - `title`: Title of the page
   - `summary`: Summary of the content

3. **metadata**

   - `id`: Primary key
   - `url_id`: Foreign key to urls table
   - `key`: Metadata key
   - `value`: Metadata value

4. **url_purpose_ranking**

   - `id`: Primary key
   - `url_id`: Foreign key to urls table
   - `purpose`: Purpose category

5. **url_topic_ranking**

   - `id`: Primary key
   - `url_id`: Foreign key to urls table
   - `topic`: Topic category
   - `score`: Topic score

6. **domain_purpose_ranking**

   - `id`: Primary key
   - `domain_id`: Foreign key to domains table
   - `purpose`: Purpose category

7. **domain_topic_ranking**
   - `id`: Primary key
   - `domain_id`: Foreign key to domains table
   - `topic`: Topic category
   - `score`: Topic score

## Usage

### Basic Usage

To import the metadata into a SQLite database:

```bash
python scripts/import_metadata_to_db.py
```

This will use the default paths:

- JSON file: `./llms_metadata.json`
- Database file: `./data/llms_metadata.db`

### Custom Paths

You can specify custom paths for the JSON file and the database:

```bash
python scripts/import_metadata_to_db.py --json-path /path/to/llms_metadata.json --db-path /path/to/database.db
```

### Logging Level

You can set the logging level to control the verbosity of the output:

```bash
python scripts/import_metadata_to_db.py --log-level DEBUG
```

Available log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

## Integration with Workflow

This import process is designed to be separate from the main workflow (`run_workflow_refactored.py`). You can run it after the workflow has completed to import the latest metadata into the database.

## Example Queries

Once the data is imported into the SQLite database, you can run various queries to analyze the data. Here are some examples:

### Get all domains with high quality ratings

```sql
SELECT d.domain, u.quality
FROM domains d
JOIN urls u ON d.id = u.domain_id
WHERE u.quality = 'High';
```

### Get the top topics for a specific domain

```sql
SELECT dt.topic, dt.score
FROM domains d
JOIN domain_topic_ranking dt ON d.id = dt.domain_id
WHERE d.domain = 'example.com'
ORDER BY dt.score DESC;
```

### Get all URLs with a specific topic

```sql
SELECT u.url, ut.topic, ut.score
FROM urls u
JOIN url_topic_ranking ut ON u.id = ut.url_id
WHERE ut.topic = 'AI/ML'
ORDER BY ut.score DESC;
```

## Maintenance

The database should be updated whenever the JSON file is updated. You can run the import script after each workflow run to ensure the database is up to date.

If you need to rebuild the database from scratch, simply delete the database file and run the import script again.

## Fetching and Storing URL Text Content

The `fetch_and_store_url_text.py` script enriches the database by fetching the raw text content from each URL in the `urls` table and storing it in a dedicated table. This enables downstream analysis, search, and summarization of the actual content referenced by the metadata.

### Overview

- Connects to the SQLite database at `data/llms_metadata.db`
- Fetches all URLs from the `urls` table
- For each URL, downloads the text content using the network utility
- Stores the fetched text and status in a new table, `url_text_content`, associated with the `url_id`
- Handles errors gracefully and logs/report them
- Summarizes the number of URLs processed and any issues

### url_text_content Table Schema

The script creates (or replaces) the `url_text_content` table with the following schema:

- `id`: Primary key (autoincrement)
- `url_id`: Foreign key to `urls` table (unique, one row per URL)
- `text_content`: The fetched text content (may be `NULL` if fetch failed)
- `fetch_status`: Status string (`success` or `error`)
- `error_message`: Error message if fetch failed
- `last_fetched_utc`: Timestamp of the last fetch attempt

### Usage

To fetch and store the text content for all URLs:

```bash
python scripts/fetch_and_store_url_text.py
```

This will process all URLs in the database and populate (or refresh) the `url_text_content` table. The script logs progress and any errors to the console.

### Example Output

```
2025-05-07 03:00:00 INFO Found 1234 URLs in the database.
2025-05-07 03:00:10 INFO Processed 10/1234 URLs...
...
2025-05-07 03:10:00 INFO Done. Processed: 1234, Success: 1200, Failed: 34
2025-05-07 03:10:00 INFO Some failures occurred:
  http://example.com/bad-url: TimeoutError
  ...
```

### Integration Notes

- The script can be run after importing or updating metadata to ensure the text content is up to date.
- The `url_text_content` table is dropped and recreated each run to ensure schema consistency and avoid stale data.
- If you need to re-fetch all content (for example, after updating URLs), simply rerun the script.

