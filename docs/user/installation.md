# LLMs.txt Security Analysis Platform: Installation Guide

This guide provides step-by-step instructions for installing and setting up the LLMs.txt Security Analysis Platform.

## Prerequisites

Before installing the platform, ensure you have the following prerequisites:

- **Python**: Version 3.11 or higher
- **UV**: The Python package and project manager ([UV Installation Guide](https://github.com/astral-sh/uv))
- **Git**: For cloning the repository
- **Operating System**: Linux, macOS, or Windows
- **Hardware Requirements**:
  - Minimum 4GB RAM (8GB recommended for large files)
  - 1GB free disk space

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/llmstxt-research.git
cd llmstxt-research
```

### 2. Install Dependencies

Using UV (recommended):

```bash
uv pip install -r requirements.txt
```

Or, if using pyproject.toml:

```bash
uv pip install
```

### 3. Set Up the Database

The platform uses SQLite for data storage. The default database location is `researchdb/llms_metadata.db`.

To initialize or migrate the database:

```bash
python -m core.database.migration
```

### 4. Install External Tools (Optional)

Some analyzers require external tools. These are optional but recommended for full functionality:

#### Semgrep

```bash
uv pip install semgrep
```

#### TruffleHog

```bash
uv pip install trufflehog
```

#### YARA

```bash
# For Linux/macOS
brew install yara  # macOS with Homebrew
apt-get install yara  # Debian/Ubuntu

# For Windows
# Download from https://github.com/VirusTotal/yara/releases
```

## Configuration

### Basic Configuration

The platform uses YAML configuration files located in the `config/` directory:

- `scoring_config.yaml`: Configure risk scoring parameters
- `reporting.yaml`: Configure reporting and alerting options

### Custom Rules

Custom rules can be added to the following directories:

- `rules/semgrep/`: Semgrep rules
- `rules/yara/`: YARA rules
- `rules/patterns/`: Custom pattern rules

## Verification

To verify that the installation was successful, run:

```bash
python main.py --mode analysis --config config/scoring_config.yaml
```

You should see output indicating that the platform is running and analyzing content.

## Troubleshooting

### Common Issues

#### Missing Dependencies

If you encounter errors about missing dependencies, try:

```bash
uv pip install -r requirements.txt --upgrade
```

#### Database Errors

If you encounter database errors, try:

```bash
# Backup existing database (if any)
cp researchdb/llms_metadata.db researchdb/llms_metadata.db.backup

# Reinitialize database
python -m core.database.migration --force
```

#### Permission Issues

If you encounter permission issues:

```bash
# For Linux/macOS
chmod +x main.py
```

### Getting Help

If you continue to experience issues:

1. Check the logs for detailed error messages
2. Consult the [Troubleshooting](troubleshooting.md) guide
3. Open an issue on the project repository

## Next Steps

After installation, you can:

- [Configure the platform](configuration.md) for your specific needs
- [Run your first analysis](running_analysis.md) on LLMs.txt files
- [Learn how to interpret results](interpreting_results.md) from the analysis