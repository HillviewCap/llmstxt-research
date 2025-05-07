# LLMs.txt Security Analysis Platform: User Guide

## Introduction

This guide provides step-by-step instructions for installing, configuring, and operating the LLMs.txt Security Analysis Platform.

---

## Installation

1. **Clone the repository:**
   ```sh
   git clone <your-repo-url>
   cd llmstxt-research
   ```

2. **Install dependencies using uv:**
   ```sh
   uv pip install -r requirements.txt
   ```

3. **Set up the database:**
   - The default SQLite database is located at `researchdb/llms_metadata.db`.
   - To migrate or initialize, use the provided migration scripts in `core/database/migration.py`.

---

## Configuration

- **Edit configuration files in `config/`** to customize scoring, reporting, and analysis rules.
- **Rule files** for analyzers are in `rules/`.
- **Plugins** can be added in the `plugins/` directory.

---

## Running the Platform

### Command-Line Interface

Run the platform using the CLI entry point:

```sh
python main.py [OPTIONS]
```

#### Options

- `--mode [analysis|reporting|all]` : Select operational mode
- `--config <path>` : Specify a custom configuration file
- `--help` : Show usage information

### Example

```sh
python main.py --mode analysis --config config/scoring_config.yaml
```

---

## Workflow Overview

1. **Content is retrieved** from the database or external sources.
2. **Content is processed** and analyzed by multiple analyzers.
3. **Results are scored** and risk is assessed.
4. **Reports are generated** and stored in the output directory.

---

## Troubleshooting

- **Logs** are written to the console and log files for debugging.
- **Errors** are handled gracefully; see logs for details.
- **For support**, consult the documentation or open an issue.

---

## Additional Resources

- [System Architecture](architecture.md)
- [API Documentation](api.md)
- [Example Workflows](example_workflow.md)