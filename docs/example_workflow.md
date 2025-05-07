# LLMs.txt Security Analysis Platform: Example Workflows

## Example 1: Full Analysis and Reporting

**Goal:** Run the full pipeline to analyze all LLMs.txt files and generate a report.

### Command

```sh
python main.py --mode all --config config/scoring_config.yaml
```

### Expected Output

- Console output showing pipeline progress and performance metrics.
- Report file generated in the output directory (see logs for path).
- Summary of findings, risk scores, and recommendations.

---

## Example 2: Analysis Only

**Goal:** Run only the analysis phase and review findings without generating a full report.

### Command

```sh
python main.py --mode analysis --config config/scoring_config.yaml
```

### Expected Output

- Console output with analysis results for each file.
- No report file generated.

---

## Example 3: Reporting Only

**Goal:** Generate a report from existing analysis results.

### Command

```sh
python main.py --mode reporting --config config/scoring_config.yaml
```

### Expected Output

- Console output indicating report generation.
- Report file created in the output directory.

---

## Example 4: Custom Content Query

**Goal:** Analyze a specific subset of content using a custom query.

### Command

```sh
python main.py --mode analysis --config config/scoring_config.yaml --query "source:external"
```

### Expected Output

- Analysis results for content matching the query.
- Performance metrics for the filtered run.

---

## Notes

- All commands assume you are in the project root directory.
- For more CLI options, run:
  ```sh
  python main.py --help
  ```
- See [User Guide](user_guide.md) for troubleshooting and advanced usage.