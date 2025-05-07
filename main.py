import argparse
import sys
import logging
from core.pipeline import Pipeline

def main():
    parser = argparse.ArgumentParser(
        description="LLMs.txt Security Analysis Platform CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--mode",
        choices=["analysis", "reporting", "all"],
        default="all",
        help="Operational mode: analysis, reporting, or all"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/scoring_config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--query",
        type=str,
        default=None,
        help="Custom content query (optional)"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Load config (placeholder: extend to parse YAML if needed)
    config = {"db": {"path": "researchdb/llms_metadata.db"}}
    # Optionally, parse YAML config here

    pipeline = Pipeline(config=config)

    if args.mode == "analysis":
        logging.info("Running analysis mode...")
        report = pipeline.run(content_query=args.query)
        print("Analysis complete.")
        print("Performance metrics:", pipeline.get_performance_metrics())
    elif args.mode == "reporting":
        logging.info("Running reporting mode...")
        # In a real implementation, load previous analysis results
        report = pipeline.reporting_manager.generate_report([], [], [], [])
        print("Report generated.")
    elif args.mode == "all":
        logging.info("Running full pipeline (analysis + reporting)...")
        report = pipeline.run(content_query=args.query)
        print("Pipeline complete.")
        print("Performance metrics:", pipeline.get_performance_metrics())
    else:
        parser.print_help()
        sys.exit(1)

    # Optionally, print or save the report
    if report:
        print("Report output:", report)

if __name__ == "__main__":
    main()
