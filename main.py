import argparse
import sys
import logging
import json
import yaml  # For loading YAML configuration
import os
from datetime import datetime
from core.pipeline import Pipeline
from core.sandbox.llm_environment import LLMEnvironment
from core.monitoring.health_check import HealthChecker
from core.monitoring.metrics_collector import MetricsCollector
from core.monitoring.alert_manager import AlertManager


def setup_logging(config):
    """Set up logging based on configuration."""
    log_level = config.get("logging", {}).get("level", "INFO")
    log_file = config.get("logging", {}).get("file")

    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Configure logging
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    if log_file:
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logging.basicConfig(
            level=numeric_level,
            format=log_format,
            filename=log_file,
            filemode="a",
            force=True,
        )
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(numeric_level)
        console.setFormatter(logging.Formatter(log_format))
        logging.getLogger("").addHandler(console)
    else:
        logging.basicConfig(level=numeric_level, format=log_format, force=True)

    logging.info(f"Logging initialized at level {log_level}")


def load_config(config_path):
    """Load configuration from file."""
    config = {}

    try:
        # Determine file type from extension
        _, ext = os.path.splitext(config_path)

        with open(config_path, "r") as f:
            if ext.lower() == ".yaml" or ext.lower() == ".yml":
                config = yaml.safe_load(f)
            elif ext.lower() == ".json":
                config = json.load(f)
            else:
                logging.warning(
                    f"Unknown config file type: {ext}. Attempting to parse as YAML."
                )
                config = yaml.safe_load(f)

        logging.info(f"Loaded configuration from {config_path}")
    except FileNotFoundError:
        logging.error(
            f"Configuration file not found: {config_path}. Using default empty config."
        )
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        logging.error(
            f"Error parsing configuration file {config_path}: {e}. Using default empty config."
        )

    # Ensure db path is set, even if config loading fails or is partial
    if "db" not in config or "path" not in config.get("db", {}):
        logging.warning(
            "Database path not found in config, using default: researchdb/llms_metadata.db"
        )
        config.setdefault("db", {}).setdefault("path", "researchdb/llms_metadata.db")

    return config


def setup_monitoring(config):
    """Set up monitoring components based on configuration."""
    monitoring_config = config.get("monitoring", {})

    if not monitoring_config.get("enabled", False):
        logging.info("Monitoring is disabled in configuration")
        return None, None, None

    logging.info("Setting up monitoring components")

    # Initialize health checker
    health_check_interval = monitoring_config.get("health_check_interval", 60)
    health_checker = HealthChecker(
        {
            "db_path": config.get("db", {}).get("path"),
            "check_interval": health_check_interval,
        }
    )

    # Initialize metrics collector
    metrics_interval = monitoring_config.get("metrics_collection_interval", 300)
    retention_days = monitoring_config.get("retention_days", 30)
    metrics_collector = MetricsCollector(
        {
            "db_path": config.get("db", {}).get("path"),
            "collection_interval": metrics_interval,
            "retention_days": retention_days,
        }
    )

    # Initialize alert manager
    alert_interval = monitoring_config.get("alert_check_interval", 600)
    alert_manager = AlertManager(
        {
            "db_path": config.get("db", {}).get("path"),
            "check_interval": alert_interval,
            "alert_rules": monitoring_config.get("alert_rules", []),
            "notification_channels": monitoring_config.get("notification_channels", []),
        }
    )

    # Start monitoring threads
    health_checker.start_monitoring(health_check_interval)
    metrics_collector.start_collection(metrics_interval)
    alert_manager.start_monitoring(alert_interval)

    logging.info("Monitoring components started")

    return health_checker, metrics_collector, alert_manager


def setup_sandbox(config):
    """Set up sandbox environment based on configuration."""
    sandbox_config = config.get("sandbox", {})

    logging.info(
        f"Setting up sandbox environment in {sandbox_config.get('mode', 'mock')} mode"
    )

    # Initialize sandbox environment
    sandbox = LLMEnvironment(sandbox_config)

    return sandbox


def main():
    parser = argparse.ArgumentParser(
        description="LLMs.txt Security Analysis Platform CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["analysis", "reporting", "sandbox", "monitor", "all"],
        default="all",
        help="Operational mode: analysis, reporting, sandbox, monitor, or all",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/scoring_config.yaml",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--env",
        choices=["dev", "test", "prod"],
        default=None,
        help="Deployment environment (uses env-specific config if available)",
    )
    parser.add_argument(
        "--query", type=str, default=None, help="Custom content query (optional)"
    )
    parser.add_argument(
        "--sandbox-prompt",
        type=str,
        default=None,
        help="Prompt to test in sandbox mode",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=None,
        help="Monitoring interval in seconds (for monitor mode)",
    )

    args = parser.parse_args()

    # Load config from file
    config = load_config(args.config)

    # If environment is specified, try to load environment-specific config
    if args.env:
        env_config_path = f"config/env_{args.env}.json"
        if os.path.exists(env_config_path):
            env_config = load_config(env_config_path)
            # Merge environment config with base config
            for key, value in env_config.items():
                if (
                    isinstance(value, dict)
                    and key in config
                    and isinstance(config[key], dict)
                ):
                    config[key].update(value)
                else:
                    config[key] = value
            logging.info(f"Loaded environment configuration for {args.env}")
        else:
            logging.warning(f"Environment configuration not found: {env_config_path}")

    # Setup logging based on config
    setup_logging(config)

    # Initialize components
    pipeline = Pipeline(config=config)
    report_data = None  # Initialize report_data

    # Setup monitoring if needed
    health_checker, metrics_collector, alert_manager = None, None, None
    if args.mode in ["monitor", "all"]:
        health_checker, metrics_collector, alert_manager = setup_monitoring(config)

    # Setup sandbox if needed
    sandbox = None
    if args.mode in ["sandbox", "all"]:
        sandbox = setup_sandbox(config)

    # Execute based on mode
    if args.mode == "analysis":
        logging.info("Running analysis mode...")
        report_data = pipeline.run(content_query=args.query)
        if isinstance(report_data, dict) and report_data.get("status") == "failed":
            logging.error(f"Analysis pipeline failed: {report_data.get('error')}")
        else:
            logging.info("Analysis complete.")
        logging.info(f"Performance metrics: {pipeline.get_performance_metrics()}")

    elif args.mode == "reporting":
        logging.info("Running reporting mode...")
        # This mode might need to load data from a previous run or database
        # For now, it demonstrates calling the report generator directly
        # This part might need significant rework depending on how analysis results are persisted
        logging.warning(
            "Reporting mode currently generates a placeholder report. For full report, run with --mode all."
        )
        report_data = pipeline.reporting_manager.generate_report(
            [], [], [], []
        )  # Placeholder
        logging.info("Report generation process finished.")

    elif args.mode == "sandbox":
        logging.info("Running sandbox mode...")
        if not args.sandbox_prompt:
            logging.error("Sandbox mode requires a prompt (use --sandbox-prompt)")
            sys.exit(1)

        if not sandbox:
            sandbox = setup_sandbox(config)

        # Process prompt in sandbox
        response = sandbox.process_prompt(args.sandbox_prompt)

        print("\n--- SANDBOX RESPONSE ---")
        print(f"Mode: {response['mode']}")
        print(f"Response ID: {response['id']}")
        print(f"Elapsed Time: {response['elapsed_time']:.4f}s")
        print("\nResponse:")
        print(response["response"])

    elif args.mode == "monitor":
        logging.info("Running monitor mode...")

        if not all([health_checker, metrics_collector, alert_manager]):
            health_checker, metrics_collector, alert_manager = setup_monitoring(config)

        # Run initial health check and metrics collection
        health_report = health_checker.get_health_report()
        metrics = metrics_collector.collect_metrics()
        alerts = alert_manager.check_alerts()

        print("\n--- SYSTEM HEALTH REPORT ---")
        print(f"Overall Status: {health_report['overall_status'].upper()}")
        print("Component Status:")
        for component, data in health_report["components"].items():
            print(f"  {component}: {data['status'].upper()}")

        print("\n--- SYSTEM METRICS ---")
        if "performance" in metrics["metrics"]:
            perf = metrics["metrics"]["performance"]
            print("Performance Metrics:")
            for key, value in perf.items():
                if isinstance(value, (int, float)):
                    print(f"  {key}: {value}")

        print("\n--- ACTIVE ALERTS ---")
        active_alerts = alert_manager.get_active_alerts()
        if active_alerts:
            for alert in active_alerts:
                print(
                    f"  {alert['alert_name']} ({alert['severity'].upper()}): {alert['message']}"
                )
        else:
            print("  No active alerts")

        # If interval specified, keep monitoring
        if args.monitor_interval:
            print(
                f"\nMonitoring will continue in the background every {args.monitor_interval} seconds."
            )
            print("Press Ctrl+C to stop.")

            try:
                # Keep the main thread alive
                import time

                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nMonitoring stopped.")

    elif args.mode == "all":
        logging.info("Running full pipeline with all components...")

        # Setup monitoring if not already done
        if not all([health_checker, metrics_collector, alert_manager]):
            health_checker, metrics_collector, alert_manager = setup_monitoring(config)

        # Setup sandbox if not already done
        if not sandbox:
            sandbox = setup_sandbox(config)

        # Run the pipeline
        report_data = pipeline.run(content_query=args.query)
        if isinstance(report_data, dict) and report_data.get("status") == "failed":
            logging.error(f"Full pipeline execution failed: {report_data.get('error')}")
        else:
            logging.info("Pipeline complete.")
        logging.info(f"Performance metrics: {pipeline.get_performance_metrics()}")

    else:
        parser.print_help()
        sys.exit(1)

    # Optionally, print or save the report
    if report_data and args.mode in ["analysis", "reporting", "all"]:
        if isinstance(report_data, dict) and report_data.get("status") == "failed":
            # Handle failed pipeline output
            print("\n--- PIPELINE EXECUTION FAILED ---")
            print(f"Error: {report_data.get('error')}")
            print("Performance metrics at failure:")
            for key, value in report_data.get("performance", {}).items():
                print(f"  {key}: {value:.4f}s")
        else:
            # Handle successful report output (actual report or placeholder)
            print("\n--- PIPELINE EXECUTION SUCCEEDED ---")
            print(
                "Report output/path:", report_data
            )  # This could be a file path or report object

            # If metrics collector is available, record pipeline execution
            if metrics_collector:
                metrics_collector.collect_metrics()


if __name__ == "__main__":
    main()
