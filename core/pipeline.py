"""
Pipeline Orchestrator for LLMs.txt Security Analysis Platform

Integrates: database, content, analysis, scoring, reporting
Implements: workflow orchestration, performance optimization, error handling, recovery
"""

import time
import logging
from core.database.connector import DatabaseConnector
from core.content.retriever import ContentRetriever
from core.content.processor import ContentProcessor
from core.analysis.markdown.analyzer import MarkdownAnalyzer
from core.analysis.patterns.analyzer import PatternAnalyzer
from core.analysis.secrets.analyzer import SecretsAnalyzer
from core.analysis.static.analyzer import StaticAnalyzer
from core.scoring.scoring_model import ScoringModel
from core.scoring.risk_assessor import RiskAssessor
from core.reporting.reporting_manager import ReportingManager

class Pipeline:
    def __init__(self, config=None):
        self.config = config or {}
        self.db = DatabaseConnector(self.config.get("db"))
        self.content_retriever = ContentRetriever(self.db)
        self.content_processor = ContentProcessor()
        self.markdown_analyzer = MarkdownAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.secrets_analyzer = SecretsAnalyzer()
        self.static_analyzer = StaticAnalyzer()
        self.scoring_model = ScoringModel()
        self.risk_assessor = RiskAssessor()
        self.reporting_manager = ReportingManager()
        self.logger = logging.getLogger("Pipeline")
        self.performance = {}

    def run(self, content_query=None):
        """
        Orchestrates the full pipeline:
        1. Retrieve content
        2. Process content
        3. Run all analyzers
        4. Score and assess risk
        5. Generate report
        Returns: report path or object
        """
        try:
            start_time = time.time()
            self.logger.info("Pipeline started.")

            # 1. Retrieve content
            t0 = time.time()
            content_items = self.content_retriever.retrieve(query=content_query)
            self.performance['content_retrieval'] = time.time() - t0
            self.logger.info(f"Retrieved {len(content_items)} content items.")

            # 2. Process content
            t0 = time.time()
            processed_items = [self.content_processor.process(item) for item in content_items]
            self.performance['content_processing'] = time.time() - t0

            # 3. Run analyzers (can be parallelized for performance)
            t0 = time.time()
            analysis_results = []
            for item in processed_items:
                result = {
                    "markdown": self.markdown_analyzer.analyze(item),
                    "patterns": self.pattern_analyzer.analyze(item),
                    "secrets": self.secrets_analyzer.analyze(item),
                    "static": self.static_analyzer.analyze(item),
                }
                analysis_results.append(result)
            self.performance['analysis'] = time.time() - t0

            # 4. Scoring and risk assessment
            t0 = time.time()
            scores = [self.scoring_model.score(result) for result in analysis_results]
            risks = [self.risk_assessor.assess(score) for score in scores]
            self.performance['scoring'] = time.time() - t0

            # 5. Reporting
            t0 = time.time()
            report = self.reporting_manager.generate_report(
                content_items=content_items,
                analysis_results=analysis_results,
                scores=scores,
                risks=risks
            )
            self.performance['reporting'] = time.time() - t0

            total_time = time.time() - start_time
            self.performance['total'] = total_time
            self.logger.info(f"Pipeline completed in {total_time:.2f}s.")

            return report

        except Exception as e:
            self.logger.error(f"Pipeline failed: {e}", exc_info=True)
            # Recovery: Optionally implement checkpointing, retries, or partial results
            raise

    def get_performance_metrics(self):
        return self.performance

    def reset(self):
        """Reset pipeline state if needed."""
        self.__init__(self.config)