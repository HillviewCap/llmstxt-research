"""
Pipeline Orchestrator for LLMs.txt Security Analysis Platform

Integrates: database, content, analysis, scoring, reporting
Implements: workflow orchestration, performance optimization, error handling, recovery
"""

import time
import logging
import threading
import concurrent.futures
import os
import signal
import psutil
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
from core.ml.integration import MLAnalysis

class Pipeline:
    def __init__(self, config=None):
        self.config = config or {}
        self.db = DatabaseConnector(self.config.get("db"))
        self.content_retriever = ContentRetriever(self.db)
        self.content_processor = ContentProcessor(self.db)
        self.markdown_analyzer = MarkdownAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.secrets_analyzer = SecretsAnalyzer()
        
        # Configure static analyzer with performance limits
        static_analyzer_config = {
            "max_content_size": self.config.get("max_content_size", 1024 * 1024),  # 1MB default
            "max_content_lines": self.config.get("max_content_lines", 10000)       # 10K lines default
        }
        self.static_analyzer = StaticAnalyzer(config=static_analyzer_config)
        
        self.scoring_model = ScoringModel()
        self.risk_assessor = RiskAssessor()
        self.reporting_manager = ReportingManager()
        
        # Initialize temporal analysis components
        from core.temporal.integration import TemporalAnalysis
        self.temporal_analyzer = TemporalAnalysis(self.db)
        
        # Initialize ML analysis components
        self.ml_analyzer = MLAnalysis(self.config.get("ml"), self.db)
        
        self.logger = logging.getLogger("Pipeline")
        self.performance = {}
        
        # Track running analysis threads
        self.running_threads = {}

    def run(self, content_query=None):
        """
        Orchestrates the full pipeline:
        1. Retrieve content
        2. Process content
        3. Run all analyzers
        4. Run ML-based analysis
        5. Score and assess risk
        6. Perform temporal analysis
        7. Generate report
        Returns: report path or object
        """
        start_time = time.time()
        self.logger.info("Pipeline started.")
        report = None
        content_items = []
        processed_items = []
        analysis_results = []
        ml_results = []
        scores = []
        risks = []

        try:
            # 1. Retrieve content
            t0 = time.time()
            try:
                content_items = self.content_retriever.retrieve(query=content_query)
                self.performance['content_retrieval'] = time.time() - t0
                self.logger.info(f"Retrieved {len(content_items)} content items.")
                if not content_items:
                    self.logger.warning("No content items retrieved. Pipeline will not proceed further.")
                    return None
            except Exception as e:
                self.logger.error(f"Content retrieval failed: {e}", exc_info=True)
                raise # Re-raise to be caught by the main try-except block

            # 2. Process content
            t0 = time.time()
            try:
                processed_items = [self.content_processor.process_pipeline_item(item) for item in content_items]
                self.performance['content_processing'] = time.time() - t0
                self.logger.info(f"Processed {len(processed_items)} items.")
            except Exception as e:
                self.logger.error(f"Content processing failed: {e}", exc_info=True)
                # Decide if pipeline can continue with partially processed items or should stop
                raise

            # 3. Run analyzers (Parallelized)
            t0 = time.time()
            try:
                analysis_results = [{} for _ in processed_items] # Initialize with empty dicts
                # Max workers can be configured, e.g., based on CPU cores or config file
                # Using a default of 4 workers for demonstration
                max_workers = self.config.get("pipeline_workers", 4)
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_item_idx = {}
                    for i, item in enumerate(processed_items):
                        # Calculate dynamic timeout based on content size and complexity
                        timeout = self._calculate_timeout(item)
                        
                        # Use thread-level timeout wrapper with dynamic timeout
                        future = executor.submit(
                            self._execute_with_thread_timeout,
                            self._analyze_item,
                            (item,),
                            timeout
                        )
                        
                        # Store item ID for better error reporting
                        future.item_id = item.get('id', f'item-{i}')
                        future_to_item_idx[future] = i

                    for future in concurrent.futures.as_completed(future_to_item_idx):
                        item_idx = future_to_item_idx[future]
                        try:
                            result = future.result()
                            # Check if result is an error dictionary from the timeout wrapper
                            if isinstance(result, dict) and "error" in result:
                                item_id = getattr(future, 'item_id', f'item-{item_idx}')
                                self.logger.error(f"Analysis for item {item_id} failed: {result['error']}")
                                analysis_results[item_idx] = result
                            else:
                                analysis_results[item_idx] = result
                        except Exception as exc:
                            item_id = getattr(future, 'item_id', f'item-{item_idx}')
                            self.logger.error(f"Analysis for item {item_id} generated an exception: {exc}", exc_info=True)
                            analysis_results[item_idx] = {"error": str(exc)} # Store error info
                self.performance['analysis'] = time.time() - t0
                self.logger.info("Analysis stage completed.")
            except Exception as e:
                self.logger.error(f"Analysis stage failed: {e}", exc_info=True)
                raise

            # 4. Scoring and risk assessment
            t0 = time.time()
            try:
                # Filter out results that had errors during analysis
                valid_analysis_results = [res for res in analysis_results if "error" not in res]
                if not valid_analysis_results:
                    self.logger.warning("No valid analysis results to score.")
                else:
                    scores = [self.scoring_model.score(result) for result in valid_analysis_results]
                    risks = [self.risk_assessor.assess(score) for score in scores]
                self.performance['scoring'] = time.time() - t0
                self.logger.info("Scoring and risk assessment completed.")
            except Exception as e:
                self.logger.error(f"Scoring and risk assessment failed: {e}", exc_info=True)
                raise

            # 5. ML-based Analysis
            t0 = time.time()
            try:
                # Run ML analysis on content items and findings
                all_findings = []
                for result in analysis_results:
                    # Extract findings from each analyzer's results
                    for analyzer_type, analyzer_result in result.items():
                        if isinstance(analyzer_result, dict) and "findings" in analyzer_result:
                            all_findings.extend(analyzer_result["findings"])
                
                ml_results = self.ml_analyzer.analyze(processed_items, all_findings)
                self.performance['ml_analysis'] = time.time() - t0
                self.logger.info("ML analysis completed.")
            except Exception as e:
                self.logger.error(f"ML analysis failed: {e}", exc_info=True)
                ml_results = {"error": str(e)}
                # Continue with pipeline even if ML analysis fails
            
            # 6. Temporal Analysis
            t0 = time.time()
            try:
                temporal_results = []
                for i, item in enumerate(content_items):
                    if i < len(valid_analysis_results) and i < len(scores) and i < len(risks):
                        # Process content for temporal analysis
                        url = item.get('url', '')
                        content = item.get('raw_content', '')
                        processed_id = item.get('processed_id')
                        
                        # Track version and detect changes
                        temporal_result = self.temporal_analyzer.process_content(url, content, processed_id)
                        
                        # Track analysis result for historical analysis
                        if i < len(scores):
                            analysis_result = valid_analysis_results[i]
                            self.temporal_analyzer.track_analysis_result(url, analysis_result)
                        
                        temporal_results.append(temporal_result)
                
                self.performance['temporal_analysis'] = time.time() - t0
                self.logger.info("Temporal analysis completed.")
            except Exception as e:
                self.logger.error(f"Temporal analysis failed: {e}", exc_info=True)
                temporal_results = []
                # Continue with reporting even if temporal analysis fails
            
            # 7. Reporting
            t0 = time.time()
            try:
                # First process the findings
                all_findings = []
                for result in analysis_results:
                    # Extract findings from each analyzer's results
                    for analyzer_type, analyzer_result in result.items():
                        if isinstance(analyzer_result, dict) and "findings" in analyzer_result:
                            all_findings.extend(analyzer_result["findings"])
                
                # Process findings and temporal results
                self.reporting_manager.process_findings(all_findings)
                self.reporting_manager.process_temporal_results(temporal_results)
                
                # Generate the HTML report
                report = self.reporting_manager.generate_html_report()
                self.performance['reporting'] = time.time() - t0
                self.logger.info("Reporting completed.")
            except Exception as e:
                self.logger.error(f"Reporting failed: {e}", exc_info=True)
                raise

            total_time = time.time() - start_time
            self.performance['total'] = total_time
            self.logger.info(f"Pipeline completed in {total_time:.2f}s.")
            return report

        except Exception as e:
            self.logger.error(f"Pipeline execution failed catastrophically: {e}", exc_info=True)
            # Recovery: Optionally implement checkpointing, retries, or partial results
            # For now, we ensure performance metrics are available up to the point of failure
            total_time = time.time() - start_time
            self.performance['total_until_failure'] = total_time
            self.logger.info(f"Pipeline ran for {total_time:.2f}s before critical failure.")
            # Potentially return partial data or a specific error report object
            return {"error": str(e), "status": "failed", "performance": self.performance}

    def _analyze_item(self, item):
        """Helper method to analyze a single item, called by the thread pool."""
        # This method can have its own try-except for finer-grained error handling per analyzer
        markdown_res, patterns_res, secrets_res, static_res = {}, {}, {}, {}
        try:
            markdown_res = self.markdown_analyzer.analyze(item)
        except Exception as e:
            self.logger.error(f"Markdown analysis for item failed: {e}", exc_info=True)
            markdown_res = {"error": str(e)}
        try:
            patterns_res = self.pattern_analyzer.analyze(item)
        except Exception as e:
            self.logger.error(f"Pattern analysis for item failed: {e}", exc_info=True)
            patterns_res = {"error": str(e)}
        try:
            secrets_res = self.secrets_analyzer.analyze(item)
        except Exception as e:
            self.logger.error(f"Secrets analysis for item failed: {e}", exc_info=True)
            secrets_res = {"error": str(e)}
        try:
            static_res = self.static_analyzer.analyze(item)
        except Exception as e:
            self.logger.error(f"Static analysis for item failed: {e}", exc_info=True)
            static_res = {"error": str(e)}
            
        return {
            "markdown": markdown_res,
            "patterns": patterns_res,
            "secrets": secrets_res,
            "static": static_res,
        }

    def get_performance_metrics(self):
        return self.performance

    def reset(self):
        """Reset pipeline state if needed."""
        self.__init__(self.config)
        
    def _calculate_timeout(self, item):
        """
        Calculate appropriate timeout based on content size and complexity
        
        Args:
            item: The content item to analyze
            
        Returns:
            Timeout in seconds
        """
        # Base timeout
        base_timeout = 60
        
        # Get content
        content = item.get('content', '')
        if not content:
            return base_timeout
            
        # Calculate size factor (1 second per 10KB, up to 60 additional seconds)
        content_size = len(content)
        size_factor = min(content_size / 10240, 60)
        
        # Calculate complexity factor based on line count and special patterns
        line_count = content.count('\n') + 1
        line_factor = min(line_count / 100, 30)  # Up to 30 additional seconds
        
        # Check for complex patterns
        complexity_factor = 0
        complex_patterns = ['```', '{{', '[[', '<script', 'function(', 'def ', 'class ']
        for pattern in complex_patterns:
            pattern_count = content.count(pattern)
            complexity_factor += min(pattern_count, 10)  # Up to 10 seconds per pattern type
            
        # Get language and adjust timeout for generic/markdown content
        language = item.get('language', '').lower()
        language_factor = 30 if language in ['generic', 'markdown', 'md'] else 0
        
        # Calculate total timeout
        total_timeout = base_timeout + size_factor + line_factor + complexity_factor + language_factor
        
        # Cap at reasonable maximum
        max_timeout = 300  # 5 minutes
        timeout = min(total_timeout, max_timeout)
        
        item_id = item.get('id', 'unknown')
        self.logger.info(f"Calculated timeout for item {item_id}: {timeout:.1f}s (size: {content_size/1024:.1f}KB, lines: {line_count})")
        
        return timeout
    
    def _execute_with_thread_timeout(self, func, args_tuple, timeout_seconds):
        """
        Executes a function 'func' with 'args_tuple' in a separate thread
        with a specified timeout.
        Returns the function's result or an error dictionary if timeout occurs.
        
        Args:
            func: The function to execute
            args_tuple: Tuple of arguments to pass to the function
            timeout_seconds: Maximum execution time in seconds
            
        Returns:
            The function result or an error dictionary if timeout occurs
        """
        result_container = [None]  # Using a list to pass result by reference
        error_container = [None]   # Using a list to pass error by reference
        completed_event = threading.Event()
        thread_id = threading.get_ident()
        
        # Get item ID for better logging
        item = args_tuple[0] if args_tuple else None
        item_id = item.get('id', 'unknown') if isinstance(item, dict) else 'unknown'
        
        # Track memory usage before execution
        memory_before = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
        start_time = time.time()
        
        def target_wrapper():
            try:
                # Set thread name for easier debugging
                threading.current_thread().name = f"Analysis-{item_id}"
                result_container[0] = func(*args_tuple)
            except Exception as e:
                # Capture any exception from the target function
                error_container[0] = e
                self.logger.error(f"Error in analysis thread for item {item_id}: {e}", exc_info=True)
            finally:
                completed_event.set()
        
        worker_thread = threading.Thread(target=target_wrapper)
        worker_thread.daemon = True  # Allow main program to exit even if thread is running
        
        # Store thread for potential cleanup
        self.running_threads[thread_id] = {
            'thread': worker_thread,
            'item_id': item_id,
            'start_time': start_time
        }
        
        worker_thread.start()
        
        # Wait for completion with timeout
        completed = completed_event.wait(timeout=timeout_seconds)
        
        # Calculate execution metrics
        execution_time = time.time() - start_time
        memory_after = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
        memory_delta = memory_after - memory_before
        
        # Clean up thread tracking
        if thread_id in self.running_threads:
            del self.running_threads[thread_id]
        
        if completed:
            self.logger.info(f"Analysis for item {item_id} completed in {execution_time:.2f}s (memory: {memory_delta:.2f}MB)")
            
            if error_container[0] is not None:
                # Return an error dictionary if the function raised an exception
                error_msg = f"Analysis failed: {str(error_container[0])}"
                self.logger.error(f"Analysis error for item {item_id}: {error_msg}")
                return {"error": error_msg, "execution_time": execution_time, "memory_delta": memory_delta}
            
            return result_container[0]  # Return the actual result
        else:
            # Timeout occurred - log detailed information
            self.logger.error(f"Analysis thread timed out after {timeout_seconds} seconds for item {item_id}")
            
            # Try to get thread stack trace for debugging
            try:
                import traceback
                import sys
                frame = sys._current_frames().get(worker_thread.ident)
                if frame:
                    stack_trace = ''.join(traceback.format_stack(frame))
                    self.logger.error(f"Thread stack trace at timeout for item {item_id}:\n{stack_trace}")
            except Exception as e:
                self.logger.error(f"Failed to get thread stack trace: {e}")
            
            # Attempt to terminate any child processes that might be running
            try:
                self._terminate_child_processes()
            except Exception as e:
                self.logger.error(f"Error terminating child processes: {e}")
            
            return {
                "error": f"Analysis thread timed out after {timeout_seconds} seconds for item {item_id}",
                "execution_time": execution_time,
                "memory_delta": memory_delta
            }
    
    def _terminate_child_processes(self):
        """
        Attempt to find and terminate any child processes that might be causing hangs
        """
        current_process = psutil.Process()
        
        # Get all child processes
        children = current_process.children(recursive=True)
        
        for child in children:
            try:
                # Check if it's a semgrep process
                if 'semgrep' in child.name().lower() or 'python' in child.name().lower():
                    self.logger.warning(f"Terminating potentially hung child process: {child.pid} ({child.name()})")
                    
                    # Try graceful termination first
                    child.terminate()
                    
                    # Wait briefly for termination
                    gone, still_alive = psutil.wait_procs([child], timeout=2)
                    
                    # If still alive, force kill
                    if still_alive:
                        self.logger.warning(f"Force killing process {child.pid} that didn't terminate gracefully")
                        child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                self.logger.warning(f"Error terminating process: {e}")