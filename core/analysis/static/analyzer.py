import os
import time
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from .semgrep_runner import SemgrepRunner, SemgrepRunnerError
from .rule_manager import RuleManager, RuleManagerError
from .finding_manager import FindingManager, FindingManagerError
from core.utils.db_utils import get_code_blocks_by_content_id
from core.database.schema import CodeBlock

# Configure logger
logger = logging.getLogger(__name__)

class StaticAnalyzerError(Exception):
    pass

class StaticAnalyzer:
    def __init__(self, rules_path: str = "rules/semgrep", config: Optional[Dict[str, Any]] = None):
        logger.info(f"StaticAnalyzer initialized with rules_path: {rules_path}")
        self.rules_path = rules_path
        self.rule_manager = RuleManager(rules_path)
        # Add Semgrep registry rulesets for gitleaks and OWASP Top Ten
        self.registry_rulesets = ["p/gitleaks", "p/owasp-top-ten"]
        
        # Default configuration
        self.config = config or {}
        self.max_content_size = self.config.get("max_content_size", 1024 * 1024)  # 1MB default
        self.max_content_lines = self.config.get("max_content_lines", 10000)  # 10K lines default
        
        # Initialize semgrep runner with configuration
        self.semgrep_runner = SemgrepRunner(
            rules_path,
            config={"max_content_size": self.max_content_size},
            registry_rulesets=self.registry_rulesets
        )
        self.finding_manager = FindingManager()
        self.db_session: Optional[Session] = None

    def set_db_session(self, session: Session):
        """Set the database session for code block analysis."""
        self.db_session = session

    def analyze_code_blocks(self, processed_content_id: int) -> List[Dict[str, Any]]:
        """Analyze all code blocks for a given processed content."""
        if not self.db_session:
            raise StaticAnalyzerError("Database session not set. Call set_db_session() first.")

        code_blocks = get_code_blocks_by_content_id(self.db_session, processed_content_id)
        if not code_blocks:
            logger.warning(f"No code blocks found for content ID: {processed_content_id}")
            return []

        all_findings = []
        for block in code_blocks:
            findings = self.analyze_single_block(block)
            all_findings.extend(findings)

        return all_findings

    def analyze_single_block(self, block: CodeBlock) -> List[Dict[str, Any]]:
        """Analyze a single code block and adjust finding locations."""
        if not block.content or not block.language:
            logger.warning(f"Skipping code block {block.id}: Missing content or language")
            return []

        # Run semgrep on the block
        findings = self.semgrep_runner.run(content=block.content, language=block.language)

        # Adjust line numbers and add block reference
        adjusted_findings = []
        for finding in findings:
            # Only adjust if we have line_start information
            if block.line_start is not None:
                line_offset = block.line_start - 1  # Convert to 0-based for calculation
                if finding.get("start", {}).get("line"):
                    finding["start"]["line"] += line_offset
                if finding.get("end", {}).get("line"):
                    finding["end"]["line"] += line_offset

            # Add code block reference
            finding["code_block_id"] = block.id
            adjusted_findings.append(finding)

        return adjusted_findings

    def analyze(self, data: Any, language: Optional[str] = None) -> List[Dict[str, Any]]:
        import time
        import psutil
        
        start_time = time.time()
        memory_before = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
        
        try:
            findings: List[Dict[str, Any]] = []

            if isinstance(data, dict):
                content_to_scan = data.get('content')
                item_id = data.get('id', 'unknown')

                if not content_to_scan:
                    raise StaticAnalyzerError(
                        f"Input dictionary for analysis is missing 'content' key. ID: {item_id}"
                    )

                # Parse markdown and extract code blocks
                from core.content.markdown_parser import MarkdownParser
                parser = MarkdownParser()
                parsed_data = parser.parse(content_to_scan)
                code_blocks = parsed_data.get('code_blocks', [])

                # Log code block analysis
                logger.info(f"Found {len(code_blocks)} code blocks to analyze")

                # Analyze each code block with its specific language
                for i, block in enumerate(code_blocks, 1):
                    code_content = block.get('code')
                    block_language = block.get('language')
                    line_start = block.get('line_start', 1)
                    
                    if code_content and block_language:
                        logger.info(f"Analyzing code block {i}/{len(code_blocks)} with language {block_language}")
                        
                        # Skip analysis for unsupported languages
                        if block_language.lower() not in [lang.lower() for lang in self.semgrep_runner.SUPPORTED_LANGUAGES]:
                            logger.info(f"Skipping unsupported language: {block_language}")
                            continue

                        # Run semgrep on the block
                        block_findings = self.semgrep_runner.run(content=code_content, language=block_language)
                        
                        # Adjust line numbers to match original document
                        for finding in block_findings:
                            if finding.get('start', {}).get('line'):
                                finding['start']['line'] += line_start - 1
                            if finding.get('end', {}).get('line'):
                                finding['end']['line'] += line_start - 1
                            
                            # Add code block context to finding
                            finding['code_block'] = {
                                'index': i,
                                'language': block_language,
                                'line_start': line_start,
                                'line_end': block.get('line_end')
                            }
                        
                        findings.extend(block_findings)
                
                # Log memory usage and content size for monitoring
                content_size = len(content_to_scan) if content_to_scan else 0
                content_lines = content_to_scan.count('\n') + 1 if content_to_scan else 0
                print(f"Item {item_id}: Content size: {content_size} bytes, {content_lines} lines")

                # Check content size before processing
                if content_to_scan and content_size > self.max_content_size:
                    print(f"WARNING: Item {item_id}: Content size ({content_size} bytes) exceeds maximum allowed size ({self.max_content_size} bytes)")
                    return [self._create_size_limit_finding(item_id, content_size, self.max_content_size)]
                
                # Check line count before processing
                if content_to_scan and content_lines > self.max_content_lines:
                    print(f"WARNING: Item {item_id}: Content line count ({content_lines}) exceeds maximum allowed lines ({self.max_content_lines})")
                    return [self._create_line_limit_finding(item_id, content_lines, self.max_content_lines)]

            elif isinstance(data, str):  # Assumed to be a file path
                target_path = data
                logger.info(f"Static analyzing file: {target_path} (lang hint: {language})")
                # The 'language' parameter here is a hint for Semgrep.
                # If None, Semgrep will attempt to auto-detect the language.
                
                # Log semgrep execution start
                logger.info(f"Starting semgrep execution for file: {target_path}")
                
                # Check for semgrep processes before execution
                self._log_semgrep_processes("before")
                
                # Run semgrep
                findings = self.semgrep_runner.run(target_path=target_path, language=language)
                
                # Check for semgrep processes after execution
                self._log_semgrep_processes("after")
                
                logger.info(f"Completed semgrep execution for file: {target_path}")
            else:
                raise StaticAnalyzerError(f"Unsupported data type for analysis: {type(data)}. Must be dict or str.")

            for finding in findings:
                self.finding_manager.store_finding(finding)
            
            # Log execution metrics
            execution_time = time.time() - start_time
            memory_after = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
            memory_used = memory_after - memory_before
            
            print(f"Static analysis completed in {execution_time:.2f}s, memory delta: {memory_used:.2f}MB")
            
            # As per original logic, return all findings managed by finding_manager.
            # If only findings from *this* run were needed, one would return the `findings` list directly.
            return self.finding_manager.get_all_findings()
        except (SemgrepRunnerError, RuleManagerError, FindingManagerError) as e:
            # Log more specific error to help diagnose
            error_type = type(e).__name__
            logger.error(f"Error during static analysis pipeline ({error_type}): {e}")
            
            # Log execution metrics even on error
            execution_time = time.time() - start_time
            memory_after = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
            memory_used = memory_after - memory_before
            
            logger.error(f"Static analysis failed after {execution_time:.2f}s, memory delta: {memory_used:.2f}MB")
            
            # Create an error finding instead of raising exception
            item_id = data.get('id', 'unknown') if isinstance(data, dict) else 'unknown'
            error_finding = {
                "rule_id": f"static_analysis_error_{error_type.lower()}",
                "path": item_id,
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 1},
                "extra": {"message": f"Static analysis error: {str(e)}", "execution_time": execution_time},
                "category": "Error",
                "priority": "Medium"
            }
            self.finding_manager.store_finding(error_finding)
            return [error_finding]
        except Exception as e:  # Catch any other unexpected errors
            error_type = type(e).__name__
            # Log the stack trace for better debugging
            logger.exception(f"Unexpected error during static analysis ({error_type}): {e}")
            
            # Log execution metrics even on error
            execution_time = time.time() - start_time
            memory_after = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
            memory_used = memory_after - memory_before
            
            logger.error(f"Static analysis failed after {execution_time:.2f}s, memory delta: {memory_used:.2f}MB")
            
            # Create an error finding instead of raising exception
            item_id = data.get('id', 'unknown') if isinstance(data, dict) else 'unknown'
            error_finding = {
                "rule_id": "static_analysis_unexpected_error",
                "path": item_id,
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 1},
                "extra": {"message": f"Unexpected error: {str(e)}", "execution_time": execution_time},
                "category": "Error",
                "priority": "High"
            }
            self.finding_manager.store_finding(error_finding)
            return [error_finding]

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.semgrep_runner.list_rules()

    def clear_findings(self):
        self.finding_manager.clear()
        
    def _log_semgrep_processes(self, stage):
        """Log information about running semgrep processes"""
        try:
            import psutil
            
            # Find all semgrep processes
            semgrep_processes = []
            total_memory_percent = 0.0
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'cpu_percent']):
                try:
                    # Check if this is a semgrep process
                    if proc.info['name'] == 'semgrep' or (
                        proc.info['cmdline'] and
                        any('semgrep' in cmd for cmd in proc.info['cmdline'] if cmd)
                    ):
                        # Get detailed process info
                        proc_info = {
                            'pid': proc.info['pid'],
                            'memory_percent': proc.info['memory_percent'],
                            'cpu_percent': proc.info['cpu_percent'] or proc.cpu_percent(interval=0.1),
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                            'create_time': proc.create_time(),
                            'running_time': time.time() - proc.create_time()
                        }
                        semgrep_processes.append(proc_info)
                        total_memory_percent += proc.info['memory_percent']
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            if semgrep_processes:
                logger.warning(
                    f"Semgrep processes {stage} execution: count={len(semgrep_processes)}, "
                    f"memory={total_memory_percent:.2f}%, "
                    f"pids={[p['pid'] for p in semgrep_processes]}"
                )
                
                # Log detailed info about long-running processes
                long_running = [p for p in semgrep_processes if p['running_time'] > 60]  # > 1 minute
                if long_running:
                    for proc in long_running:
                        logger.warning(
                            f"Long-running semgrep process: pid={proc['pid']}, "
                            f"running_time={proc['running_time']:.1f}s, "
                            f"memory={proc['memory_percent']:.2f}%, "
                            f"cmd={proc['cmdline']}"
                        )
            else:
                logger.info(f"No semgrep processes found {stage} execution")
                
        except ImportError:
            logger.debug("psutil not installed, cannot check semgrep processes")
        except Exception as e:
            logger.error(f"Error checking semgrep processes: {e}")
            
    def _is_complex_generic_content(self, content: str) -> bool:
        """
        Determine if generic content is too complex for semgrep analysis
        """
        # Check content size
        if len(content) > 100000:  # 100KB
            return True
            
        # Check line count
        if content.count('\n') > 1000:  # More than 1000 lines
            return True
            
        # Check for complex patterns that might cause semgrep to hang
        complex_patterns = [
            r'```',  # Code blocks in markdown
            r'\[\[',  # Wiki-style links
            r'\{\{',  # Template syntax
        ]
        
        for pattern in complex_patterns:
            if content.count(pattern) > 10:  # More than 10 occurrences
                return True
                
        return False
        
    def _analyze_complex_generic_content(self, content: str, item_id: str) -> List[Dict[str, Any]]:
        """
        Alternative analysis for complex generic content that would timeout with semgrep
        """
        import re
        
        findings = []
        
        # Simple pattern matching for common issues in markdown/generic content
        patterns = [
            (r'(https?:\/\/[^\s]+)', "url_found", "URL detected in content", "Info"),
            (r'(password|api[_\s]?key|secret|token)[=:]\s*[\'"][^\'"]+[\'"]', "potential_secret", "Potential hardcoded secret", "High"),
            (r'(eval\(|exec\(|system\()', "dangerous_function", "Potentially dangerous function call", "High"),
            (r'(DROP\s+TABLE|DELETE\s+FROM|UPDATE\s+.*\s+SET)', "sql_command", "SQL command detected", "Medium"),
            (r'<script[^>]*>.*?<\/script>', "script_tag", "Script tag detected", "Medium"),
        ]
        
        for pattern, rule_id, message, priority in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                start_pos = match.start()
                end_pos = match.end()
                
                # Calculate line and column numbers
                line_start = content[:start_pos].count('\n') + 1
                line_end = content[:end_pos].count('\n') + 1
                
                # Calculate column positions
                if line_start == line_end:
                    col_start = start_pos - content[:start_pos].rfind('\n') if '\n' in content[:start_pos] else start_pos + 1
                    col_end = end_pos - content[:end_pos].rfind('\n') if '\n' in content[:end_pos] else end_pos + 1
                else:
                    col_start = start_pos - content[:start_pos].rfind('\n') if '\n' in content[:start_pos] else start_pos + 1
                    col_end = end_pos - content[:end_pos].rfind('\n') if '\n' in content[:end_pos] else end_pos + 1
                
                findings.append({
                    "rule_id": rule_id,
                    "path": f"item-{item_id}",
                    "start": {"line": line_start, "col": col_start},
                    "end": {"line": line_end, "col": col_end},
                    "extra": {
                        "message": message,
                        "matched_text": match.group(0)[:100] + ("..." if len(match.group(0)) > 100 else "")
                    },
                    "category": "ContentScan",
                    "priority": priority
                })
        
        # Add a note that alternative analysis was used
        findings.append({
            "rule_id": "alternative_analysis_used",
            "path": f"item-{item_id}",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 1},
            "extra": {"message": "Complex generic content analyzed with alternative method instead of semgrep"},
            "category": "Info",
            "priority": "Low"
        })
        
        return findings
        
    def _create_size_limit_finding(self, item_id: str, content_size: int, max_size: int) -> Dict[str, Any]:
        """Create a finding for content that exceeds size limits"""
        return {
            "rule_id": "content_size_limit_exceeded",
            "path": f"item-{item_id}",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 1},
            "extra": {
                "message": f"Content size ({content_size} bytes) exceeds maximum allowed size ({max_size} bytes)",
                "content_size": content_size,
                "max_size": max_size
            },
            "category": "Performance",
            "priority": "Medium"
        }
        
    def _create_line_limit_finding(self, item_id: str, line_count: int, max_lines: int) -> Dict[str, Any]:
        """Create a finding for content that exceeds line count limits"""
        return {
            "rule_id": "content_line_limit_exceeded",
            "path": f"item-{item_id}",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 1},
            "extra": {
                "message": f"Content line count ({line_count}) exceeds maximum allowed lines ({max_lines})",
                "line_count": line_count,
                "max_lines": max_lines
            },
            "category": "Performance",
            "priority": "Medium"
        }
