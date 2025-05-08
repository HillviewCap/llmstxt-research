# Documentation Plan: Static Analysis Timeout Fix

This document outlines the plan for creating comprehensive documentation for the static analysis timeout fix.

## I. Create a New Technical Note: `docs/technical_notes/static_analysis_timeout_handling.md`

This document will provide a deep dive into the problem and the implemented solution.

*   **Title:** `Technical Deep Dive: Static Analysis Timeout Resolution and Robustness`
*   **Content Outline:**
    1.  **Introduction:**
        *   Briefly describe the original problem: static analysis (specifically Semgrep) timing out on complex or large "generic" content (like markdown), leading to pipeline thread timeouts.
        *   State the purpose of this document: to explain the issue, the multi-layered solution, and guidelines for the future.
    2.  **Understanding the Timeout Root Causes:**
        *   Initial symptom: `ERROR:Pipeline:Analysis thread timed out after 180 seconds`.
        *   Discuss Semgrep's performance characteristics with certain patterns on large/complex "generic" language inputs.
        *   Explain the need for granular timeouts and robust process termination.
    3.  **The Multi-Layered Solution:** This section will detail the changes across different components.
        *   **A. Pipeline-Level Enhancements ([`core/pipeline.py`](core/pipeline.py)):**
            *   **Dynamic Thread Timeouts:** Detail how `Pipeline._calculate_timeout()` ([`core/pipeline.py:294-341`](core/pipeline.py:294-341)) determines timeouts for analysis threads based on content size, line count, complexity heuristics, and language (especially 'generic'/'markdown').
            *   **Thread Execution with Timeout:** Explain how `Pipeline._execute_with_thread_timeout()` ([`core/pipeline.py:343-441`](core/pipeline.py:343-441)) applies these timeouts.
            *   **Improved Process Termination:** Describe the role of `Pipeline._terminate_child_processes()` ([`core/pipeline.py:443-469`](core/pipeline.py:443-469)) in killing runaway child processes (like Semgrep) upon thread timeout, including logging stack traces.
        *   **B. Static Analyzer Layer Enhancements ([`core/analysis/static/analyzer.py`](core/analysis/static/analyzer.py)):**
            *   **Pre-emptive Content Checks:** Mention the `max_content_size` and `max_content_lines` checks.
            *   **Specialized Handling for Complex Generic Content:** Explain the `_is_complex_generic_content()` heuristic ([`core/analysis/static/analyzer.py:198-221`](core/analysis/static/analyzer.py:198-221)) and the `_analyze_complex_generic_content()` ([`core/analysis/static/analyzer.py:223-281`](core/analysis/static/analyzer.py:223-281)) alternative regex-based analysis path, which bypasses Semgrep for such content.
            *   **Error Handling:** How `SemgrepRunnerError` is caught and translated into a finding.
        *   **C. Semgrep Runner Layer Enhancements ([`core/analysis/static/semgrep_runner.py`](core/analysis/static/semgrep_runner.py)):**
            *   **Internal Semgrep Process Timeout:** The `--timeout` flag passed to Semgrep CLI and its own `_calculate_timeout()` ([`core/analysis/static/semgrep_runner.py:239-249`](core/analysis/static/semgrep_runner.py:239-249)).
            *   **Robust Subprocess Management:** Detail `run_with_process_group_timeout()` ([`core/analysis/static/semgrep_runner.py:251-335`](core/analysis/static/semgrep_runner.py:251-335)) using `os.setsid` and `os.killpg` for reliable termination.
            *   **Optimized Handling for 'Generic' Language:** Using lightweight rulesets (`r2c-ci`) for 'generic' content ([`core/analysis/static/semgrep_runner.py:125-135`](core/analysis/static/semgrep_runner.py:125-135)).
    4.  **How the Components Work Together (Flow Diagram):**
        *   A Mermaid sequence diagram illustrating the interaction from pipeline item reception to Semgrep execution and timeout handling at various levels.
        ```mermaid
        sequenceDiagram
            participant P as Pipeline
            participant SA as StaticAnalyzer
            participant SR as SemgrepRunner
            participant SEM as Semgrep CLI

            P->>P: _calculate_timeout() for thread
            P->>P: _execute_with_thread_timeout(SA.analyze, item)
            activate P
            P->>SA: analyze(item)
            activate SA
            SA->>SA: Check size/line limits
            SA->>SA: _is_complex_generic_content()?
            alt Complex Generic Content
                SA->>SA: _analyze_complex_generic_content() (regex)
                SA-->>P: Return regex findings
            else Not Complex or Other Language
                SA->>SR: run(content, language)
                activate SR
                SR->>SR: Check SR.max_content_size
                SR->>SR: _calculate_timeout() for Semgrep process
                SR->>SR: run_with_process_group_timeout(semgrep_cmd)
                activate SR # Inner activation for process run
                SR->>SEM: Execute semgrep ... --timeout X
                activate SEM
                Note over SEM: Semgrep processing...
                alt Semgrep Finishes/Times out Internally
                    SEM-->>SR: Results or error
                end
                deactivate SEM
                SR-->>SA: Parsed findings or SemgrepRunnerError
                deactivate SR # Inner deactivation
                deactivate SR
                SA-->>P: Findings or error finding
            end
            deactivate SA
            P-->>P: Thread completes or P times out thread
            deactivate P
            alt Pipeline Thread Timeout
                 P->>P: _terminate_child_processes()
                 P->>P: Log error, return error finding
            end
        ```
    5.  **Guidelines for Handling Similar Issues in the Future:**
        *   **Monitoring:** Key log messages to watch.
        *   **Debugging:** Steps to diagnose future timeout issues (checking logs, problematic content, Semgrep rule performance).
        *   **Configuration:** Relevant timeout parameters in configuration files.
        *   **Rule Development:** Performance considerations for new Semgrep rules.
    6.  **Recommendations for Further Improvements:**
        *   More sophisticated complexity analysis.
        *   Adaptive timeout learning.
        *   Resource quotas.
        *   Dedicated queue for very large/complex files.

## II. Update `docs/architecture.md`

*   **Analysis Layer Section:** Add a note about the static analyzer's robustness mechanisms (size limits, complexity checks, alternative analysis for generic content).
*   **Orchestration Section:** Expand on error handling to mention dynamic, content-aware timeouts for analysis threads and robust termination of underlying processes.
*   **Error Handling & Recovery Section:** Add points about "Layered timeout mechanisms" and "Alternative analysis paths for known problematic content types."

## III. Update `docs/system/components.md`

*   **`Semgrep Runner (semgrep_runner.py)` description:** Add details about its robust timeout management, dynamic timeout calculation, process group termination, and specific strategies for 'generic' language content.
*   **`Analyzer (analyzer.py)` (under Static Analysis) description:** Add details about pre-analysis checks (size/line limits), the heuristic for complex 'generic' content, and the alternative regex-based analysis path.
*   **`Pipeline Orchestrator (core/pipeline.py)` description:** Add details about managing parallel analysis threads with dynamically calculated timeouts, handling thread timeouts, logging diagnostics, and terminating runaway child processes.

## IV. Update `docs/developer/testing.md`

*   **New Subsection: `Testing for Timeout Robustness`** (e.g., under "System Tests" or as a new main section):
    *   Emphasize testing with large/complex files (referencing `tests/data/large_complex_markdown.llms.txt`, `tests/data/extremely_large_content.llms.txt`).
    *   Outline how to verify timeout handling: correct identification of problematic analyses, log message checks, triggering of alternative analysis paths, generation of timeout/alternative-analysis findings.
*   **`Common Issues / Debugging Techniques` Section:**
    *   Add a point about debugging analysis timeouts, referencing the new technical note in `docs/technical_notes/`.