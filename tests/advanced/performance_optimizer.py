"""
Performance Optimizer for Advanced Testing Framework

This module provides tools for optimizing the performance of the LLMs.txt Security
Analysis Platform, including profiling, bottleneck detection, and optimization
recommendations.
"""

import os
import time
import json
import logging
import cProfile
import pstats
import io
import tracemalloc
from typing import Dict, Any, List, Optional, Union, Tuple, Callable
from datetime import datetime

from core.pipeline import Pipeline

logger = logging.getLogger(__name__)

class PerformanceOptimizer:
    """
    Optimizes the performance of the platform.
    
    This class provides methods to profile the platform's performance, detect
    bottlenecks, and provide optimization recommendations.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the performance optimizer with the given configuration.
        
        Args:
            config: Configuration dictionary with settings for performance optimization.
                   Supported keys:
                   - output_dir: Directory to save optimization results
                   - pipeline_config: Configuration for the pipeline
                   - profiling_enabled: Whether to enable profiling
                   - memory_tracking_enabled: Whether to enable memory tracking
                   - optimization_targets: List of optimization targets
        """
        self.config = config or {}
        self.output_dir = self.config.get("output_dir", "tests/advanced/results")
        self.pipeline_config = self.config.get("pipeline_config", {})
        self.profiling_enabled = self.config.get("profiling_enabled", True)
        self.memory_tracking_enabled = self.config.get("memory_tracking_enabled", True)
        self.optimization_targets = self.config.get("optimization_targets", [
            "time", "memory", "database", "file_io"
        ])
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize pipeline
        self.pipeline = Pipeline(config=self.pipeline_config)
        
        logger.info(f"Initialized performance optimizer with {len(self.optimization_targets)} optimization targets")
    
    def profile_pipeline(self, content_query: Optional[str] = None) -> Dict[str, Any]:
        """
        Profile the pipeline's performance.
        
        Args:
            content_query: Optional content query to pass to the pipeline
            
        Returns:
            Dictionary with profiling results
        """
        logger.info("Profiling pipeline performance")
        
        # Initialize results
        results = {
            "timestamp": datetime.now().isoformat(),
            "profiling_enabled": self.profiling_enabled,
            "memory_tracking_enabled": self.memory_tracking_enabled,
            "optimization_targets": self.optimization_targets,
            "metrics": {},
            "bottlenecks": [],
            "recommendations": []
        }
        
        # Run time profiling
        if "time" in self.optimization_targets:
            time_profile = self._profile_time(content_query)
            results["metrics"]["time"] = time_profile
            
            # Detect time bottlenecks
            time_bottlenecks = self._detect_time_bottlenecks(time_profile)
            results["bottlenecks"].extend(time_bottlenecks)
            
            # Generate time optimization recommendations
            time_recommendations = self._generate_time_recommendations(time_bottlenecks)
            results["recommendations"].extend(time_recommendations)
        
        # Run memory profiling
        if "memory" in self.optimization_targets and self.memory_tracking_enabled:
            memory_profile = self._profile_memory(content_query)
            results["metrics"]["memory"] = memory_profile
            
            # Detect memory bottlenecks
            memory_bottlenecks = self._detect_memory_bottlenecks(memory_profile)
            results["bottlenecks"].extend(memory_bottlenecks)
            
            # Generate memory optimization recommendations
            memory_recommendations = self._generate_memory_recommendations(memory_bottlenecks)
            results["recommendations"].extend(memory_recommendations)
        
        # Save results
        self._save_results(results)
        
        logger.info(f"Profiling complete: {len(results['bottlenecks'])} bottlenecks identified")
        logger.info(f"Generated {len(results['recommendations'])} optimization recommendations")
        
        return results
    
    def optimize_pipeline(self, optimizations: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Apply optimizations to the pipeline.
        
        Args:
            optimizations: List of optimization IDs to apply
            
        Returns:
            Dictionary with optimization results
        """
        logger.info(f"Applying {len(optimizations) if optimizations else 'all'} optimizations")
        
        # Initialize results
        results = {
            "timestamp": datetime.now().isoformat(),
            "optimizations_applied": [],
            "before_metrics": {},
            "after_metrics": {},
            "improvement": {}
        }
        
        # Profile before optimization
        before_profile = self.profile_pipeline()
        results["before_metrics"] = before_profile["metrics"]
        
        # Apply optimizations
        if optimizations is None:
            # Apply all recommended optimizations
            optimizations = [rec["id"] for rec in before_profile["recommendations"]]
        
        for opt_id in optimizations:
            # Find the recommendation
            recommendation = next((rec for rec in before_profile["recommendations"] if rec["id"] == opt_id), None)
            
            if recommendation:
                # Apply the optimization
                success = self._apply_optimization(recommendation)
                
                if success:
                    results["optimizations_applied"].append({
                        "id": opt_id,
                        "description": recommendation["description"],
                        "target": recommendation["target"]
                    })
        
        # Profile after optimization
        after_profile = self.profile_pipeline()
        results["after_metrics"] = after_profile["metrics"]
        
        # Calculate improvement
        results["improvement"] = self._calculate_improvement(results["before_metrics"], results["after_metrics"])
        
        # Save results
        self._save_optimization_results(results)
        
        logger.info(f"Applied {len(results['optimizations_applied'])} optimizations")
        
        return results
    
    def _profile_time(self, content_query: Optional[str] = None) -> Dict[str, Any]:
        """
        Profile the pipeline's execution time.
        
        Args:
            content_query: Optional content query to pass to the pipeline
            
        Returns:
            Dictionary with time profiling results
        """
        logger.info("Profiling execution time")
        
        # Initialize results
        results = {
            "total_time": 0,
            "component_times": {},
            "function_times": {},
            "hotspots": []
        }
        
        # Run with cProfile if enabled
        if self.profiling_enabled:
            # Create profiler
            profiler = cProfile.Profile()
            
            # Start profiling
            profiler.enable()
            
            # Run pipeline
            start_time = time.time()
            self.pipeline.run(content_query=content_query)
            end_time = time.time()
            
            # Stop profiling
            profiler.disable()
            
            # Get total time
            results["total_time"] = end_time - start_time
            
            # Process profiling results
            s = io.StringIO()
            ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
            ps.print_stats(50)  # Print top 50 functions
            
            # Parse profiling output
            profile_text = s.getvalue()
            
            # Extract function times
            for line in profile_text.split('\n'):
                if line.strip() and not line.startswith('ncalls') and not line.startswith('Ordered by'):
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        try:
                            # Extract function name and time
                            func_name = ' '.join(parts[5:])
                            cum_time = float(parts[3])
                            
                            # Add to function times
                            results["function_times"][func_name] = cum_time
                            
                            # Check if it's a hotspot
                            if cum_time > results["total_time"] * 0.05:  # More than 5% of total time
                                results["hotspots"].append({
                                    "function": func_name,
                                    "time": cum_time,
                                    "percentage": (cum_time / results["total_time"]) * 100
                                })
                        except (ValueError, IndexError):
                            pass
        else:
            # Run pipeline without profiling
            start_time = time.time()
            self.pipeline.run(content_query=content_query)
            end_time = time.time()
            
            # Get total time
            results["total_time"] = end_time - start_time
            
            # Get component times from pipeline
            results["component_times"] = self.pipeline.get_performance_metrics()
        
        logger.info(f"Time profiling complete: {results['total_time']:.2f}s total execution time")
        
        return results
    
    def _profile_memory(self, content_query: Optional[str] = None) -> Dict[str, Any]:
        """
        Profile the pipeline's memory usage.
        
        Args:
            content_query: Optional content query to pass to the pipeline
            
        Returns:
            Dictionary with memory profiling results
        """
        logger.info("Profiling memory usage")
        
        # Initialize results
        results = {
            "peak_memory": 0,
            "memory_by_type": {},
            "memory_leaks": [],
            "large_allocations": []
        }
        
        if self.memory_tracking_enabled:
            # Start memory tracking
            tracemalloc.start()
            
            # Run pipeline
            self.pipeline.run(content_query=content_query)
            
            # Get memory snapshot
            snapshot = tracemalloc.take_snapshot()
            
            # Stop memory tracking
            tracemalloc.stop()
            
            # Get peak memory
            results["peak_memory"] = tracemalloc.get_traced_memory()[1]
            
            # Group by file and line
            stats = snapshot.statistics('lineno')
            
            # Process memory statistics
            for stat in stats[:50]:  # Top 50 allocations
                # Extract file and line
                file_path = stat.traceback[0].filename
                line = stat.traceback[0].lineno
                
                # Extract type from file path
                file_name = os.path.basename(file_path)
                module_name = os.path.splitext(file_name)[0]
                
                # Add to memory by type
                if module_name not in results["memory_by_type"]:
                    results["memory_by_type"][module_name] = 0
                results["memory_by_type"][module_name] += stat.size
                
                # Check if it's a large allocation
                if stat.size > 1024 * 1024:  # More than 1 MB
                    results["large_allocations"].append({
                        "file": file_path,
                        "line": line,
                        "size": stat.size,
                        "count": stat.count
                    })
        
        logger.info(f"Memory profiling complete: {results['peak_memory'] / (1024 * 1024):.2f} MB peak memory usage")
        
        return results
    
    def _detect_time_bottlenecks(self, time_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect time bottlenecks from time profiling results.
        
        Args:
            time_profile: Time profiling results
            
        Returns:
            List of bottleneck dictionaries
        """
        bottlenecks = []
        
        # Check hotspots
        for hotspot in time_profile.get("hotspots", []):
            bottlenecks.append({
                "type": "time",
                "subtype": "hotspot",
                "function": hotspot["function"],
                "time": hotspot["time"],
                "percentage": hotspot["percentage"],
                "severity": "high" if hotspot["percentage"] > 20 else "medium"
            })
        
        # Check component times
        for component, time_value in time_profile.get("component_times", {}).items():
            if time_value > time_profile["total_time"] * 0.2:  # More than 20% of total time
                bottlenecks.append({
                    "type": "time",
                    "subtype": "component",
                    "component": component,
                    "time": time_value,
                    "percentage": (time_value / time_profile["total_time"]) * 100,
                    "severity": "high" if time_value > time_profile["total_time"] * 0.4 else "medium"
                })
        
        return bottlenecks
    
    def _detect_memory_bottlenecks(self, memory_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect memory bottlenecks from memory profiling results.
        
        Args:
            memory_profile: Memory profiling results
            
        Returns:
            List of bottleneck dictionaries
        """
        bottlenecks = []
        
        # Check large allocations
        for allocation in memory_profile.get("large_allocations", []):
            bottlenecks.append({
                "type": "memory",
                "subtype": "large_allocation",
                "file": allocation["file"],
                "line": allocation["line"],
                "size": allocation["size"],
                "count": allocation["count"],
                "severity": "high" if allocation["size"] > 10 * 1024 * 1024 else "medium"  # More than 10 MB
            })
        
        # Check memory by type
        for module, size in memory_profile.get("memory_by_type", {}).items():
            if size > memory_profile["peak_memory"] * 0.2:  # More than 20% of peak memory
                bottlenecks.append({
                    "type": "memory",
                    "subtype": "module",
                    "module": module,
                    "size": size,
                    "percentage": (size / memory_profile["peak_memory"]) * 100,
                    "severity": "high" if size > memory_profile["peak_memory"] * 0.4 else "medium"
                })
        
        return bottlenecks
    
    def _generate_time_recommendations(self, bottlenecks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate time optimization recommendations from bottlenecks.
        
        Args:
            bottlenecks: List of bottleneck dictionaries
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        for bottleneck in bottlenecks:
            if bottleneck["type"] != "time":
                continue
            
            if bottleneck["subtype"] == "hotspot":
                # Generate recommendation for hotspot
                recommendations.append({
                    "id": f"time_hotspot_{hash(bottleneck['function']) % 10000:04d}",
                    "target": "time",
                    "description": f"Optimize the hotspot function: {bottleneck['function']}",
                    "details": f"This function takes {bottleneck['time']:.2f}s ({bottleneck['percentage']:.1f}% of total time)",
                    "severity": bottleneck["severity"],
                    "implementation": {
                        "type": "code_change",
                        "function": bottleneck["function"]
                    }
                })
            elif bottleneck["subtype"] == "component":
                # Generate recommendation for component
                recommendations.append({
                    "id": f"time_component_{hash(bottleneck['component']) % 10000:04d}",
                    "target": "time",
                    "description": f"Optimize the {bottleneck['component']} component",
                    "details": f"This component takes {bottleneck['time']:.2f}s ({bottleneck['percentage']:.1f}% of total time)",
                    "severity": bottleneck["severity"],
                    "implementation": {
                        "type": "component_optimization",
                        "component": bottleneck["component"]
                    }
                })
        
        return recommendations
    
    def _generate_memory_recommendations(self, bottlenecks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate memory optimization recommendations from bottlenecks.
        
        Args:
            bottlenecks: List of bottleneck dictionaries
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        for bottleneck in bottlenecks:
            if bottleneck["type"] != "memory":
                continue
            
            if bottleneck["subtype"] == "large_allocation":
                # Generate recommendation for large allocation
                recommendations.append({
                    "id": f"memory_allocation_{hash(bottleneck['file'] + str(bottleneck['line'])) % 10000:04d}",
                    "target": "memory",
                    "description": f"Reduce memory allocation at {os.path.basename(bottleneck['file'])}:{bottleneck['line']}",
                    "details": f"This allocation uses {bottleneck['size'] / (1024 * 1024):.1f} MB of memory",
                    "severity": bottleneck["severity"],
                    "implementation": {
                        "type": "code_change",
                        "file": bottleneck["file"],
                        "line": bottleneck["line"]
                    }
                })
            elif bottleneck["subtype"] == "module":
                # Generate recommendation for module
                recommendations.append({
                    "id": f"memory_module_{hash(bottleneck['module']) % 10000:04d}",
                    "target": "memory",
                    "description": f"Optimize memory usage in the {bottleneck['module']} module",
                    "details": f"This module uses {bottleneck['size'] / (1024 * 1024):.1f} MB of memory ({bottleneck['percentage']:.1f}% of peak memory)",
                    "severity": bottleneck["severity"],
                    "implementation": {
                        "type": "module_optimization",
                        "module": bottleneck["module"]
                    }
                })
        
        return recommendations
    
    def _apply_optimization(self, recommendation: Dict[str, Any]) -> bool:
        """
        Apply an optimization recommendation.
        
        Args:
            recommendation: Recommendation dictionary
            
        Returns:
            True if the optimization was applied successfully, False otherwise
        """
        logger.info(f"Applying optimization: {recommendation['description']}")
        
        # This is a placeholder for actual optimization implementation
        # In a real implementation, this would modify code, configuration, etc.
        
        return True
    
    def _calculate_improvement(self, before_metrics: Dict[str, Any], after_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate improvement between before and after metrics.
        
        Args:
            before_metrics: Metrics before optimization
            after_metrics: Metrics after optimization
            
        Returns:
            Dictionary with improvement metrics
        """
        improvement = {}
        
        # Calculate time improvement
        if "time" in before_metrics and "time" in after_metrics:
            before_time = before_metrics["time"]["total_time"]
            after_time = after_metrics["time"]["total_time"]
            
            improvement["time"] = {
                "before": before_time,
                "after": after_time,
                "difference": before_time - after_time,
                "percentage": ((before_time - after_time) / before_time) * 100 if before_time > 0 else 0
            }
        
        # Calculate memory improvement
        if "memory" in before_metrics and "memory" in after_metrics:
            before_memory = before_metrics["memory"]["peak_memory"]
            after_memory = after_metrics["memory"]["peak_memory"]
            
            improvement["memory"] = {
                "before": before_memory,
                "after": after_memory,
                "difference": before_memory - after_memory,
                "percentage": ((before_memory - after_memory) / before_memory) * 100 if before_memory > 0 else 0
            }
        
        return improvement
    
    def _save_results(self, results: Dict[str, Any]) -> str:
        """
        Save profiling results to a file.
        
        Args:
            results: Profiling results
            
        Returns:
            Path to the saved results file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(self.output_dir, f"profiling_{timestamp}.json")
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Saved profiling results to {file_path}")
        
        return file_path
    
    def _save_optimization_results(self, results: Dict[str, Any]) -> str:
        """
        Save optimization results to a file.
        
        Args:
            results: Optimization results
            
        Returns:
            Path to the saved results file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(self.output_dir, f"optimization_{timestamp}.json")
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Saved optimization results to {file_path}")
        
        return file_path