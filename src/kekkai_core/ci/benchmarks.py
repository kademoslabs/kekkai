"""Performance benchmarking utilities for cross-platform testing."""

import json
import platform
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import psutil  # type: ignore[import-untyped]

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class BenchmarkResult:
    """Results from a performance benchmark."""

    name: str
    duration_seconds: float
    memory_peak_mb: float | None = None
    memory_start_mb: float | None = None
    memory_end_mb: float | None = None
    platform: str = field(default_factory=lambda: sys.platform)
    python_version: str = field(default_factory=lambda: platform.python_version())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "duration_seconds": self.duration_seconds,
            "memory_peak_mb": self.memory_peak_mb,
            "memory_start_mb": self.memory_start_mb,
            "memory_end_mb": self.memory_end_mb,
            "platform": self.platform,
            "python_version": self.python_version,
            "metadata": self.metadata,
        }


class PerformanceBenchmark:
    """Context manager for performance benchmarking."""

    def __init__(self, name: str, metadata: dict[str, Any] | None = None):
        """Initialize benchmark.

        Args:
            name: Name of the benchmark
            metadata: Additional metadata to include
        """
        self.name = name
        self.metadata = metadata or {}
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.memory_start: float | None = None
        self.memory_end: float | None = None
        self.memory_peak: float | None = None

    def __enter__(self) -> "PerformanceBenchmark":
        """Start benchmarking."""
        self.start_time = time.perf_counter()

        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            self.memory_start = process.memory_info().rss / (1024 * 1024)  # MB

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """End benchmarking."""
        self.end_time = time.perf_counter()

        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            self.memory_end = process.memory_info().rss / (1024 * 1024)  # MB
            self.memory_peak = self.memory_end  # Simplified; real peak tracking needs monitoring

    def get_result(self) -> BenchmarkResult:
        """Get benchmark result."""
        if self.start_time is None or self.end_time is None:
            raise RuntimeError("Benchmark not completed")

        duration = self.end_time - self.start_time

        return BenchmarkResult(
            name=self.name,
            duration_seconds=duration,
            memory_peak_mb=self.memory_peak,
            memory_start_mb=self.memory_start,
            memory_end_mb=self.memory_end,
            metadata=self.metadata,
        )


def benchmark_function(
    func: Callable[..., Any],
    name: str | None = None,
    iterations: int = 1,
    warmup: int = 0,
    metadata: dict[str, Any] | None = None,
) -> BenchmarkResult:
    """Benchmark a function.

    Args:
        func: Function to benchmark
        name: Name for the benchmark (defaults to function name)
        iterations: Number of times to run the function
        warmup: Number of warmup iterations (not measured)
        metadata: Additional metadata

    Returns:
        Benchmark result
    """
    benchmark_name = name or func.__name__

    # Warmup
    for _ in range(warmup):
        func()

    # Measure
    with PerformanceBenchmark(benchmark_name, metadata=metadata) as bench:
        for _ in range(iterations):
            func()

    result = bench.get_result()

    # Adjust for iterations
    if iterations > 1:
        result.duration_seconds /= iterations
        result.metadata["iterations"] = iterations

    return result


class BenchmarkRunner:
    """Runner for multiple benchmarks."""

    def __init__(self, output_dir: Path | None = None):
        """Initialize benchmark runner.

        Args:
            output_dir: Directory to store benchmark results
        """
        self.output_dir = output_dir or Path(".benchmarks")
        self.results: list[BenchmarkResult] = []

    def run_benchmark(
        self,
        func: Callable[..., Any],
        name: str | None = None,
        iterations: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> BenchmarkResult:
        """Run a benchmark and store result.

        Args:
            func: Function to benchmark
            name: Benchmark name
            iterations: Number of iterations
            metadata: Additional metadata

        Returns:
            Benchmark result
        """
        result = benchmark_function(func, name=name, iterations=iterations, metadata=metadata)
        self.results.append(result)
        return result

    def save_results(self, filename: str | None = None) -> Path:
        """Save benchmark results to file.

        Args:
            filename: Output filename (default: benchmark_{timestamp}.json)

        Returns:
            Path to saved file
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"benchmark_{timestamp}.json"

        output_path = self.output_dir / filename

        results_data = {
            "timestamp": time.time(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
            },
            "results": [r.to_dict() for r in self.results],
        }

        output_path.write_text(json.dumps(results_data, indent=2))

        return output_path

    def load_results(self, filepath: Path) -> list[BenchmarkResult]:
        """Load benchmark results from file.

        Args:
            filepath: Path to results file

        Returns:
            List of benchmark results
        """
        data = json.loads(filepath.read_text())

        loaded_results = []
        for result_dict in data.get("results", []):
            result = BenchmarkResult(
                name=result_dict["name"],
                duration_seconds=result_dict["duration_seconds"],
                memory_peak_mb=result_dict.get("memory_peak_mb"),
                memory_start_mb=result_dict.get("memory_start_mb"),
                memory_end_mb=result_dict.get("memory_end_mb"),
                platform=result_dict.get("platform", "unknown"),
                python_version=result_dict.get("python_version", "unknown"),
                metadata=result_dict.get("metadata", {}),
            )
            loaded_results.append(result)

        return loaded_results

    def compare_with_baseline(
        self, baseline_file: Path, threshold_percent: float = 20.0
    ) -> dict[str, Any]:
        """Compare current results with baseline.

        Args:
            baseline_file: Path to baseline results file
            threshold_percent: Threshold for regression detection (e.g., 20.0 = 20%)

        Returns:
            Comparison report
        """
        baseline_results = self.load_results(baseline_file)

        # Create lookup by name
        baseline_by_name = {r.name: r for r in baseline_results}

        regressions: list[dict[str, Any]] = []
        improvements: list[dict[str, Any]] = []

        for current in self.results:
            if current.name not in baseline_by_name:
                continue

            baseline = baseline_by_name[current.name]

            # Calculate percentage change
            percent_change = (
                (current.duration_seconds - baseline.duration_seconds)
                / baseline.duration_seconds
                * 100.0
            )

            comparison = {
                "name": current.name,
                "baseline_duration": baseline.duration_seconds,
                "current_duration": current.duration_seconds,
                "percent_change": percent_change,
            }

            if percent_change > threshold_percent:
                regressions.append(comparison)
            elif percent_change < -threshold_percent:
                improvements.append(comparison)

        return {
            "threshold_percent": threshold_percent,
            "regressions": regressions,
            "improvements": improvements,
            "total_benchmarks": len(self.results),
        }


def get_system_info() -> dict[str, Any]:
    """Get system information for benchmarking context.

    Returns:
        Dictionary with system information
    """
    info = {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler(),
        },
    }

    if PSUTIL_AVAILABLE:
        info["memory"] = {
            "total_gb": psutil.virtual_memory().total / (1024**3),
            "available_gb": psutil.virtual_memory().available / (1024**3),
        }
        info["cpu"] = {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
        }

    return info


def format_benchmark_report(results: list[BenchmarkResult]) -> str:
    """Format benchmark results as human-readable report.

    Args:
        results: List of benchmark results

    Returns:
        Formatted report string
    """
    lines = ["# Performance Benchmark Report", ""]

    # System info
    sys_info = get_system_info()
    lines.append("## System Information")
    lines.append(f"- Platform: {sys_info['platform']['system']} {sys_info['platform']['release']}")
    lines.append(f"- Machine: {sys_info['platform']['machine']}")
    lines.append(
        f"- Python: {sys_info['python']['version']} ({sys_info['python']['implementation']})"
    )
    lines.append("")

    # Results table
    lines.append("## Benchmark Results")
    lines.append("")
    lines.append("| Benchmark | Duration (s) | Memory Peak (MB) |")
    lines.append("|-----------|--------------|------------------|")

    for result in results:
        memory_str = f"{result.memory_peak_mb:.2f}" if result.memory_peak_mb else "N/A"
        lines.append(f"| {result.name} | {result.duration_seconds:.4f} | {memory_str} |")

    lines.append("")

    return "\n".join(lines)
