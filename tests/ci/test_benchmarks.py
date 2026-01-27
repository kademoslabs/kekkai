"""Tests for performance benchmarking utilities."""

import time
from pathlib import Path
from typing import Any

import pytest

from kekkai_core.ci.benchmarks import (
    BenchmarkResult,
    BenchmarkRunner,
    PerformanceBenchmark,
    benchmark_function,
    format_benchmark_report,
    get_system_info,
)


class TestBenchmarkResult:
    """Test BenchmarkResult dataclass."""

    def test_benchmark_result_creation(self) -> None:
        """Test creating a benchmark result."""
        result = BenchmarkResult(
            name="test_benchmark",
            duration_seconds=1.23,
            memory_peak_mb=45.6,
            metadata={"test": True},
        )

        assert result.name == "test_benchmark"
        assert result.duration_seconds == 1.23
        assert result.memory_peak_mb == 45.6
        assert result.metadata["test"] is True

    def test_benchmark_result_to_dict(self) -> None:
        """Test converting result to dict."""
        result = BenchmarkResult(
            name="test",
            duration_seconds=1.0,
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["name"] == "test"
        assert result_dict["duration_seconds"] == 1.0
        assert "platform" in result_dict
        assert "python_version" in result_dict


class TestPerformanceBenchmark:
    """Test PerformanceBenchmark context manager."""

    def test_benchmark_context_manager(self) -> None:
        """Test using benchmark as context manager."""
        with PerformanceBenchmark("test") as bench:
            time.sleep(0.01)  # Sleep for 10ms

        result = bench.get_result()

        assert result.name == "test"
        assert result.duration_seconds >= 0.01
        assert result.duration_seconds < 0.1  # Should be much less than 100ms

    def test_benchmark_with_metadata(self) -> None:
        """Test benchmark with metadata."""
        metadata = {"test_type": "unit", "iterations": 10}

        with PerformanceBenchmark("test", metadata=metadata) as bench:
            pass

        result = bench.get_result()

        assert result.metadata == metadata

    def test_benchmark_error_before_completion(self) -> None:
        """Test error if getting result before completion."""
        bench = PerformanceBenchmark("test")

        with pytest.raises(RuntimeError, match="not completed"):
            bench.get_result()


class TestBenchmarkFunction:
    """Test benchmark_function utility."""

    def test_benchmark_simple_function(self) -> None:
        """Test benchmarking a simple function."""

        def simple_func() -> int:
            return sum(range(1000))

        result = benchmark_function(simple_func)

        assert result.name == "simple_func"
        assert result.duration_seconds > 0
        assert result.duration_seconds < 1.0  # Should be very fast

    def test_benchmark_with_custom_name(self) -> None:
        """Test benchmark with custom name."""

        def func() -> None:
            pass

        result = benchmark_function(func, name="custom_name")

        assert result.name == "custom_name"

    def test_benchmark_multiple_iterations(self) -> None:
        """Test benchmark with multiple iterations."""
        counter = {"count": 0}

        def counted_func() -> None:
            counter["count"] += 1

        result = benchmark_function(counted_func, iterations=10)

        assert counter["count"] == 10
        assert "iterations" in result.metadata
        assert result.metadata["iterations"] == 10

    def test_benchmark_with_warmup(self) -> None:
        """Test benchmark with warmup iterations."""
        counter = {"count": 0}

        def counted_func() -> None:
            counter["count"] += 1

        # 2 warmup + 5 measured = 7 total calls
        benchmark_function(counted_func, iterations=5, warmup=2)

        assert counter["count"] == 7


class TestBenchmarkRunner:
    """Test BenchmarkRunner class."""

    def test_runner_initialization(self, tmp_path: Path) -> None:
        """Test runner initialization."""
        runner = BenchmarkRunner(output_dir=tmp_path / "benchmarks")

        assert runner.output_dir == tmp_path / "benchmarks"
        assert len(runner.results) == 0

    def test_runner_run_benchmark(self, tmp_path: Path) -> None:
        """Test running benchmark with runner."""
        runner = BenchmarkRunner(output_dir=tmp_path)

        def test_func() -> int:
            return sum(range(100))

        result = runner.run_benchmark(test_func, name="sum_test")

        assert len(runner.results) == 1
        assert runner.results[0].name == "sum_test"
        assert result.duration_seconds > 0

    def test_runner_multiple_benchmarks(self, tmp_path: Path) -> None:
        """Test running multiple benchmarks."""
        runner = BenchmarkRunner(output_dir=tmp_path)

        def func1() -> None:
            pass

        def func2() -> None:
            pass

        runner.run_benchmark(func1, name="benchmark1")
        runner.run_benchmark(func2, name="benchmark2")

        assert len(runner.results) == 2

    def test_runner_save_results(self, tmp_path: Path) -> None:
        """Test saving benchmark results."""
        runner = BenchmarkRunner(output_dir=tmp_path / "benchmarks")

        def test_func() -> None:
            pass

        runner.run_benchmark(test_func)

        output_path = runner.save_results(filename="test_results.json")

        assert output_path.exists()
        assert output_path.name == "test_results.json"
        assert "benchmark" in output_path.parent.name.lower()

    def test_runner_load_results(self, tmp_path: Path) -> None:
        """Test loading benchmark results."""
        runner = BenchmarkRunner(output_dir=tmp_path)

        def test_func() -> None:
            pass

        runner.run_benchmark(test_func, name="test_benchmark")
        output_path = runner.save_results(filename="test.json")

        # Load results
        loaded_results = runner.load_results(output_path)

        assert len(loaded_results) == 1
        assert loaded_results[0].name == "test_benchmark"

    def test_runner_compare_with_baseline(self, tmp_path: Path) -> None:
        """Test comparing results with baseline."""
        # Create baseline
        baseline_runner = BenchmarkRunner(output_dir=tmp_path / "baseline")

        def fast_func() -> None:
            time.sleep(0.001)

        baseline_runner.run_benchmark(fast_func, name="test_func")
        baseline_path = baseline_runner.save_results(filename="baseline.json")

        # Create current results (slower)
        current_runner = BenchmarkRunner(output_dir=tmp_path / "current")

        def slow_func() -> None:
            time.sleep(0.002)

        current_runner.run_benchmark(slow_func, name="test_func")

        # Compare
        comparison = current_runner.compare_with_baseline(baseline_path, threshold_percent=10.0)

        assert "regressions" in comparison
        assert "improvements" in comparison
        assert "total_benchmarks" in comparison
        assert comparison["total_benchmarks"] == 1


class TestSystemInfo:
    """Test system information utilities."""

    def test_get_system_info(self) -> None:
        """Test getting system information."""
        info = get_system_info()

        assert "platform" in info
        assert "python" in info
        assert "system" in info["platform"]
        assert "version" in info["python"]

    def test_system_info_structure(self) -> None:
        """Test system info has expected structure."""
        info = get_system_info()

        # Platform info
        assert isinstance(info["platform"]["system"], str)
        assert isinstance(info["platform"]["machine"], str)

        # Python info
        assert isinstance(info["python"]["version"], str)
        assert isinstance(info["python"]["implementation"], str)


class TestBenchmarkReporting:
    """Test benchmark reporting utilities."""

    def test_format_benchmark_report(self) -> None:
        """Test formatting benchmark report."""
        results = [
            BenchmarkResult(
                name="test1",
                duration_seconds=1.23,
                memory_peak_mb=45.6,
            ),
            BenchmarkResult(
                name="test2",
                duration_seconds=0.56,
                memory_peak_mb=23.4,
            ),
        ]

        report = format_benchmark_report(results)

        assert "Performance Benchmark Report" in report
        assert "test1" in report
        assert "test2" in report
        assert "1.23" in report or "1.2300" in report

    def test_report_without_memory(self) -> None:
        """Test report formatting without memory info."""
        results = [
            BenchmarkResult(
                name="test",
                duration_seconds=1.0,
                memory_peak_mb=None,
            ),
        ]

        report = format_benchmark_report(results)

        assert "N/A" in report


@pytest.mark.integration
class TestBenchmarkIntegration:
    """Integration tests for benchmarking."""

    def test_end_to_end_benchmark_workflow(self, tmp_path: Path) -> None:
        """Test complete benchmark workflow."""
        runner = BenchmarkRunner(output_dir=tmp_path / "benchmarks")

        # Define test functions
        def list_comprehension() -> list[int]:
            return [i * 2 for i in range(10000)]

        def generator_expression() -> int:
            return sum(i * 2 for i in range(10000))

        # Run benchmarks
        runner.run_benchmark(list_comprehension, name="list_comp", iterations=10)
        runner.run_benchmark(generator_expression, name="generator", iterations=10)

        # Save results
        output_path = runner.save_results(filename="integration_test.json")

        assert output_path.exists()
        assert len(runner.results) == 2

        # Format report
        report = format_benchmark_report(runner.results)
        assert "list_comp" in report
        assert "generator" in report


@pytest.mark.benchmark
class TestPerformanceRegression:
    """Performance regression tests."""

    def test_scan_performance_baseline(self) -> None:
        """Baseline scan performance test."""

        def simulated_scan() -> list[int]:
            # Simulate scan workload
            return [i for i in range(1000)]

        result = benchmark_function(simulated_scan, iterations=100)

        # Should complete in reasonable time
        assert result.duration_seconds < 1.0

    def test_json_parsing_performance(self) -> None:
        """Test JSON parsing performance."""
        import json

        data = {"key": "value", "items": list(range(1000))}
        json_str = json.dumps(data)

        def parse_json() -> Any:
            return json.loads(json_str)

        result = benchmark_function(parse_json, iterations=1000)

        # Should be fast
        assert result.duration_seconds < 0.5

    def test_file_io_performance(self, tmp_path: Path) -> None:
        """Test file I/O performance."""
        test_file = tmp_path / "test.txt"
        content = "test content\n" * 1000

        def write_and_read() -> str:
            test_file.write_text(content)
            return test_file.read_text()

        result = benchmark_function(write_and_read, iterations=10)

        # Should be reasonably fast
        assert result.duration_seconds < 1.0
