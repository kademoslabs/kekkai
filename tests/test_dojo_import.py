from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from kekkai.dojo_import import DojoClient, DojoConfig, ImportResult
from kekkai.scanners.base import ScanResult


class TestDojoConfig:
    def test_defaults(self) -> None:
        cfg = DojoConfig(base_url="http://localhost:8080", api_key="test-key")
        assert cfg.product_name == "Kekkai Scans"
        assert cfg.engagement_name == "Default Engagement"


class TestDojoClient:
    def test_build_multipart(self) -> None:
        cfg = DojoConfig(base_url="http://localhost:8080", api_key="test")
        client = DojoClient(cfg)

        data = {"field1": "value1"}
        files = {"file": ("test.json", b'{"test": true}', "application/json")}
        result = client._build_multipart(data, files, "boundary123")

        assert b"boundary123" in result
        assert b"field1" in result
        assert b"value1" in result
        assert b"test.json" in result


class TestImportResult:
    def test_success_result(self) -> None:
        result = ImportResult(
            success=True,
            test_id=123,
            findings_created=5,
            findings_closed=2,
        )
        assert result.success
        assert result.test_id == 123
        assert result.findings_created == 5

    def test_failure_result(self) -> None:
        result = ImportResult(success=False, error="Connection failed")
        assert not result.success
        assert result.error == "Connection failed"


class TestDojoClientIntegration:
    @patch("kekkai.dojo_import.urlopen")
    def test_get_or_create_product_existing(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"results": [{"id": 42}]}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        cfg = DojoConfig(base_url="http://localhost:8080", api_key="test")
        client = DojoClient(cfg)
        product_id = client.get_or_create_product("Test Product")

        assert product_id == 42

    def test_import_scan_no_file(self, tmp_path: Path) -> None:
        cfg = DojoConfig(base_url="http://localhost:8080", api_key="test")
        client = DojoClient(cfg)

        scan_result = ScanResult(
            scanner="trivy",
            success=True,
            findings=[],
            raw_output_path=None,
        )
        result = client.import_scan(
            scan_result=scan_result,
            scan_type="Trivy Scan",
            engagement_id=1,
            run_id="test-run",
        )

        assert not result.success
        assert "No raw output file" in (result.error or "")
