from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .scanners.base import ScanResult

DEFAULT_TIMEOUT = 30


@dataclass(frozen=True)
class DojoConfig:
    base_url: str
    api_key: str
    product_name: str = "Kekkai Scans"
    engagement_name: str = "Default Engagement"
    verify_ssl: bool = True


@dataclass(frozen=True)
class ImportResult:
    success: bool
    test_id: int | None = None
    findings_created: int = 0
    findings_closed: int = 0
    error: str | None = None


class DojoClient:
    def __init__(self, config: DojoConfig, timeout: int = DEFAULT_TIMEOUT) -> None:
        self._config = config
        self._timeout = timeout
        self._base_url = config.base_url.rstrip("/")

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        files: dict[str, tuple[str, bytes, str]] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base_url}/api/v2/{endpoint}"
        headers = {
            "Authorization": f"Token {self._config.api_key}",
        }

        body: bytes | None = None
        if files:
            boundary = "----KekkaiFormBoundary"
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            body = self._build_multipart(data or {}, files, boundary)
        elif data:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()

        req = Request(url, data=body, headers=headers, method=method)  # noqa: S310  # nosec B310

        try:
            with urlopen(req, timeout=self._timeout) as resp:  # noqa: S310  # nosec B310
                return json.loads(resp.read().decode()) if resp.read else {}
        except HTTPError as exc:
            error_body = exc.read().decode() if exc.fp else str(exc)
            raise RuntimeError(f"Dojo API error {exc.code}: {error_body}") from exc
        except URLError as exc:
            raise RuntimeError(f"Dojo connection error: {exc.reason}") from exc

    def _build_multipart(
        self,
        data: dict[str, Any],
        files: dict[str, tuple[str, bytes, str]],
        boundary: str,
    ) -> bytes:
        lines: list[bytes] = []
        for key, value in data.items():
            lines.append(f"--{boundary}".encode())
            lines.append(f'Content-Disposition: form-data; name="{key}"'.encode())
            lines.append(b"")
            lines.append(str(value).encode())

        for field_name, (filename, content, content_type) in files.items():
            lines.append(f"--{boundary}".encode())
            disp = f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
            lines.append(disp.encode())
            lines.append(f"Content-Type: {content_type}".encode())
            lines.append(b"")
            lines.append(content)

        lines.append(f"--{boundary}--".encode())
        lines.append(b"")
        return b"\r\n".join(lines)

    def get_or_create_product(self, name: str) -> int:
        resp = self._request("GET", f"products/?name={urllib.parse.quote(name)}")
        results = resp.get("results", [])
        if results:
            return int(results[0]["id"])

        resp = self._request(
            "POST",
            "products/",
            data={
                "name": name,
                "description": "Created by Kekkai CLI",
                "prod_type": 1,
            },
        )
        return int(resp["id"])

    def get_or_create_engagement(self, product_id: int, name: str) -> int:
        resp = self._request(
            "GET",
            f"engagements/?product={product_id}&name={urllib.parse.quote(name)}",
        )
        results = resp.get("results", [])
        if results:
            return int(results[0]["id"])

        resp = self._request(
            "POST",
            "engagements/",
            data={
                "name": name,
                "product": product_id,
                "target_start": "2024-01-01",
                "target_end": "2099-12-31",
                "engagement_type": "CI/CD",
                "status": "In Progress",
            },
        )
        return int(resp["id"])

    def import_scan(
        self,
        scan_result: ScanResult,
        scan_type: str,
        engagement_id: int,
        run_id: str,
        commit_sha: str | None = None,
    ) -> ImportResult:
        if not scan_result.raw_output_path or not scan_result.raw_output_path.exists():
            return ImportResult(
                success=False,
                error="No raw output file to import",
            )

        file_content = scan_result.raw_output_path.read_bytes()
        filename = scan_result.raw_output_path.name

        data = {
            "engagement": engagement_id,
            "scan_type": scan_type,
            "active": True,
            "verified": False,
            "minimum_severity": "Info",
            "close_old_findings": True,
            "push_to_jira": False,
            "version": run_id,
        }
        if commit_sha:
            data["commit_hash"] = commit_sha

        try:
            resp = self._request(
                "POST",
                "import-scan/",
                data=data,
                files={"file": (filename, file_content, "application/json")},
            )
            return ImportResult(
                success=True,
                test_id=resp.get("test"),
                findings_created=resp.get("statistics", {}).get("created", 0),
                findings_closed=resp.get("statistics", {}).get("closed", 0),
            )
        except RuntimeError as exc:
            return ImportResult(success=False, error=str(exc))


def import_results_to_dojo(
    config: DojoConfig,
    results: list[ScanResult],
    scanners: dict[str, Any],
    run_id: str,
    commit_sha: str | None = None,
) -> list[ImportResult]:
    client = DojoClient(config)
    product_id = client.get_or_create_product(config.product_name)
    engagement_id = client.get_or_create_engagement(product_id, config.engagement_name)

    import_results: list[ImportResult] = []
    for result in results:
        scanner = scanners.get(result.scanner)
        if not scanner:
            import_results.append(
                ImportResult(success=False, error=f"Unknown scanner: {result.scanner}")
            )
            continue

        scan_type = getattr(scanner, "scan_type", result.scanner)
        import_result = client.import_scan(
            scan_result=result,
            scan_type=scan_type,
            engagement_id=engagement_id,
            run_id=run_id,
            commit_sha=commit_sha,
        )
        import_results.append(import_result)

    return import_results
