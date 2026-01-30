from __future__ import annotations

import contextlib
import json
import secrets
import shutil
import socket
import string
import subprocess  # nosec B404
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .paths import app_base_dir, ensure_dir

DEFAULT_PORT = 8080
DEFAULT_TLS_PORT = 8443
DEFAULT_PROJECT_NAME = "kekkai-dojo"
DEFAULT_DJANGO_VERSION = "latest"
DEFAULT_NGINX_VERSION = "latest"
DOJO_PROFILE = "dojo"


@dataclass(frozen=True)
class ServiceStatus:
    name: str
    state: str
    health: str | None
    exit_code: int | None
    ports: str | None


def compose_dir(override: str | None = None) -> Path:
    if override:
        return Path(override).expanduser().resolve()
    return app_base_dir() / "dojo"


def compose_command() -> list[str]:
    docker = shutil.which("docker")
    if docker:
        proc = subprocess.run([docker, "compose", "version"], capture_output=True, text=True)  # noqa: S603  # nosec B603
        if proc.returncode == 0:
            return [docker, "compose"]
    docker_compose = shutil.which("docker-compose")
    if docker_compose:
        return [docker_compose]
    raise RuntimeError(
        "Docker Compose not found. Please install Docker Desktop "
        "or the 'docker-compose-plugin' package for your system."
    )


def check_port_available(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def find_available_port(preferred: int, max_attempts: int = 20) -> tuple[int, bool]:
    """Find an available port, starting from preferred.

    Returns:
        Tuple of (port, was_fallback) - was_fallback is True if not the preferred port
    """
    if check_port_available(preferred):
        return preferred, False
    for offset in range(1, max_attempts + 1):
        candidate = preferred + offset
        if check_port_available(candidate):
            return candidate, True
    raise RuntimeError(f"No available ports found in range {preferred}-{preferred + max_attempts}")


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def write_env_file(path: Path, env: dict[str, str]) -> None:
    lines = [f"{key}={env[key]}" for key in sorted(env.keys())]
    path.write_text("\n".join(lines) + "\n")


def ensure_env(path: Path, port: int, tls_port: int) -> dict[str, str]:
    env = load_env_file(path)
    env.setdefault("DD_ADMIN_USER", "admin")
    env.setdefault("DD_ADMIN_MAIL", "admin@defectdojo.local")
    env.setdefault("DD_ADMIN_FIRST_NAME", "Admin")
    env.setdefault("DD_ADMIN_LAST_NAME", "User")
    env.setdefault("DD_ADMIN_PASSWORD", _random_string(20))
    env.setdefault("DD_DATABASE_NAME", "defectdojo")
    env.setdefault("DD_DATABASE_USER", "defectdojo")
    env.setdefault("DD_DATABASE_PASSWORD", _random_string(24))
    env.setdefault("DD_DATABASE_HOST", "postgres")
    env.setdefault("DD_DATABASE_PORT", "5432")
    env.setdefault(
        "DD_DATABASE_URL",
        f"postgresql://{env['DD_DATABASE_USER']}:{env['DD_DATABASE_PASSWORD']}@"
        f"{env['DD_DATABASE_HOST']}:{env['DD_DATABASE_PORT']}/{env['DD_DATABASE_NAME']}",
    )
    env.setdefault("DD_CELERY_BROKER_URL", "redis://valkey:6379/0")
    env.setdefault("DD_SECRET_KEY", _random_string(50))
    env.setdefault("DD_CREDENTIAL_AES_256_KEY", _random_string(32))
    env.setdefault("DD_INITIALIZE", "true")
    env.setdefault("DD_ALLOWED_HOSTS", "*")
    env.setdefault("DD_DATABASE_READINESS_TIMEOUT", "30")
    env.setdefault("DD_DJANGO_METRICS_ENABLED", "False")
    env.setdefault("DD_CELERY_WORKER_CONCURRENCY", "1")
    env.setdefault("DD_CELERY_WORKER_PREFETCH_MULTIPLIER", "1")
    env.setdefault("DD_PORT", str(port))
    env.setdefault("DD_TLS_PORT", str(tls_port))
    env.setdefault("DJANGO_VERSION", DEFAULT_DJANGO_VERSION)
    env.setdefault("NGINX_VERSION", DEFAULT_NGINX_VERSION)
    return env


def build_compose_yaml() -> str:
    return (
        "services:\n"
        "  nginx:\n"
        "    image: defectdojo/defectdojo-nginx:${NGINX_VERSION:-latest}\n"
        '    profiles: ["dojo"]\n'
        "    depends_on:\n"
        "      uwsgi:\n"
        "        condition: service_started\n"
        "    environment:\n"
        '      NGINX_METRICS_ENABLED: "false"\n'
        '      DD_UWSGI_HOST: "uwsgi"\n'
        '      DD_UWSGI_PORT: "3031"\n'
        "    volumes:\n"
        "      - defectdojo_media:/usr/share/nginx/html/media\n"
        "    ports:\n"
        "      - target: 8080\n"
        "        published: ${DD_PORT:-8080}\n"
        "        protocol: tcp\n"
        "        mode: host\n"
        "      - target: 8443\n"
        "        published: ${DD_TLS_PORT:-8443}\n"
        "        protocol: tcp\n"
        "        mode: host\n"
        "    healthcheck:\n"
        '      test: ["CMD", "wget", "-q", "-O", "-", "http://localhost:8080/"]\n'
        "      interval: 10s\n"
        "      timeout: 3s\n"
        "      retries: 15\n"
        "  uwsgi:\n"
        "    image: defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}\n"
        '    profiles: ["dojo"]\n'
        "    depends_on:\n"
        "      initializer:\n"
        "        condition: service_completed_successfully\n"
        "      postgres:\n"
        "        condition: service_healthy\n"
        "      valkey:\n"
        "        condition: service_started\n"
        '    entrypoint: ["/wait-for-it.sh", '
        '"${DD_DATABASE_HOST:-postgres}:${DD_DATABASE_PORT:-5432}", '
        '"-t", "30", "--", "/entrypoint-uwsgi.sh"]\n'
        "    environment:\n"
        '      DD_DEBUG: "False"\n'
        "      DD_DJANGO_METRICS_ENABLED: ${DD_DJANGO_METRICS_ENABLED:-False}\n"
        "      DD_ALLOWED_HOSTS: ${DD_ALLOWED_HOSTS:-*}\n"
        "      DD_DATABASE_URL: ${DD_DATABASE_URL:-postgresql://defectdojo:defectdojo@postgres:5432/defectdojo}\n"
        "      DD_CELERY_BROKER_URL: ${DD_CELERY_BROKER_URL:-redis://valkey:6379/0}\n"
        "      DD_SECRET_KEY: ${DD_SECRET_KEY:-change-me}\n"
        "      DD_CREDENTIAL_AES_256_KEY: ${DD_CREDENTIAL_AES_256_KEY:-change-me}\n"
        "      DD_DATABASE_READINESS_TIMEOUT: ${DD_DATABASE_READINESS_TIMEOUT:-30}\n"
        "    volumes:\n"
        "      - defectdojo_media:${DD_MEDIA_ROOT:-/app/media}\n"
        "  celerybeat:\n"
        "    image: defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}\n"
        '    profiles: ["dojo"]\n'
        "    depends_on:\n"
        "      initializer:\n"
        "        condition: service_completed_successfully\n"
        "      postgres:\n"
        "        condition: service_healthy\n"
        "      valkey:\n"
        "        condition: service_started\n"
        '    entrypoint: ["/wait-for-it.sh", '
        '"${DD_DATABASE_HOST:-postgres}:${DD_DATABASE_PORT:-5432}", '
        '"-t", "30", "--", "/entrypoint-celery-beat.sh"]\n'
        "    environment:\n"
        "      DD_DATABASE_URL: ${DD_DATABASE_URL:-postgresql://defectdojo:defectdojo@postgres:5432/defectdojo}\n"
        "      DD_CELERY_BROKER_URL: ${DD_CELERY_BROKER_URL:-redis://valkey:6379/0}\n"
        "      DD_SECRET_KEY: ${DD_SECRET_KEY:-change-me}\n"
        "      DD_CREDENTIAL_AES_256_KEY: ${DD_CREDENTIAL_AES_256_KEY:-change-me}\n"
        "      DD_DATABASE_READINESS_TIMEOUT: ${DD_DATABASE_READINESS_TIMEOUT:-30}\n"
        "  celeryworker:\n"
        "    image: defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}\n"
        '    profiles: ["dojo"]\n'
        "    depends_on:\n"
        "      initializer:\n"
        "        condition: service_completed_successfully\n"
        "      postgres:\n"
        "        condition: service_healthy\n"
        "      valkey:\n"
        "        condition: service_started\n"
        '    entrypoint: ["/wait-for-it.sh", '
        '"${DD_DATABASE_HOST:-postgres}:${DD_DATABASE_PORT:-5432}", '
        '"-t", "30", "--", "/entrypoint-celery-worker.sh"]\n'
        "    environment:\n"
        "      DD_DATABASE_URL: ${DD_DATABASE_URL:-postgresql://defectdojo:defectdojo@postgres:5432/defectdojo}\n"
        "      DD_CELERY_BROKER_URL: ${DD_CELERY_BROKER_URL:-redis://valkey:6379/0}\n"
        "      DD_SECRET_KEY: ${DD_SECRET_KEY:-change-me}\n"
        "      DD_CREDENTIAL_AES_256_KEY: ${DD_CREDENTIAL_AES_256_KEY:-change-me}\n"
        "      DD_DATABASE_READINESS_TIMEOUT: ${DD_DATABASE_READINESS_TIMEOUT:-30}\n"
        "      DD_CELERY_WORKER_CONCURRENCY: ${DD_CELERY_WORKER_CONCURRENCY:-1}\n"
        "      DD_CELERY_WORKER_PREFETCH_MULTIPLIER: ${DD_CELERY_WORKER_PREFETCH_MULTIPLIER:-1}\n"
        "    volumes:\n"
        "      - defectdojo_media:${DD_MEDIA_ROOT:-/app/media}\n"
        "  initializer:\n"
        "    image: defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}\n"
        '    profiles: ["dojo"]\n'
        "    depends_on:\n"
        "      postgres:\n"
        "        condition: service_healthy\n"
        '    entrypoint: ["/wait-for-it.sh", '
        '"${DD_DATABASE_HOST:-postgres}:${DD_DATABASE_PORT:-5432}", '
        '"--", "/entrypoint-initializer.sh"]\n'
        "    environment:\n"
        "      DD_DATABASE_URL: ${DD_DATABASE_URL:-postgresql://defectdojo:defectdojo@postgres:5432/defectdojo}\n"
        "      DD_ADMIN_USER: ${DD_ADMIN_USER:-admin}\n"
        "      DD_ADMIN_MAIL: ${DD_ADMIN_MAIL:-admin@defectdojo.local}\n"
        "      DD_ADMIN_FIRST_NAME: ${DD_ADMIN_FIRST_NAME:-Admin}\n"
        "      DD_ADMIN_LAST_NAME: ${DD_ADMIN_LAST_NAME:-User}\n"
        "      DD_ADMIN_PASSWORD: ${DD_ADMIN_PASSWORD:-admin}\n"
        "      DD_INITIALIZE: ${DD_INITIALIZE:-true}\n"
        "      DD_SECRET_KEY: ${DD_SECRET_KEY:-change-me}\n"
        "      DD_CREDENTIAL_AES_256_KEY: ${DD_CREDENTIAL_AES_256_KEY:-change-me}\n"
        "      DD_DATABASE_READINESS_TIMEOUT: ${DD_DATABASE_READINESS_TIMEOUT:-30}\n"
        "  postgres:\n"
        "    image: postgres:18.1-alpine\n"
        '    profiles: ["dojo"]\n'
        "    environment:\n"
        "      POSTGRES_DB: ${DD_DATABASE_NAME:-defectdojo}\n"
        "      POSTGRES_USER: ${DD_DATABASE_USER:-defectdojo}\n"
        "      POSTGRES_PASSWORD: ${DD_DATABASE_PASSWORD:-defectdojo}\n"
        '    command: ["postgres", "-c", "shared_buffers=256MB", "-c", '
        '"work_mem=16MB", "-c", "maintenance_work_mem=128MB", '
        '"-c", "max_connections=50"]\n'
        "    volumes:\n"
        "      - defectdojo_postgres:/var/lib/postgresql/data\n"
        "    healthcheck:\n"
        '      test: ["CMD-SHELL", '
        '"pg_isready -U ${DD_DATABASE_USER:-defectdojo} -d '
        '${DD_DATABASE_NAME:-defectdojo}"]\n'
        "      interval: 10s\n"
        "      timeout: 5s\n"
        "      retries: 10\n"
        "  valkey:\n"
        "    image: valkey/valkey:7.2.11-alpine\n"
        '    profiles: ["dojo"]\n'
        "    volumes:\n"
        "      - defectdojo_redis:/data\n"
        "volumes:\n"
        "  defectdojo_postgres: {}\n"
        "  defectdojo_media: {}\n"
        "  defectdojo_redis: {}\n"
    )


def ensure_compose_files(
    compose_path: Path, env_path: Path, port: int, tls_port: int
) -> dict[str, str]:
    ensure_dir(compose_path.parent)
    env = ensure_env(env_path, port=port, tls_port=tls_port)
    write_env_file(env_path, env)
    compose_path.write_text(build_compose_yaml())
    return env


def compose_up(
    *,
    compose_root: Path,
    project_name: str,
    port: int,
    tls_port: int,
    wait: bool,
    open_browser: bool,
) -> tuple[dict[str, str], int, int]:
    """Start DefectDojo stack.

    Returns:
        Tuple of (env_dict, actual_port, actual_tls_port)
    """
    # Auto-select available ports
    actual_port, port_fallback = find_available_port(port)
    actual_tls_port, tls_fallback = find_available_port(tls_port)

    compose_file = compose_root / "docker-compose.yml"
    env_file = compose_root / ".env"
    env = ensure_compose_files(compose_file, env_file, actual_port, actual_tls_port)

    # Store port info for later retrieval
    env["DD_PORT"] = str(actual_port)
    env["DD_TLS_PORT"] = str(actual_tls_port)
    write_env_file(env_file, env)

    cmd = compose_command() + [
        "--project-name",
        project_name,
        "--file",
        str(compose_file),
        "--profile",
        DOJO_PROFILE,
    ]
    proc = subprocess.run(cmd + ["up", "-d"], capture_output=True, text=True)  # noqa: S603  # nosec B603
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Failed to start DefectDojo")

    if wait:
        wait_for_ui(actual_port, timeout=300)
        # Generate API key for kekkai upload command
        try:
            api_key = generate_api_key(
                actual_port,
                env.get("DD_ADMIN_USER", "admin"),
                env.get("DD_ADMIN_PASSWORD", ""),
            )
            env["DD_API_KEY"] = api_key
            write_env_file(env_file, env)
        except RuntimeError:
            # Non-fatal - user can generate API key manually via UI
            pass

    if open_browser:
        open_ui(actual_port)

    return env, actual_port, actual_tls_port


def compose_down(*, compose_root: Path, project_name: str) -> None:
    compose_file = compose_root / "docker-compose.yml"
    cmd = compose_command() + [
        "--project-name",
        project_name,
        "--file",
        str(compose_file),
        "--profile",
        DOJO_PROFILE,
    ]
    proc = subprocess.run(  # noqa: S603  # nosec B603
        cmd + ["down", "--remove-orphans", "--volumes"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Failed to stop DefectDojo")


def compose_status(*, compose_root: Path, project_name: str) -> list[ServiceStatus]:
    compose_file = compose_root / "docker-compose.yml"
    cmd = compose_command() + [
        "--project-name",
        project_name,
        "--file",
        str(compose_file),
        "--profile",
        DOJO_PROFILE,
    ]
    proc = subprocess.run(cmd + ["ps", "--format", "json"], capture_output=True, text=True)  # noqa: S603  # nosec B603
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Failed to read status")
    return parse_compose_ps(proc.stdout)


def parse_compose_ps(output: str) -> list[ServiceStatus]:
    if not output.strip():
        return []
    try:
        data: Any = json.loads(output)
    except json.JSONDecodeError:
        data = []
        for line in output.splitlines():
            if not line.strip():
                continue
            data.append(json.loads(line))
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("Invalid compose ps json")

    statuses: list[ServiceStatus] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        statuses.append(
            ServiceStatus(
                name=str(item.get("Service") or item.get("Name") or "unknown"),
                state=str(item.get("State") or "unknown"),
                health=_optional_str(item.get("Health")),
                exit_code=_optional_int(item.get("ExitCode")),
                ports=_optional_str(item.get("Publishers")),
            ),
        )
    return statuses


def wait_for_ui(port: int, timeout: int = 300) -> None:
    url = f"http://localhost:{port}/"
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            req = Request(url, method="GET")  # noqa: S310  # nosec B310
            with urlopen(req, timeout=5) as resp:  # noqa: S310  # nosec B310
                if resp.status in {200, 302, 401}:
                    return
                last_error = f"HTTP {resp.status}"
        except (URLError, HTTPError, OSError, ConnectionError) as exc:
            # OSError/ConnectionError covers ConnectionResetError, BrokenPipeError, etc.
            last_error = str(exc)
        time.sleep(2)
    raise RuntimeError(f"DefectDojo UI did not become ready in time ({last_error})")


def open_ui(port: int) -> None:
    url = f"http://localhost:{port}/"
    print(f"Opening {url}")
    with contextlib.suppress(Exception):
        webbrowser.open(url)


def generate_api_key(port: int, username: str, password: str, timeout: int = 30) -> str:
    """Generate DefectDojo API key using admin credentials.

    Uses the /api/v2/api-token-auth/ endpoint to get a token.

    Args:
        port: DefectDojo port
        username: Admin username
        password: Admin password
        timeout: Request timeout in seconds

    Returns:
        API token string

    Raises:
        RuntimeError: If token generation fails
    """
    url = f"http://localhost:{port}/api/v2/api-token-auth/"
    data = json.dumps({"username": username, "password": password}).encode()
    headers = {"Content-Type": "application/json"}

    req = Request(url, data=data, headers=headers, method="POST")  # noqa: S310  # nosec B310
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            result: dict[str, str] = json.loads(resp.read().decode())
            token = result.get("token", "")
            if not token:
                raise RuntimeError("Empty token returned from DefectDojo")
            return token
    except (URLError, HTTPError, OSError) as exc:
        raise RuntimeError(f"Failed to generate API key: {exc}") from exc


def _random_string(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
