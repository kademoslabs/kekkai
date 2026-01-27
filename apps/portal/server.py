#!/usr/bin/env python3
"""Kekkai Portal WSGI server entry point."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from wsgiref.simple_server import make_server

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from portal.web import create_app


def main() -> int:
    """Run the portal development server."""
    host = os.environ.get("PORTAL_HOST", "127.0.0.1")
    port = int(os.environ.get("PORTAL_PORT", "8000"))
    tenant_store = os.environ.get("PORTAL_TENANT_STORE")

    store_path = Path(tenant_store) if tenant_store else None
    app = create_app(store_path)

    print(f"Starting Kekkai Portal on http://{host}:{port}")
    print("Press Ctrl+C to stop")

    with make_server(host, port, app) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")

    return 0


if __name__ == "__main__":
    sys.exit(main())
