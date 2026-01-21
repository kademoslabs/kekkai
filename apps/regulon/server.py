from __future__ import annotations

from wsgiref.simple_server import make_server

from regulon.web import application


def main() -> None:
    with make_server("127.0.0.1", 8080, application) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
