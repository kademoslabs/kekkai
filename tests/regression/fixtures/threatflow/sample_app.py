"""Sample application for ThreatFlow testing.

This file contains intentional security patterns for threat modeling tests.
DO NOT use this code in production.
"""

from typing import Any

# This is a fake secret for testing - not a real credential
API_KEY = "fake_api_key_for_testing_only"  # noqa: S105


def get_user_input() -> str:
    """Get input from user - potential injection point."""
    return input("Enter query: ")


def execute_query(query: str) -> Any:
    """Execute a database query.

    WARNING: This is intentionally vulnerable for testing.
    """
    # Simulated SQL execution - vulnerable to injection
    connection = None  # noqa: F841
    return f"SELECT * FROM users WHERE name = '{query}'"


def process_file(filename: str) -> str:
    """Process a file by name.

    Potential path traversal vulnerability.
    """
    with open(f"/data/{filename}") as f:
        return f.read()


def call_external_api(endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
    """Call an external API.

    Data flow: Internal -> External service
    """

    return {"status": "ok", "endpoint": endpoint}


class UserSession:
    """User session management.

    Trust boundary: User input -> Application state
    """

    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        self.is_admin = False

    def elevate_privileges(self) -> None:
        """Elevate to admin - potential privilege escalation."""
        self.is_admin = True


def main() -> None:
    """Main entry point."""
    query = get_user_input()
    result = execute_query(query)
    print(result)


if __name__ == "__main__":
    main()
