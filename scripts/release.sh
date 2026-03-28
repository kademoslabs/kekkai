#!/bin/bash
# release.sh - Reproducible release script for Kekkai CLI
#
# Usage:
#   ./scripts/release.sh              # Build release artifacts
#   ./scripts/release.sh --publish    # Build and publish (requires GITHUB_TOKEN)
#
# Environment variables:
#   GITHUB_TOKEN - Required for --publish to create GitHub releases
#   VERSION      - Override version (default: read from pyproject.toml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Extract version from pyproject.toml
get_version() {
    python3 -c "
import tomllib
with open('pyproject.toml', 'rb') as f:
    data = tomllib.load(f)
print(data['project']['version'])
"
}

VERSION="${VERSION:-$(get_version)}"
PUBLISH=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --publish)
            PUBLISH=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=== Kekkai Release Script ==="
echo "Version: $VERSION"
echo ""

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info src/*.egg-info

# Run tests
echo "Running tests..."
make ci-quick

# Build artifacts
echo "Building release artifacts..."
python3 -m pip install -q build
python3 -m build

# Generate SBOM
echo "Generating SBOM..."
pip freeze --exclude-editable > dist/requirements-frozen.txt

# Generate sha256 checksums for Homebrew formula
echo ""
echo "Generating checksums for Homebrew formula..."
for file in dist/*.tar.gz; do
    if [ -f "$file" ]; then
        sha256sum "$file" | tee -a dist/checksums.txt
    fi
done

# List artifacts
echo ""
echo "Release artifacts:"
ls -la dist/

# Verify wheel
echo ""
echo "Verifying wheel..."
python3 -m pip install -q twine
twine check dist/*.whl dist/*.tar.gz

if [ "$PUBLISH" = true ]; then
    if [ -z "${GITHUB_TOKEN:-}" ]; then
        echo "ERROR: GITHUB_TOKEN required for --publish"
        exit 1
    fi

    echo ""
    echo "Creating GitHub release v${VERSION}..."

    # Check if gh is available
    if ! command -v gh &> /dev/null; then
        echo "ERROR: gh (GitHub CLI) not found. Install it or use manual release."
        exit 1
    fi

    # Create release
    gh release create "v${VERSION}" \
        --title "Kekkai v${VERSION}" \
        --notes "Release v${VERSION}" \
        dist/*.whl \
        dist/*.tar.gz \
        dist/requirements-frozen.txt

    echo "Release v${VERSION} created successfully!"
fi

echo ""
echo "=== Release complete ==="
