#!/bin/bash
set -e

TARGET_DIR="my-insecure-app"

# Ensure we are in the project root
cd "$(dirname "$0")/.."

echo "🏗️  Setting up test playground in ./$TARGET_DIR..."

# Clean previous run
if [ -d "$TARGET_DIR" ]; then
    rm -rf "$TARGET_DIR"
fi

mkdir "$TARGET_DIR"
cd "$TARGET_DIR"
git init -q

# 1. Vulnerable Python App (SCA + SAST targets)
cat <<'EOF' > app.py
import os

# TODO: Remove before prod (Gitleaks target)
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

def run_command(user_input):
    # DANGER: Command Injection (Semgrep target)
    os.system("echo " + user_input)

def main():
    print("Starting app...")
EOF

# 2. Vulnerable Dockerfile (Trivy Config target)
echo "FROM python:3.7" > Dockerfile

# 3. Dummy Requirements (Trivy SCA target)
echo "flask==0.12" > requirements.txt

echo "✅ Test environment ready."
echo "👉 Run: cd $TARGET_DIR && kekkai scan --repo ."
