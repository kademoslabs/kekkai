# Dockerfile for Kekkai CLI
# Hardened container image for running kekkai without local Python installation
# Usage: docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .

FROM python:3.12-slim-bookworm

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash kekkai

WORKDIR /app

# Copy project files
COPY requirements/ requirements/
COPY pyproject.toml .
COPY src/ src/

# Install kekkai package
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER kekkai

ENTRYPOINT ["kekkai"]
CMD ["--help"]
