# Dockerfile for Kekkai CLI
# Hardened container image for running kekkai without local Python installation
# Usage: docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .

# Build stage - build wheel and install
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /home/nonroot/build

# Copy project files (owned by nonroot user in this directory)
COPY --chown=nonroot:nonroot pyproject.toml README.md ./
COPY --chown=nonroot:nonroot src/ src/

# Build wheel and install to user directory
RUN pip wheel --no-cache-dir --wheel-dir=/home/nonroot/wheels . && \
    pip install --no-cache-dir --user /home/nonroot/wheels/*.whl

# Final stage - minimal runtime image (distroless, no shell)
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /home/nonroot/.local /home/nonroot/.local

# Set Python path
ENV PATH=/home/nonroot/.local/bin:$PATH

ENTRYPOINT ["python", "-m", "kekkai.cli"]
CMD ["--help"]
