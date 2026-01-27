# Kekkai Portal Docker Image
# Multi-stage build using Chainguard distroless images for security

LABEL maintainer="Kademos Labs"
LABEL description="Kekkai Portal - DefectDojo-backed security dashboard"

# Build stage - build wheel and install
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /home/nonroot/build

# Copy source code (owned by nonroot user)
COPY --chown=nonroot:nonroot pyproject.toml README.md ./
COPY --chown=nonroot:nonroot src/ src/

# Build wheel and install to user directory
RUN pip wheel --no-cache-dir --wheel-dir=/home/nonroot/wheels . && \
    pip install --no-cache-dir --user /home/nonroot/wheels/*.whl

# Create data directories in builder
RUN mkdir -p /home/nonroot/uploads /home/nonroot/static
RUN cp -r src/portal/static/* /home/nonroot/static/ 2>/dev/null || true

# Final stage - minimal runtime image (distroless, no shell)
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# Copy installed packages and static files from builder
COPY --from=builder /home/nonroot/.local /home/nonroot/.local
COPY --from=builder /home/nonroot/uploads /var/lib/kekkai-portal/uploads
COPY --from=builder /home/nonroot/static /var/www/static

# Set Python path
ENV PATH=/home/nonroot/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PORTAL_HOST=0.0.0.0
ENV PORTAL_PORT=8000

# Expose port
EXPOSE 8000

# Note: HEALTHCHECK with curl not available in distroless
# Use container orchestrator health checks instead (k8s probes, etc.)

# Run the server
CMD ["python", "-m", "portal.web"]
