# Kekkai Portal Docker Image
FROM python:3.12-slim

LABEL maintainer="Kademos Labs"
LABEL description="Kekkai Portal - DefectDojo-backed security dashboard"

# Security: Run as non-root user
RUN groupadd -r kekkai && useradd -r -g kekkai kekkai

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY src/ /app/src/
COPY pyproject.toml /app/

# Install the package
RUN pip install --no-cache-dir -e .

# Create data directories
RUN mkdir -p /var/lib/kekkai-portal/uploads && \
    chown -R kekkai:kekkai /var/lib/kekkai-portal

# Copy static files for nginx
RUN mkdir -p /var/www/static && \
    cp -r /app/src/portal/static/* /var/www/static/ && \
    chown -R kekkai:kekkai /var/www/static

# Switch to non-root user
USER kekkai

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PORTAL_HOST=0.0.0.0
ENV PORTAL_PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run the server
CMD ["python", "-m", "portal.web"]
