# ==============================================================================
# AGENTATK — Google Cloud Run Container Definition
# Autonomous AI Agent Security Researcher & Vulnerability Verification Engine
# ==============================================================================

FROM python:3.11-slim

# Set non-interactive and unbuffered output for real-time Cloud Run logging
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml /app/
COPY README.md /app/
COPY agentatk/ /app/agentatk/
COPY targets/ /app/targets/
COPY tests/ /app/tests/

# Install AGENTATK and all dependencies
RUN pip install --no-cache-dir -e .

# Expose default Cloud Run port
EXPOSE 8080

# Launch AGENTATK Live Web Visualizer Server on Cloud Run
CMD ["sh", "-c", "uvicorn agentatk.server:app --host 0.0.0.0 --port ${PORT:-8080}"]
