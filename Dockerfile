
FROM debian:bookworm-slim AS base

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies & WPScan
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Runtime dependencies for WPScan
    ruby \
    ruby-bundler \
    libcurl4 \
    libxml2 \
    libxslt1.1 \
    zlib1g \
    # Build dependencies for WPScan (will be removed)
    ruby-dev \
    build-essential \
    libcurl4-openssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    # Common tools
    curl \
    ca-certificates \
    # Install WPScan via gem
    && gem install wpscan --no-document \
    # Purge build dependencies to lighten the image
    && apt-get purge -y --auto-remove \
        ruby-dev \
        build-essential \
        libcurl4-openssl-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
    # Clean up APT cache
    && rm -rf /var/lib/apt/lists/* \
    # Verify WPScan works
    && wpscan --version

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Prepare application
WORKDIR /app

# Copy dependency files first
COPY pyproject.toml uv.lock* ./

# Install Python dependencies
RUN uv sync --no-dev --no-install-project \
    && uv cache clean

# Copy source code
COPY app/ ./app/
COPY README.md ./

# Install the project
RUN uv sync --no-dev \
    && uv cache clean

# Configuration
ENV API_HOST=0.0.0.0
ENV API_PORT=8000
ENV WPSCAN_PATH=wpscan

EXPOSE $API_PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${API_PORT}/health || exit 1

# Launch
CMD exec uv run uvicorn app.main:app --host ${API_HOST} --port ${API_PORT}
