FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    krb5-user \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-osd \
    libreoffice \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set working directory
WORKDIR /manspider

# Copy project files
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY man_spider ./man_spider

# Install the package with uv
RUN uv sync --frozen --no-dev

ENTRYPOINT [".venv/bin/manspider"]
