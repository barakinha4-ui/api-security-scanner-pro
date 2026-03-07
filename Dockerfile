# Stage 1: Build
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies if needed, then python packages
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Final Image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for WeasyPrint + curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application files
COPY . .

# Add python packages to PATH
ENV PATH=/root/.local/bin:$PATH

# Use CMD instead of ENTRYPOINT to allow docker-compose to override easily
CMD ["python", "src/apiscanner/cli.py", "--help"]
