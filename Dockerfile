# Stage 1: Build
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies if needed, then python packages
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Final Image
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application files
COPY . .

# Add python packages to PATH
ENV PATH=/root/.local/bin:$PATH

# Define entrypoint to run the CLI directly
ENTRYPOINT ["python", "src/apiscanner/cli.py"]

# Default command if none provided
CMD ["--help"]
