"""
core/metrics.py — Prometheus Metrics for the API Security Scanner
"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# --- Job Metrics ---
SCANNER_JOBS_TOTAL = Counter(
    "scanner_jobs_total", 
    "Total scans processed by the worker",
    ["status"]
)

SCANNER_ACTIVE_JOBS = Gauge(
    "scanner_active_jobs",
    "Current number of running scan jobs"
)

# --- Phase & Duration Metrics ---
SCAN_PHASE_DURATION = Histogram(
    "scanner_phase_duration_seconds",
    "Duration of each scan phase",
    ["phase"]
)

# --- Finding & Security Metrics ---
SCANNER_FINDINGS_TOTAL = Counter(
    "scanner_findings_total",
    "Total vulnerabilities found by severity",
    ["severity"]
)

RATE_LIMITED_REQS_TOTAL = Counter(
    "rate_limited_requests_total",
    "Total requests blocked or delayed by rate limit",
    ["source"]
)

ACTIVE_SCANS_PER_TARGET = Gauge(
    "active_scans_per_target",
    "Active scan jobs per target host",
    ["target"]
)

# --- Performance Metrics ---
HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "API request latency",
    ["method", "endpoint"]
)
