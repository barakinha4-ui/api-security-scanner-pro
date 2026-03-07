import pytest
import os
import time
import json
from jose import jwt
import uuid
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Set Env vars for testing
os.environ["SUPABASE_JWT_SECRET"] = "test-secret"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"

from security_shield import SecurityShieldMiddleware, JWTPayload, is_internal_ip

# Setup base FastAPI
app = FastAPI()
app.add_middleware(SecurityShieldMiddleware)

@app.post("/api/scan")
async def dummy_scan(target: dict):
    return {"status": "ok"}

@app.get("/api/other")
async def dummy_other():
    return {"status": "ok"}

client = TestClient(app)

# ==========================================
# TEST 1: INTERNAL IP BLOCK (SSRF)
# ==========================================
@pytest.mark.parametrize("bad_ip", [
    "127.0.0.1",
    "10.0.0.5",
    "172.16.50.1",
    "192.168.1.100",
    "169.254.0.0",
    "100.64.0.5", # Carrier-grade NAT (RFC6598)
    "169.254.169.254" # AWS Metadata
])
def test_ssrf_protection_blocks_private(bad_ip):
    # Direct IP tests to ensure is_internal_ip explicitly tracks these ranges
    assert is_internal_ip(bad_ip) is True

    # End-to-end simulation
    with patch("socket.gethostbyname", return_value=bad_ip):
        # We test hitting a domain that resolves to bad_ip
        response = client.post("/api/scan", json={"target": f"http://malicious.com"})
        
        assert response.status_code == 403
        assert "SSRF protected target" in response.text

# ==========================================
# TEST 2: RATE LIMIT REACHED (REDIS MOCK)
# ==========================================
@patch("security_shield.redis_client.pipeline")
def test_rate_limiting_exceeded(mock_pipeline):
    # Arrange: Mock Redis pipeline logic returning zcard >= 100
    mock_pipe = MagicMock()
    
    # We await pipeline.execute(), so return a future pointing to the results tuple
    # Result tuple for [zremrangebyscore, zcard, zadd, expire] -> [0, 100, 1, True]
    import asyncio
    future = asyncio.Future()
    future.set_result((0, 100, 1, True)) 
    mock_pipe.execute.return_value = future
    
    # When the middleware calls pipeline(), it gets our mock
    mock_pipeline.return_value = mock_pipe

    response = client.get("/api/other")
    
    assert response.status_code == 429
    data = response.json()
    
    assert data["error"] == "rate_limit_exceeded"
    assert data["retry_after"] == 60
    assert response.headers["Retry-After"] == "60"

# ==========================================
# TEST 3: JWT EXPIRED
# ==========================================
def test_jwt_payload_class_expired():
    # Test our Pydantic validation directly
    past_time = int(time.time()) - 3600 # 1 hour ago
    payload = JWTPayload(sub=uuid.uuid4(), exp=past_time, roles=["admin"])
    
    assert payload.is_valid() is False

def test_jwt_payload_class_valid():
    future_time = int(time.time()) + 3600 # Next hour
    payload = JWTPayload(sub=uuid.uuid4(), exp=future_time, roles=["admin"])
    
    assert payload.is_valid() is True

@patch("security_shield.redis_client.pipeline")
def test_jwt_expired_endpoint_rejection(mock_pipeline):
    # Allow redis to pass
    mock_pipe = MagicMock()
    import asyncio
    future = asyncio.Future()
    future.set_result((0, 1, 1, True)) 
    mock_pipe.execute.return_value = future
    mock_pipeline.return_value = mock_pipe

    # Generate Expired Token manually
    payload = {"sub": str(uuid.uuid4()), "role": ["user"], "exp": int(time.time()) - 30}
    token = jwt.encode(payload, "test-secret", algorithm="HS256")
    
    # Send request with expired Bearer
    response = client.get("/api/other", headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 401
    assert "JWT is expired" in response.text
