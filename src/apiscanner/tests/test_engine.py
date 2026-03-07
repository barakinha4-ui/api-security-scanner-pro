import pytest
import respx
from core.engine import AsyncEngine

@pytest.mark.asyncio
@respx.mock
async def test_engine_request_success():
    respx.get("https://api.example.com/test").respond(status_code=200, json={"ok": True})
    
    engine = AsyncEngine()
    async with engine:
        response = await engine.get("https://api.example.com/test")
        
    assert response.status == 200
    assert response.json() == {"ok": True}
    assert engine.request_count == 1

@pytest.mark.asyncio
async def test_engine_ssrf_protection():
    engine = AsyncEngine(allow_internal=False)
    # 127.0.0.1 is blocked natively unless allow_internal=True
    response = await engine.get("http://127.0.0.1/admin")
    
    assert response.error == "SSRF_PROTECTION_TRIGGERED"

@pytest.mark.asyncio
@respx.mock
async def test_engine_waf_detect():
    # Mocks a response containing WAF signatures
    respx.get("https://api.example.com/").respond(
        status_code=200,  # Engine currently evaluates WAF passively on OK responses
        headers={"cf-ray": "123456789", "server": "cloudflare"}
    )
    
    engine = AsyncEngine()
    async with engine:
        await engine.get("https://api.example.com/")
        
    assert engine.waf_name == "Cloudflare"
    assert engine.waf_confidence == 80.0
