import pytest
from core.oast import OASTIntegration

@pytest.mark.asyncio
async def test_oast_setup_session():
    oast = OASTIntegration(engine=None)
    success = await oast.setup_session()
    
    assert success is True
    assert oast.correlation_id is not None
    assert oast.secret_key is not None
    assert oast.oast_domain.endswith(".oast.fun")

def test_oast_generate_payloads():
    oast = OASTIntegration(engine=None)
    oast.oast_domain = "abc.oast.fun"
    
    # Ensure payloads properly bind the dynamic domain
    payloads = oast.generate_payloads("rce")
    assert any("curl abc.oast.fun" in p for p in payloads)

@pytest.mark.asyncio
async def test_oast_check_confirmation(monkeypatch):
    from core.oast import Interaction
    
    # Mocking poll to return a fake interaction
    async def mock_poll():
        return [Interaction(correlation_id="123", type="DNS", client_ip="1.1.1.1", timestamp="123", raw_request="GET /?marker=secret_marker HTTP/1.1")]
        
    oast = OASTIntegration(engine=None)
    monkeypatch.setattr(oast, "poll", mock_poll)
    
    # Reduced timeout to run test faster
    verified = await oast.verify_interaction("secret_marker", timeout=1)
    assert verified is True
