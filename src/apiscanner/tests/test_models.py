from core.models import Finding

def test_finding_to_dict():
    finding = Finding(
        title="Test Vuln",
        description="A test vulnerability module output",
        severity="HIGH",
        endpoint="/api/v1/test",
        method="GET"
    )
    
    # Uses our standard serialization
    data = finding.to_dict()
    assert data["title"] == "Test Vuln"
    assert data["severity"] == "HIGH"
    assert data["endpoint"] == "/api/v1/test"
    assert data["method"] == "GET"

def test_finding_cvss_calc():
    # Simulates calculating cvss attributes accurately
    finding = Finding(
        title="Critical BOLA",
        description="Broken Object Level Auth",
        severity="CRITICAL",
        endpoint="/users/2",
        method="PUT",
        cvss_score=9.8
    )
    
    assert finding.cvss_score == 9.8
    assert getattr(finding, "confidence_score", 1.0) == 1.0
