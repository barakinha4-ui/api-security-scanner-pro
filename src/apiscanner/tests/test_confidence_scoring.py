"""
tests/test_confidence_scoring.py — Unit tests for the finding confidence engine.
"""
import pytest
from core.models import Finding

def test_confidence_calculation_signals():
    """Test that multiple signals correctly increment the confidence score."""
    f = Finding(vuln_type="Test Vuln")
    
    # Single signal
    score = f.calculate_confidence({"status_match": True})
    assert score == 0.2
    assert f.status_label == "❓ Unconfirmed"

    # Multiple signals
    score = f.calculate_confidence({
        "status_match": True, 
        "pattern_match": True, 
        "time_based": True
    })
    # 0.2 + 0.3 + 0.25 = 0.75
    assert score == 0.75
    assert f.status_label == "⚠️ Probable"

def test_oast_boost():
    """Test that OAST callbacks significantly boost confidence."""
    f = Finding(vuln_type="SSRF")
    
    score = f.calculate_confidence({
        "status_match": True,
        "oast_callback": True
    })
    # 0.2 + 0.5 = 0.7
    assert score == 0.7
    
    # Adding pattern match should push it to Confirmed
    score = f.calculate_confidence({
        "status_match": True,
        "oast_callback": True,
        "pattern_match": True
    })
    # 0.2 + 0.5 + 0.3 = 1.0
    assert score == 1.0
    assert f.status_label == "✅ Confirmed"

def test_confidence_cap():
    """Test that confidence doesn't exceed 1.0."""
    f = Finding(vuln_type="Critical SQLi")
    score = f.calculate_confidence({
        "status_match": True,
        "pattern_match": True,
        "time_based": True,
        "boolean_based": True,
        "oast_callback": True
    })
    # Sum is > 1.0, should be capped at 1.0
    assert score == 1.0
    assert f.confidence_score == 1.0
