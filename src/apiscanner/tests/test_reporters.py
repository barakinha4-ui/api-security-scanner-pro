import json
from reports.reporter import JSONReporter
from core.models import ScanResult, Finding

def test_json_reporter_generation(tmp_path):
    # Dummy mock data for injection testing
    result = ScanResult(
        target="https://api.testbed.io",
        duration=1.45,
        findings=[
            Finding(title="Insecure Storage", description="Test context", severity="LOW", endpoint="/api/v1", method="GET", confirmed=True)
        ],
        technologies=["Express.js"]
    )
    
    report_file = tmp_path / "test_report.json"
    reporter = JSONReporter()
    reporter.generate(result, str(report_file), encrypt=False)
    
    assert report_file.exists()
    
    with open(report_file, "r") as f:
        data = json.load(f)
        
    assert data["target"] == "https://api.testbed.io"
    assert data["duration_seconds"] == 1.45
    assert len(data["findings"]) == 1
    assert "Express.js" in data["technologies"]
