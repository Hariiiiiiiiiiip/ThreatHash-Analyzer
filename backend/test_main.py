import pytest
from fastapi.testclient import TestClient
from main import app, build_empty_report

client = TestClient(app)

def test_scan_hash_missing_api_key(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "")
    # In FastAPI, the os.getenv is evaluated at startup/import, so monkeypatching os.getenv for the module is needed
    import main
    monkeypatch.setattr(main, "VT_API_KEY", None)
    
    response = client.get("/api/scan/12345")
    assert response.status_code == 500
    assert "VT_API_KEY is not configured" in response.json()["detail"]

def test_build_empty_report():
    report = build_empty_report("test_hash")
    assert report["sha256"] == "test_hash"
    assert report["detectionRatio"] == "0/72"
    assert report["riskScore"] == "Safe"

class MockResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP Error {self.status_code}")

@pytest.mark.asyncio
async def test_scan_hash_success(monkeypatch):
    import main
    monkeypatch.setattr(main, "VT_API_KEY", "dummy_key")
    
    async def mock_get(*args, **kwargs):
        return MockResponse(200, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 60,
                        "suspicious": 0,
                        "undetected": 10
                    },
                    "last_analysis_results": {
                        "Engine1": {"category": "malicious", "result": "Trojan.Test"},
                        "Engine2": {"category": "undetected", "result": None}
                    }
                }
            }
        })
    
    # Mock httpx.AsyncClient.get
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
    
    response = client.get("/api/scan/dummyhash")
    assert response.status_code == 200
    data = response.json()
    assert data["sha256"] == "dummyhash"
    assert data["riskScore"] == "Malware"
    assert data["severity"] == "malware"
    assert data["detectionRatio"] == "60/70"
    
@pytest.mark.asyncio
async def test_scan_hash_not_found(monkeypatch):
    import main
    monkeypatch.setattr(main, "VT_API_KEY", "dummy_key")
    
    async def mock_get(*args, **kwargs):
        return MockResponse(404)
        
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
    
    response = client.get("/api/scan/unknownhash")
    assert response.status_code == 200
    data = response.json()
    assert data["riskScore"] == "Safe"
    assert data["detectionRatio"] == "0/72"
