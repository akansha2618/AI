from fastapi.testclient import TestClient
from backend.app.api.main import app

client = TestClient(app)


def test_dashboard_and_health_are_available():
    page = client.get("/")
    assert page.status_code == 200
    assert "Inspect before you trust." in page.text
    assert client.get("/health").json()["status"] == "healthy"


def test_analyze_endpoint_returns_decision_shape():
    response = client.post("/analyze", json={"user_input": "What is the capital of France?"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "ALLOW"
    assert "request_id" in payload
    assert isinstance(payload["findings"], list)


def test_analyze_rejects_unknown_fields():
    response = client.post("/analyze", json={"user_input": "Hello", "unexpected": True})
    assert response.status_code == 422


def test_response_scan_detects_untrusted_domain():
    response = client.post("/response-scan", json={"request_id": "test", "response_text": "Visit https://attacker.invalid/exfil"})
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["finding"]["category"] == "UNAUTHORIZED_URL"


def test_response_scan_does_not_false_positive_on_empty_canary_setting():
    response = client.post("/response-scan", json={"request_id": "test", "response_text": "A regular response with no configured secret."})
    assert response.status_code == 200
    assert response.json()["safe"] is True


def test_response_scan_rejects_hostname_substring_spoof():
    response = client.post("/response-scan", json={"request_id": "test", "response_text": "https://example.com.attacker.invalid/path"})
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"


def test_response_scan_redacts_canary_value_from_evidence():
    response = client.post("/response-scan", json={"request_id": "test", "response_text": "The secret key is CYBERDESK-SECRET-7F39"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "BLOCK"
    assert "CYBERDESK-SECRET-7F39" not in payload["finding"]["evidence"]


def test_api_key_is_enforced_when_configured(monkeypatch):
    from backend.app.config import settings
    monkeypatch.setattr(settings, "API_KEY", "test-secret-key")
    assert client.get("/api/info").status_code == 401
    response = client.get("/api/info", headers={"X-API-Key": "test-secret-key"})
    assert response.status_code == 200
    assert response.json()["api_key_required"] is True
    monkeypatch.setattr(settings, "API_KEY", "")
