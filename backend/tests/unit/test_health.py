"""Unit tests for health check endpoint and Lambda routing foundation."""

import json
from backend.src.handlers.analyze import handler
from backend.src.handlers.health import health_handler


class TestHealthEndpoint:
    """Test health check behavior and information exposure controls."""

    def test_health_handler_returns_200_and_status_ok(self):
        resp = health_handler()
        assert resp["statusCode"] == 200
        assert "headers" in resp
        assert resp["headers"]["Content-Type"] == "application/json"
        assert resp["headers"]["Access-Control-Allow-Origin"] == "*"

        body = json.loads(resp["body"])
        assert body == {"status": "ok"}

    def test_health_handler_does_not_leak_sensitive_metadata(self):
        resp = health_handler()
        raw_body = resp["body"]
        # Ensure zero leakage of AWS/system/infrastructure terms
        forbidden_terms = [
            "aws",
            "account",
            "secret",
            "key",
            "password",
            "token",
            "version",
            "path",
            "traceback",
            "exception",
        ]
        for term in forbidden_terms:
            assert term not in raw_body.lower()


class TestHandlerRoutingFoundation:
    """Test Lambda request routing, CORS preflight, and validation integration."""

    def test_handler_routes_get_health(self):
        event = {
            "httpMethod": "GET",
            "path": "/health",
        }
        resp = handler(event)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["status"] == "ok"

    def test_handler_routes_options_cors_preflight(self):
        event = {
            "httpMethod": "OPTIONS",
            "path": "/analyze",
        }
        resp = handler(event)
        assert resp["statusCode"] == 200
        assert "Access-Control-Allow-Methods" in resp["headers"]
        assert "OPTIONS" in resp["headers"]["Access-Control-Allow-Methods"]

    def test_handler_routes_post_analyze_valid_payload(self):
        event = {
            "httpMethod": "POST",
            "path": "/analyze",
            "body": json.dumps({"message": "Suspicious SMS claiming my debit card is locked."}),
        }
        resp = handler(event)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["status"] == "received"
        assert body["length"] > 0

    def test_handler_routes_post_analyze_invalid_payload(self):
        event = {
            "httpMethod": "POST",
            "path": "/analyze",
            "body": json.dumps({"message": "   "}),  # whitespace only
        }
        resp = handler(event)
        assert resp["statusCode"] == 400
        body = json.loads(resp["body"])
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert len(body["error"]["details"]) > 0
        assert body["error"]["details"][0]["field"] == "message"

    def test_handler_method_not_allowed(self):
        event = {
            "httpMethod": "DELETE",
            "path": "/analyze",
        }
        resp = handler(event)
        assert resp["statusCode"] == 405
        body = json.loads(resp["body"])
        assert body["error"]["code"] == "METHOD_NOT_ALLOWED"
