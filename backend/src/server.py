"""Local AWS API Gateway & Lambda emulation server for ScamShield AI.

Runs the production AWS Lambda handler over HTTP (default port 8000),
providing an identical execution environment to AWS API Gateway invoking
the ScamShield AI Lambda function.
"""

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Ensure workspace root is in sys.path so backend package imports work
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.src.handlers.analyze import handler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scamshield.server")

DEFAULT_PORT = int(os.environ.get("PORT", "8000"))
DEFAULT_HOST = os.environ.get("HOST", "0.0.0.0")


class LambdaProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler emulating AWS API Gateway Lambda proxy integration."""

    def _build_lambda_event(self, body_bytes: bytes) -> dict:
        parsed_url = urlparse(self.path)
        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}

        headers_dict = {k.lower(): v for k, v in self.headers.items()}
        body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

        return {
            "resource": parsed_url.path,
            "path": parsed_url.path,
            "httpMethod": self.command,
            "headers": headers_dict,
            "queryStringParameters": query_params if query_params else None,
            "body": body_str if body_str else None,
            "isBase64Encoded": False,
            "requestContext": {
                "accountId": "123456789012",
                "apiId": "scamshield-local",
                "stage": "prod",
                "httpMethod": self.command,
                "path": parsed_url.path,
                "identity": {
                    "sourceIp": self.client_address[0],
                },
            },
        }

    def _handle_request(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""

        event = self._build_lambda_event(body_bytes)
        logger.info(f"API Gateway >> {self.command} {self.path} (payload: {content_length} bytes)")

        try:
            response = handler(event, context=None)
        except Exception as exc:
            logger.exception("Unexpected exception in Lambda handler")
            response = {
                "statusCode": 500,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                },
                "body": json.dumps({"error": {"code": "INTERNAL_ERROR", "message": str(exc)}}),
            }

        status_code = response.get("statusCode", 200)
        headers = response.get("headers", {})
        body = response.get("body", "")

        self.send_response(status_code)
        for header_key, header_val in headers.items():
            self.send_header(header_key, header_val)
        self.end_headers()

        if isinstance(body, str):
            self.wfile.write(body.encode("utf-8"))
        elif isinstance(body, bytes):
            self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self._handle_request()

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def log_message(self, format, *args):
        # Suppress default stdio access logging to avoid noise
        return


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    server_address = (host, port)
    httpd = HTTPServer(server_address, LambdaProxyHandler)
    logger.info(f"ScamShield AI Serverless Emulator running at http://{host}:{port}")
    logger.info(f"  POST http://{host}:{port}/analyze  -> Lambda: analyze.handler")
    logger.info(f"  GET  http://{host}:{port}/health   -> Lambda: health.handler")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down emulator server...")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
