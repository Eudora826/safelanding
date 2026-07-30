from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .data_store import ROOT, add_user_report, delete_user_report, init_database, load_database, update_case, update_user_report
from .retrieval import retrieve

STATIC_DIR = ROOT / "static"


class SafeLandingHandler(BaseHTTPRequestHandler):
    server_version = "SafeLandingHTTP/0.1"

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        db = load_database()
        if path == "/api/health":
            self._send_json({"status": "ok"})
        elif path == "/api/cases":
            self._send_json(db["cases"])
        elif path == "/api/patterns":
            self._send_json(db["patterns"])
        elif path == "/api/knowledge-gaps":
            self._send_json(db["knowledge_gaps"])
        elif path == "/api/reports":
            self._send_json(db["user_reports"])
        elif path in {"/", "/index.html"}:
            self._send_static("index.html", "text/html; charset=utf-8")
        elif path in {"/admin", "/admin.html"}:
            self._send_static("admin.html", "text/html; charset=utf-8")
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        if path == "/api/retrieve":
            message = str(payload.get("message", "")).strip()
            if not message:
                self._send_json({"error": "message is required"}, 400)
                return
            self._send_json(retrieve(message, payload.get("top_n", 3)))
        elif path == "/api/reports":
            self._send_json(add_user_report(payload), 201)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        if path.startswith("/api/reports/"):
            report_id = path.rsplit("/", 1)[-1]
            updated = update_user_report(report_id, payload)
            if updated is None:
                self._send_json({"error": "Report not found"}, 404)
                return
            self._send_json(updated)
        elif path.startswith("/api/cases/"):
            case_id = path.rsplit("/", 1)[-1]
            updated = update_case(case_id, payload)
            if updated is None:
                self._send_json({"error": "Case not found"}, 404)
                return
            self._send_json(updated)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/reports/"):
            report_id = path.rsplit("/", 1)[-1]
            if not delete_user_report(report_id):
                self._send_json({"error": "Report not found"}, 404)
                return
            self._send_json({"deleted": True, "Report_ID": report_id})
        else:
            self._send_json({"error": "Not found"}, 404)

    def _send_static(self, filename: str, content_type: str) -> None:
        path = STATIC_DIR / filename
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def main() -> None:
    init_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), SafeLandingHandler)
    print("SafeLanding API running at http://127.0.0.1:8000")
    server.serve_forever()


if __name__ == "__main__":
    main()
