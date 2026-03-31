"""Minimal web frontend/backend for AI Safety Guardrails."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .ethical_framework import Action, Domain
from .pipeline import SafetyPipeline

_MAX_BODY_BYTES = 1024 * 1024

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AI Safety Guardrails</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.4; }
    h1 { margin-bottom: 0.2rem; }
    .muted { color: #555; margin-top: 0; }
    form { display: grid; gap: 0.75rem; margin-top: 1rem; }
    label { font-weight: 600; display: grid; gap: 0.25rem; }
    input, select, textarea, button { font: inherit; padding: 0.5rem; }
    textarea { min-height: 90px; }
    button { cursor: pointer; width: fit-content; }
    pre { background: #f6f8fa; border: 1px solid #ddd; padding: 0.75rem; overflow: auto; }
  </style>
</head>
<body>
  <h1>AI Safety Guardrails</h1>
  <p class="muted">Evaluate actions with the SafetyPipeline and view verdicts instantly.</p>
  <form id="evaluate-form">
    <label>Action ID <input id="action_id" value="web-action-001" required /></label>
    <label>Actor ID <input id="actor_id" value="web-user-001" required /></label>
    <label>Domain
      <select id="domain">
        <option value="financial_trading">Financial Trading</option>
        <option value="gaming">Gaming</option>
        <option value="business">Business</option>
        <option value="healthcare">Healthcare</option>
        <option value="social_platform">Social Platform</option>
        <option value="general">General</option>
      </select>
    </label>
    <label>Action Type <input id="action_type" value="place_order" required /></label>
    <label>Parameters (JSON object)
      <textarea id="parameters">{ "front_run": true }</textarea>
    </label>
    <button type="submit">Evaluate</button>
  </form>
  <h2>Result</h2>
  <pre id="result">Submit an action to see the evaluation.</pre>
  <script>
    const form = document.getElementById("evaluate-form");
    const resultEl = document.getElementById("result");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      let parameters;
      try {
        parameters = JSON.parse(document.getElementById("parameters").value || "{}");
      } catch (err) {
        resultEl.textContent = "Invalid JSON in parameters: " + err.message;
        return;
      }

      const payload = {
        action_id: document.getElementById("action_id").value,
        actor_id: document.getElementById("actor_id").value,
        domain: document.getElementById("domain").value,
        action_type: document.getElementById("action_type").value,
        parameters: parameters
      };

      try {
        const response = await fetch("/api/evaluate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        resultEl.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        resultEl.textContent = "Request failed: " + err.message;
      }
    });
  </script>
</body>
</html>
"""


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _parse_domain(raw_domain: str) -> Domain:
    try:
        return Domain(raw_domain)
    except ValueError as exc:
        valid = ", ".join(d.value for d in Domain)
        raise ValueError(f"Invalid domain '{raw_domain}'. Valid values: {valid}.") from exc


def build_action_from_payload(payload: dict[str, Any]) -> Action:
    action_id = str(payload.get("action_id") or "").strip()
    action_type = str(payload.get("action_type") or "").strip()
    actor_id = str(payload.get("actor_id") or "").strip()
    domain_value = str(payload.get("domain") or "").strip()

    if not action_id:
        raise ValueError("action_id is required.")
    if not action_type:
        raise ValueError("action_type is required.")
    if not actor_id:
        raise ValueError("actor_id is required.")
    if not domain_value:
        raise ValueError("domain is required.")

    parameters = payload.get("parameters", {})
    context = payload.get("context", {})
    metadata = payload.get("metadata", {})
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be a JSON object.")
    if not isinstance(context, dict):
        raise ValueError("context must be a JSON object.")
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object.")

    return Action(
        action_id=action_id,
        domain=_parse_domain(domain_value),
        action_type=action_type,
        parameters=parameters,
        actor_id=actor_id,
        context=context,
        metadata=metadata,
    )


def evaluate_payload(payload: dict[str, Any], pipeline: SafetyPipeline) -> dict[str, Any]:
    action = build_action_from_payload(payload)
    result = pipeline.evaluate(action)
    return _json_safe(asdict(result))


def create_handler(pipeline: SafetyPipeline):
    class GuardrailsRequestHandler(BaseHTTPRequestHandler):
        def _send_json(self, status_code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, status_code: int, html: str) -> None:
            raw = html.encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/":
                self._send_html(200, _INDEX_HTML)
                return
            if path == "/api/domains":
                self._send_json(200, {"domains": [d.value for d in Domain]})
                return
            self._send_json(404, {"error": "Not found."})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path != "/api/evaluate":
                self._send_json(404, {"error": "Not found."})
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(400, {"error": "Request body is required."})
                return
            if content_length > _MAX_BODY_BYTES:
                self._send_json(413, {"error": "Request body too large."})
                return

            try:
                payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("JSON payload must be an object.")
                evaluation = evaluate_payload(payload, pipeline)
                self._send_json(200, evaluation)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
            except Exception:  # pragma: no cover
                self._send_json(500, {"error": "Internal server error."})

    return GuardrailsRequestHandler


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    pipeline = SafetyPipeline()
    handler = create_handler(pipeline)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"AI Safety Guardrails web app running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
