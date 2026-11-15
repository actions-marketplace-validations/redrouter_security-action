"""Local catalog, scripted Chat Completions, and delivery capture server."""
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODEL = "demo-model"


class MockServer(ThreadingHTTPServer):
    def __init__(self, directory):
        super().__init__(("127.0.0.1", 0), Handler)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "requests.jsonl").write_text("")
        self.requests = []
        self.comments = []
        self.catalog_failure = False
        self.guard_commands = []
        self.finding = None
        self.lock = threading.Lock()

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.server_port}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PATCH(self):
        self.handle_request()

    def handle_request(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw) if raw else None
        record = {"method": self.command, "path": self.path, "body": body}
        with self.server.lock:
            self.server.requests.append(record)
            with (self.server.directory / "requests.jsonl").open("a") as out:
                out.write(json.dumps(record) + "\n")
        if self.path == "/api/catalog":
            if self.server.catalog_failure:
                self.reply({"error": "catalog unavailable"}, 503)
                return
            self.reply({"revision": "local-demo", "environment": "local", "api_base_url": self.server.origin + "/v1", "models": [{
                "id": MODEL, "display_name": "Scripted local model", "available": True,
                "capabilities": {"tools": True}, "context_tokens": 131072, "max_output_tokens": 8192,
                "pricing": {"source": "fixture", "input_usd_per_mtok": "0.25", "cached_input_usd_per_mtok": "0.10", "output_usd_per_mtok": "1.00"},
            }], "limits": {"requests_per_minute": 60, "max_concurrency": 5, "daily_spend_usd": "3"}})
        elif self.path == "/v1/chat/completions":
            self.completion(body)
        elif self.path == "/slack":
            (self.server.directory / "slack.json").write_text(json.dumps(body, indent=2) + "\n")
            self.reply({"ok": True})
        elif self.path.endswith("/code-scanning/sarifs"):
            self.reply({"id": "local-sarif", "url": self.server.origin + "/sarif/local"}, 202)
        elif "/issues/" in self.path and "/comments" in self.path:
            if self.command == "GET":
                self.reply(self.server.comments)
            else:
                item = {"id": 1, "body": body["body"], "user": {"type": "Bot"}}
                self.server.comments[:] = [item]
                (self.server.directory / "pr-comment.md").write_text(body["body"])
                self.reply(item, 200 if self.command == "PATCH" else 201)
        else:
            self.reply({"error": "Unexpected mock request"}, 404)

    def reply(self, body, status=200):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def completion(self, body):
        messages = body.get("messages", [])
        tools = [t.get("function", {}).get("name") for t in body.get("tools", [])]
        previous = [m.get("name") for m in messages if m.get("role") == "tool"]
        final = {"executive_summary": "Local scripted fixture completed; this is an integration demo, not a security assessment.",
                 "methodology": "Scripted responses against a local fixture.",
                 "technical_analysis": "No autonomous vulnerability validation was performed.",
                 "recommendations": "Use parameterized queries and constrain download paths to the public directory."}
        call = None
        if self.server.guard_commands and "exec_command" in tools:
            call = ("exec_command", {"cmd": self.server.guard_commands.pop(0), "yield_time_ms": 20000})
        elif self.server.finding and "create_vulnerability_report" in tools:
            call = ("create_vulnerability_report", self.server.finding)
            self.server.finding = None
        elif "demo_read_source" in tools and "demo_read_source" not in previous:
            call = ("demo_read_source", {"path": "sample-app/app.py"})
        elif "demo_report" in tools and "demo_report" not in previous:
            call = ("demo_report", {"high": 1, "medium": 1, "summary": "SQL injection and path traversal in seeded fixture."})
        elif "finish_scan" in tools:
            # The real engine's native terminal tool finalizes the run and SARIF.
            call = ("finish_scan", final)
        message = {"role": "assistant", "content": None if call else json.dumps(final)}
        if call:
            message["tool_calls"] = [{"id": "call_demo_" + str(len(messages)), "type": "function", "function": {"name": call[0], "arguments": json.dumps(call[1])}}]
        finish = "tool_calls" if call else "stop"
        base = {"id": "chatcmpl-local", "created": int(time.time()), "model": body.get("model", MODEL)}
        usage = {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140}
        if not body.get("stream"):
            self.reply(base | {"object": "chat.completion", "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        delta = dict(message)
        if call:
            delta["tool_calls"] = [dict(message["tool_calls"][0], index=0)]
        for item in (base | {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                     base | {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": finish}], "usage": usage}):
            self.wfile.write(("data: " + json.dumps(item) + "\n\n").encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


@contextmanager
def server(directory):
    instance = MockServer(directory)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join()
