"""Runner-local mock and sample servers for the real engine's self-test."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

from .mock import server


def serve(directory, guarded):
    source = Path(__file__).resolve().parents[1] / "sample-app/app.py"
    spec = importlib.util.spec_from_file_location("sample_app", source)
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)

    class Handler(app.App):
        def log_message(self, template, *args):
            with (directory / f"app-{self.server.server_port}.log").open("a") as stream:
                stream.write(template % args + "\n")

    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    servers = [ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in (8080, 8081)]
    for instance in servers:
        threading.Thread(target=instance.serve_forever, daemon=True).start()
    try:
        with server(directory) as mock:
            # The bundled proxy starts asynchronously; a scripted model can outrun it.
            url = "'http://host.docker.internal:8080/lookup?id=0%20OR%201=1'"
            command = "curl --fail-with-body -sS --retry 12 --retry-connrefused --retry-delay 1 --retry-max-time 15 --max-time 3 " + url
            if not guarded:
                # Try the runner alias directly if the bundled interception proxy cannot resolve it.
                command += " || curl -fsS --noproxy host.docker.internal --max-time 10 " + url
            mock.guard_commands = [command]
            if guarded:
                mock.guard_commands.append("curl -sS --max-time 8 -w '\\nHTTP=%{http_code}\\n' http://host.docker.internal:8081/lookup?id=1")
            mock.finding = {
                "title": "Seeded SQL injection in the local sample",
                "description": "Scripted integration fixture: user input is concatenated into a SQLite query.",
                "impact": "The seeded record can be read despite selecting a nonexistent identifier.",
                "target": "http://localhost:8080", "endpoint": "/lookup", "method": "GET", "cwe": "CWE-89",
                "technical_analysis": "The id query parameter reaches database.execute without parameter binding.",
                "poc_description": "Request id=0 OR 1=1 and observe the seeded record.",
                "poc_script_code": command,
                "remediation_steps": "Bind the identifier as a SQL parameter.",
                "evidence": "The scripted request returns seeded demo record. This is a test fixture, not an autonomous assessment.",
                "assumptions": "The deliberately vulnerable sample is running on the isolated CI runner.",
                "counterevidence": "Only synthetic data exists; no real service or user data is assessed.",
                "confidence": "high", "severity_change_conditions": "Parameter binding would remove this fixture vulnerability.",
                "fix_effort": "low",
                "cvss_breakdown": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                                   "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "N"},
                "code_locations": [{"file": "sample-app/app.py", "start_line": 15, "end_line": 15}],
            }
            (directory / "api-base.txt").write_text(mock.origin + "/v1")
            stopped.wait()
    finally:
        for instance in servers:
            instance.shutdown()
            instance.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("start", "serve", "stop", "verify"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--guard", choices=("on", "off"), default="off")
    parser.add_argument("--exit-code")
    parser.add_argument("--expected-exit", default="0")
    parser.add_argument("--sarif", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    pidfile = directory / "pid"
    if args.operation == "serve":
        serve(directory, args.guard == "on")
    elif args.operation == "start":
        with (directory / "server.log").open("w") as log:
            child = subprocess.Popen([sys.executable, "-m", "demo.hosted", "serve", "--directory", str(directory),
                                      "--guard", args.guard], stdout=log, stderr=log, start_new_session=True)
        pidfile.write_text(str(child.pid))
        for _ in range(100):
            if (directory / "api-base.txt").exists():
                break
            if child.poll() is not None:
                raise RuntimeError("Local servers failed to start; see server.log")
            time.sleep(.1)
        else:
            os.killpg(child.pid, signal.SIGTERM)
            raise RuntimeError("Local servers did not become ready")
        with open(os.environ["GITHUB_ENV"], "a") as stream:
            stream.write("MOCK_API_BASE=" + (directory / "api-base.txt").read_text() + "\n")
        subprocess.run(["docker", "version"], check=True)
    elif args.operation == "stop":
        if pidfile.exists():
            try:
                os.killpg(int(pidfile.read_text()), signal.SIGTERM)
            except ProcessLookupError:
                pass
    else:
        assert args.exit_code == args.expected_exit, f"Engine exit {args.exit_code}; expected {args.expected_exit}"
        sarif = json.loads(args.sarif.read_text())
        findings = [r for run in sarif["runs"] for r in run["results"] if r.get("kind", "fail") == "fail"]
        assert len(findings) == 1 and findings[0]["properties"]["strix"]["severity"] == "high", findings
        assert "GET /lookup?id=0%20OR%201=1" in (directory / "app-8080.log").read_text(), "Sandbox did not reach the runner app"
        if args.guard == "on":
            log = args.sarif.parents[2] / "egress-guard.jsonl"
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            assert any(row.get("action") == "block" and row.get("port") == 8081 for row in rows), "Excluded request was not logged"
            assert not (directory / "app-8081.log").exists(), "Excluded app received a request"
        (directory / "proof.json").write_text(json.dumps({"exit_code": args.exit_code, "high": 1, "guard": args.guard, "app_reached": True}))
        print("Verified: one high fixture finding, expected exit, and sandbox access to the runner app.")


if __name__ == "__main__":
    main()
