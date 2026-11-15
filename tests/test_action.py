"""Integration checks using the same local mock as the demo."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from demo.cases import ROOT, invoke, prepare, scope_fixture
from demo.mock import server
from redrouter import results
from redrouter.engine import Findings
from redrouter.scope import CODES, Refusal, Scope, check_targets, parse_scope


class ActionTests(unittest.TestCase):
    def setUp(self):
        directory = ROOT / ".cache" / "tests"
        directory.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=directory)
        self.directory = Path(self.temp.name)
        self.context = server(self.directory)
        self.mock = self.context.__enter__()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.context.__exit__, None, None, None)

    def no_model_requests(self):
        self.assertFalse([r for r in self.mock.requests if r["path"] == "/v1/chat/completions"])

    def refusal(self, code):
        env = prepare(self.directory, self.mock.origin, code)
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(outputs["refusal"], code)
        self.assertIn("No model request was made.", (self.directory / "summary.md").read_text())
        self.no_model_requests()

    def test_catalog_fetch_failure(self):
        self.mock.catalog_failure = True
        env = prepare(self.directory, self.mock.origin)
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(outputs["refusal"], "prices-unavailable")
        self.no_model_requests()

    def test_budget_wind_down_wording(self):
        result = results.Result(exit_code=0, complete=True, budget=0.9,
                                findings=Findings(finished=True, estimated_spend="0.82631166"))
        for text in (results.summary(result), results.comment(result), results.slack(result)["text"]):
            self.assertIn("No findings at or above high. The budget cap was reached, so the scan is incomplete.", text)
            self.assertIn("Spent $0.83 of $0.90.", text)
            self.assertNotIn("Pass:", text)
        self.assertEqual(result.outputs()["exit-code"], "0")
        result.findings.estimated_spend = "0.81"
        self.assertIn("scan is incomplete", result.status())
        result.findings.estimated_spend = "0.809"
        self.assertEqual(result.status(), "Pass: no findings at or above high.")

    def test_loopback_instructions(self):
        example = (ROOT / "README.md").read_text().split("```yaml\n", 1)[1].split("```", 1)[0]
        scope = parse_scope(example)
        self.assertIn("host.docker.internal with the same scheme, port and path", scope.instructions())
        for host in ("localhost", "127.0.0.2", "[::1]", "0.0.0.0", "outside.test"):
            with self.subTest(host=host):
                scope.data["in_scope"] = [{"type": "url", "value": f"http://{host}:8080/app"}]
                self.assertEqual("host.docker.internal" in scope.instructions(), host != "outside.test")

    def test_pr_head_cannot_widen_base_scope(self):
        env = prepare(self.directory, self.mock.origin)
        workspace = Path(env["GITHUB_WORKSPACE"])
        scope = scope_fixture()
        scope["in_scope"].append({"type": "url", "value": "https://head-only.example.test"})
        (workspace / ".github/scope.yaml").write_text(json.dumps(scope))
        subprocess.run(["git", "add", ".github/scope.yaml"], cwd=workspace, check=True)
        subprocess.run(["git", "-c", "user.name=RedRouter", "-c", "user.email=support@redrouter.org",
                        "commit", "-qm", "test: widen scope on PR head"], cwd=workspace, check=True)
        env["GITHUB_SHA"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=workspace, text=True).strip()
        event_path = Path(env["GITHUB_EVENT_PATH"])
        event = json.loads(event_path.read_text())
        event["pull_request"]["head"]["sha"] = env["GITHUB_SHA"]
        event_path.write_text(json.dumps(event))
        env["INPUT_TARGETS"] = "https://head-only.example.test"
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(outputs["refusal"], "target-out-of-scope")
        self.no_model_requests()

    def test_guard_start_failure(self):
        env = prepare(self.directory, self.mock.origin)
        env.pop("REDROUTER_DEMO_STUB")
        env["INPUT_EGRESS_GUARD"] = "on"
        binaries = self.directory / "bin"
        binaries.mkdir()
        # Installation succeeds locally; Docker refuses startup. No real Docker.
        for name, body in {"uvx": "exit 0", "docker": 'if [ "$1" = ps ]; then exit 0; fi; exit 1'}.items():
            path = binaries / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)
        env["PATH"] = str(binaries) + ":" + env["PATH"]
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(outputs["exit-code"], "1")
        self.assertIn("Egress guard could not start", (self.directory / "summary.md").read_text())
        self.no_model_requests()

    def test_fork_guard(self):
        env = prepare(self.directory, self.mock.origin)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
        event["pull_request"]["head"]["repo"]["full_name"] = "outside/shop"
        Path(env["GITHUB_EVENT_PATH"]).write_text(json.dumps(event))
        env["INPUT_API_KEY"] = ""
        env["INPUT_MODEL"] = ""
        env["INPUT_SCOPE"] = "absent.yaml"
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(outputs["skipped"], "true")
        self.assertIn("::notice::", result.stdout)
        self.assertEqual(self.mock.requests, [])

    def test_dry_run(self):
        # This also materializes the valid-client fixture with dates around now.
        env = prepare(self.directory, self.mock.origin, "valid-client")
        env.pop("REDROUTER_DEMO_STUB")
        env["INPUT_DRY_RUN"] = "true"
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("uvx --exclude-newer 2026-11-15T00:00:00Z --python 3.12 --from git+https://github.com/usestrix/strix.git@685bbc8138d35fc9fe378ac37ec0d9198b9c46a3", result.stdout)
        self.assertIn("--instruction-file", result.stdout)
        self.assertIn("STRIX_TELEMETRY=false", result.stdout)
        self.assertIn("[REDACTED]", result.stdout)
        self.assertNotIn("local-demo-key", result.stdout)
        self.assertEqual(outputs["refusal"], "")
        self.no_model_requests()

    def engine_exit(self, code):
        env = prepare(self.directory, self.mock.origin)
        env["REDROUTER_STUB_EXIT"] = str(code)
        result, outputs = invoke(env, self.directory)
        self.assertEqual(result.returncode, code, result.stdout)
        self.assertEqual(outputs["exit-code"], str(code))
        self.assertEqual(outputs["findings-total"], "2" if code == 2 else "0")
        self.assertTrue((self.directory / "summary.md").exists())
        self.assertTrue((self.directory / "pr-comment.md").exists())
        self.assertTrue((self.directory / "slack.json").exists())

    def test_spec_parsing_cannot_hide_servers(self):
        scope = Scope(scope_fixture(), {})
        path = self.directory / "api.yaml"
        raw = 'openapi: "3.0.3"\nservers: [{url: http://localhost:8080}]\npaths: {/ping: {get: {responses: {200: {description: OK}}}}}\n'
        path.write_text(raw)
        check_targets(scope, ["./"], self.directory, "acme/shop")
        path.write_text(raw.replace("http://localhost:8080", "https://outside.test") + 'x: !Ref y\n')
        with self.assertRaises(Refusal) as error:
            check_targets(scope, ["./"], self.directory, "acme/shop")
        self.assertEqual(error.exception.code, "openapi-server-out-of-scope")
        path.unlink()
        (self.directory / "api.json").write_text(json.dumps({"openapi": "3.0.3", "servers": [{"url": "https://outside.test"}]}, indent="\t"))
        with self.assertRaises(Refusal) as error:
            check_targets(scope, ["./"], self.directory, "acme/shop")
        self.assertEqual(error.exception.code, "openapi-server-out-of-scope")

    def test_spec_server_templates_are_checked(self):
        scope = Scope(scope_fixture(), {})
        path = self.directory / "api.json"
        server = {"url": "http://localhost:{port}", "variables": {"port": {"default": "8080"}}}
        path.write_text(json.dumps({"openapi": "3.0.3", "servers": [server]}))
        check_targets(scope, ["./"], self.directory, "acme/shop")
        server = {"url": "{base}/v1", "variables": {"base": {"default": "http://localhost:8080", "enum": ["https://outside.test"]}}}
        path.write_text(json.dumps({"openapi": "3.0.3", "servers": [server]}))
        with self.assertRaises(Refusal) as error:
            check_targets(scope, ["./"], self.directory, "acme/shop")
        self.assertEqual(error.exception.code, "openapi-server-out-of-scope")

    def test_url_paths_preserve_scope_boundaries(self):
        scope = Scope({"in_scope": [{"type": "url", "value": "https://h.test/api"}]}, {})
        for path in ("/apix", "/api/../admin", "/api/%2E%2e/admin", "/api%2fadmin", "/api%5cadmin"):
            with self.subTest(path=path):
                self.assertFalse(scope.allows("https://h.test" + path))
        scope = Scope({"in_scope": [{"type": "url", "value": "https://h.test/"}], "out_of_scope": [{"type": "url", "value": "https://h.test/admin"}]}, {})
        self.assertTrue(scope.allows("https://h.test"))
        for path in ("/x/../admin", "//admin", "/%61dmin"):
            with self.subTest(path=path):
                self.assertFalse(scope.allows("https://h.test" + path))


for code in CODES:
    setattr(ActionTests, "test_" + code.replace("-", "_"), lambda self, code=code: self.refusal(code))
for code in (0, 1, 2):
    setattr(ActionTests, f"test_engine_exit_{code}", lambda self, code=code: self.engine_exit(code))

if __name__ == "__main__":
    unittest.main()
