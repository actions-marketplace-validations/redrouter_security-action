"""Adapter verified against Strix 1.7.1 commit 685bbc8 on 2026-11-15."""
import json
import os
import re
import shutil
import signal
import subprocess
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit

from .engine import Findings
from .scope import local_path

PIN = "685bbc8138d35fc9fe378ac37ec0d9198b9c46a3"
IMAGE = "ghcr.io/usestrix/strix-sandbox@sha256:c8e70302ba4a69b678b4001c909b134d8d0b84625d7b23feed59ece02672c1d2"


class Strix:
    def __init__(self, config, scope, prices, work, instructions):
        self.config, self.scope, self.prices = config, scope, prices
        self.work, self.instructions = work, instructions
        self.guard = None
        if not re.fullmatch(r"[0-9a-f]{40}", config.engine_ref):
            raise ValueError("engine-ref must be an immutable 40-character Git commit")
        self.stub = os.environ.get("REDROUTER_DEMO_STUB") == "1"
        if self.stub and urlsplit(config.api_base).hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Demo stub requires a localhost model endpoint")
        self.prefix = ["strix"] if self.stub else ["uvx", "--python", "3.12", "--from", f"git+https://github.com/usestrix/strix.git@{config.engine_ref}", "strix"]
        if not self.stub and config.engine_ref == PIN:
            self.prefix[1:1] = ["--exclude-newer", "2026-11-15T00:00:00Z"]

    def build(self):
        c = self.config
        prefix = self.prefix
        if self.guard is not None and not self.stub:
            prefix = prefix[:-1] + ["python", str(Path(__file__).with_name("strix_guard.py")), str(self.guard)]
        command = prefix + ["-n"]
        for target in c.targets:
            path = local_path(target, c.workspace)
            command += ["-t", str(path) if path else target]
        command += ["--scan-mode", c.scan_mode, "--scope-mode", c.scope_mode, "--fail-on", c.fail_on,
                    "--max-budget", str(c.budget), "--max-turns", str(c.turns),
                    "--instruction-file", str(self.instructions)]
        env = {
            "STRIX_LLM": "openai/" + c.model, "LLM_API_KEY": c.api_key,
            "LLM_API_BASE": c.api_base, "STRIX_API_TYPE": "chat_completions",
            "STRIX_REASONING_EFFORT": "none", "STRIX_MAX_CONTEXT_IMAGES": "0",
            "STRIX_TELEMETRY": "false", "OPENAI_AGENTS_DISABLE_TRACING": "1",
            "STRIX_NO_UPDATE_CHECK": "1", "LITELLM_LOCAL_MODEL_COST_MAP": "True",
            "STRIX_RUN_ID": self.work.parent.name, "STRIX_IMAGE": IMAGE, "LLM_EXTRA_BODY": '{"max_tokens":8192}',
            "STRIX_LLM_INPUT_COST_PER_MTOK": self.prices["input_usd_per_mtok"],
            "STRIX_LLM_CACHED_INPUT_COST_PER_MTOK": self.prices["cached_input_usd_per_mtok"],
            "STRIX_LLM_OUTPUT_COST_PER_MTOK": self.prices["output_usd_per_mtok"],
        }
        # No inherited provider keys, tracing configuration, or GitHub write token.
        for key in ("PATH", "LANG", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "GITHUB_ACTIONS", "GITHUB_BASE_REF", "GITHUB_HEAD_REF", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "CI"):
            if key in os.environ:
                env[key] = os.environ[key]
        for account in self.scope.data.get("test_accounts", []):
            for key in ("username_env", "password_env"):
                name = account[key]
                if name in env or name.startswith(("STRIX_", "LLM_", "OPENAI_", "GITHUB_", "PYTHON", "LD_", "DYLD_", "UV_")) or name in ("HOME", "PATH"):
                    raise ValueError("Test account variable collides with engine configuration")
                if name in os.environ:
                    env[name] = os.environ[name]
        # Avoid user-level engine configuration and MCP connections on reused runners.
        env["HOME"] = str(self.work.parent / "engine-home")
        if self.guard is not None and self.guard.exists():
            env["STRIX_DOCKER_SANDBOX_NETWORK"] = json.loads(self.guard.read_text())["network"]
        if self.stub and "REDROUTER_STUB_EXIT" in os.environ:
            env["REDROUTER_STUB_EXIT"] = os.environ["REDROUTER_STUB_EXIT"]
        return command, env

    def install(self):
        command, env = self.build()
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        if self.stub:
            if not shutil.which("strix"):
                raise RuntimeError("Demo stub missing from PATH")
            return
        with (self.work / "install.log").open("w") as log:
            code = self._execute(self.prefix + ["--help"], env, log, 600)
            if code:
                raise subprocess.CalledProcessError(code, self.prefix)

    def _execute(self, command, env, log, timeout):
        process = subprocess.Popen(command, cwd=self.work, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

    def run(self):
        command, env = self.build()
        with (self.work / "engine.log").open("w") as log:
            code = self._execute(command, env, log, 40 * 60)
        return code if code in (0, 1, 2) else 1

    def locate_results(self):
        files = sorted(self.work.glob("strix_runs/*/findings.sarif"))
        if len(files) > 1:
            raise ValueError("Engine returned multiple run directories")
        return files[0] if files else None

    def normalize(self, path):
        findings = Findings(sarif=path)
        if path is None:
            return findings
        document = json.loads(path.read_text())
        for run in document["runs"]:
            driver = run["tool"]["driver"]
            if driver["name"] != "RedRouter Security Action":
                engine = {"name": driver["name"]}
                if "version" in driver:
                    engine["version"] = driver.pop("version")
                driver.setdefault("properties", {})["engine"] = engine
                driver["name"] = "RedRouter Security Action"
            for result in run.get("results", []):
                if result.get("kind", "fail") != "fail":
                    continue  # Coverage entries are not findings.
                severity = result.get("properties", {}).get("strix", {}).get("severity", "unknown").lower()
                if severity == "informational":
                    severity = "info"
                findings.counts[severity if severity in findings.counts else "unknown"] += 1
        path.write_text(json.dumps(document, indent=2) + "\n")
        record = path.with_name("run.json")
        if record.exists():
            data = json.loads(record.read_text())
            findings.finished = data.get("status") == "completed"
            value = data.get("llm_usage", {}).get("cost")
            if value is not None:
                spend = Decimal(str(value))
                if spend.is_finite() and spend >= 0:
                    findings.estimated_spend = format(spend, "f")
        return findings
