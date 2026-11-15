"""Shared local case setup for the demo and integration tests."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import signal
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def scope_fixture(name="valid-own-app"):
    text = (ROOT / "fixtures" / "scope" / (name + ".yaml")).read_text()
    now = datetime.now(timezone.utc)
    substitutions = {"STARTS": now - timedelta(days=1), "EXPIRES": now + timedelta(days=1), "PAST_START": now - timedelta(days=2), "PAST_END": now - timedelta(days=1), "FUTURE_START": now + timedelta(days=1), "FUTURE_END": now + timedelta(days=2)}
    for key, value in substitutions.items():
        text = text.replace("{{" + key + "}}", value.isoformat().replace("+00:00", "Z"))
    return yaml.safe_load(text)


def prepare(directory, origin, case="valid-own-app", *, real=False):
    directory = Path(directory).resolve()
    workspace = directory / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "sample-app", workspace / "sample-app", dirs_exist_ok=True)
    scope = scope_fixture(case)
    scope_path = workspace / ".github" / "scope.yaml"
    scope_path.parent.mkdir(exist_ok=True)
    scope_path.write_text(yaml.safe_dump(scope, sort_keys=False))
    if case == "openapi-server-out-of-scope":
        (workspace / "sample-app" / "openapi.yaml").write_text('openapi: "3.0.3"\ninfo: {title: Demo, version: "1"}\nservers:\n  - url: https://outside.example.test\npaths: {}\n')
    for command in (["git", "init", "-q", "-b", "main"], ["git", "add", "."], ["git", "-c", "user.name=RedRouter", "-c", "user.email=support@redrouter.org", "commit", "-qm", "test: seed local fixture"]):
        subprocess.run(command, cwd=workspace, check=True, capture_output=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=workspace, text=True).strip()
    event = {"number": 7, "pull_request": {"number": 7, "head": {"repo": {"full_name": "acme/shop", "fork": False}, "sha": sha}, "base": {"repo": {"full_name": "acme/shop"}, "sha": sha}}}
    event_path = directory / "event.json"
    event_path.write_text(json.dumps(event))
    env = {"PATH": str(ROOT / "demo" / "bin") + os.pathsep + os.environ["PATH"], "PYTHONPATH": str(ROOT), "HOME": str(ROOT / ".cache" / "demo-home"),
           "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "acme/shop", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": sha, "GITHUB_REF": "refs/pull/7/merge",
           "GITHUB_WORKSPACE": str(workspace), "GITHUB_EVENT_PATH": str(event_path), "GITHUB_STEP_SUMMARY": str(directory / "summary.md"), "GITHUB_OUTPUT": str(directory / "outputs.txt"), "GITHUB_TOKEN": "local-demo-token",
           "REDROUTER_GITHUB_API_URL": origin, "REDROUTER_SLACK_WEBHOOK_URL": origin + "/slack", "REDROUTER_RESULTS_DIR": str(directory / "results"),
           "INPUT_API_KEY": "local-demo-key", "INPUT_MODEL": "unlisted-model" if case == "prices-unavailable" else "demo-model", "INPUT_API_BASE": origin + "/v1", "INPUT_TARGETS": "./sample-app", "INPUT_MAX_TURNS": "5" if real else "150",
           "UV_CACHE_DIR": str(ROOT / ".cache" / "uv"), "UV_PYTHON_INSTALL_DIR": str(ROOT / ".cache" / "python"), "TMPDIR": str(ROOT / ".cache" / "tmp")}
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    if real:
        env["PATH"] = os.environ["PATH"]
        env["DOCKER_HOST"] = os.environ.get("DOCKER_HOST") or subprocess.check_output(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], text=True).strip()
    else:
        env["REDROUTER_DEMO_STUB"] = "1"
    return env


def invoke(env, directory, timeout=60):
    process = subprocess.Popen([sys.executable, "-m", "redrouter.main"], env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        (Path(directory) / "action.log").write_text(stdout + stderr)
        raise
    finally:
        if env.get("REDROUTER_DEMO_STUB") != "1":
            for run in (Path(directory) / "results").glob("run-*"):
                ids = subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=strix-run-id=" + run.name], text=True).split()
                if ids:
                    subprocess.run(["docker", "rm", "-f", *ids], check=True, capture_output=True)
    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
    directory = Path(directory)
    (directory / "action.log").write_text(result.stdout + result.stderr)
    outputs = dict(line.split("=", 1) for line in (directory / "outputs.txt").read_text().splitlines())
    if outputs.get("sarif-path"):
        shutil.copyfile(outputs["sarif-path"], directory / "findings.sarif")
    return result, outputs
