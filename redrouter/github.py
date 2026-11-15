"""Best-effort PR comment and SARIF delivery via the REST API."""
import base64
import gzip
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote

from .http import request
from .results import MARKER


def endpoint(path):
    base = os.environ.get("REDROUTER_GITHUB_API_URL", os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    return base.rstrip("/") + path


def api(path, method="GET", payload=None):
    return request(endpoint(path), method, payload, os.environ.get("GITHUB_TOKEN", ""))


def repository_path():
    return "/repos/" + "/".join(quote(x, safe="") for x in os.environ["GITHUB_REPOSITORY"].split("/"))


def sticky_comment(number, body):
    repo = repository_path()
    path = f"{repo}/issues/{int(number)}/comments"
    page = 1
    while True:
        comments = api(f"{path}?per_page=100&page={page}")
        for item in comments:
            if item.get("user", {}).get("type") == "Bot" and item.get("body", "").startswith(MARKER):
                api(f"{repo}/issues/comments/{int(item['id'])}", "PATCH", {"body": body})
                return
        if len(comments) < 100:
            break
        page += 1
    api(path, "POST", {"body": body})


def upload_sarif(path):
    payload = {
        "commit_sha": os.environ["GITHUB_SHA"], "ref": os.environ["GITHUB_REF"],
        "sarif": base64.b64encode(gzip.compress(path.read_bytes())).decode(),
        "checkout_uri": Path(os.environ["GITHUB_WORKSPACE"]).resolve().as_uri(),
        "validate": True,
    }
    try:
        api(repository_path() + "/code-scanning/sarifs", "POST", payload)
    except HTTPError as exc:
        if exc.code in (403, 404):
            return "SARIF not uploaded: code scanning is not enabled for this repository. The file is in the run artifact."
        raise
    return ""
