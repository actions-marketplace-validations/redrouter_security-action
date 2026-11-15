"""Engine-independent redrouter.scope/v1 validation and target matching.

Reuse Scope.allows() for connections; exclusions always win. This module does
not perform DNS resolution, network requests, or GitHub/engine integration.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import product
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml


CODES = (
    "scope-missing", "scope-draft", "scope-revoked", "scope-expired",
    "scope-outside-window", "target-out-of-scope",
    "openapi-server-out-of-scope", "prices-unavailable",
)
DEFAULT_LIMITS = dict(requests_per_second=10, concurrency=5, max_budget_usd=3, max_turns=150)


class Refusal(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ScopeLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


ScopeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
# Retain timestamp spelling so malformed/non-UTC YAML timestamps cannot bypass RFC 3339 validation.
ScopeLoader.add_constructor("tag:yaml.org,2002:timestamp", lambda loader, node: loader.construct_scalar(node))


def _check(condition, message):
    if not condition:
        raise Refusal("scope-missing", message)


def _keys(value, allowed, required=()):
    _check(isinstance(value, dict), "Expected a mapping.")
    _check(not set(value) - set(allowed), "Remove unknown fields: " + ", ".join(set(value) - set(allowed)))
    _check(set(required) <= set(value), "Missing required fields: " + ", ".join(set(required) - set(value)))


def _string(value):
    return isinstance(value, str) and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def positive(value, name, integer=False):
    _check(type(value) in (int, float) and 0 < value <= 1e9 and math.isfinite(value), f"{name} must be positive, finite and at most 1e9.")
    _check(not integer or type(value) is int, f"{name} must be an integer.")
    return value


def host(value):
    normalized = value.lower().removesuffix(".")
    try:
        return str(ipaddress.ip_address(normalized.split("%", 1)[0]))
    except ValueError:
        if not value.isascii() or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", normalized):
            raise ValueError("Invalid host")
        return normalized


def _url(value):
    if any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("URL contains whitespace or control characters")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("URLs need http(s), a host, and no credentials")
    path = parts.path
    if "\\" in path or "//" in path or any(segment in (".", "..") for segment in path.split("/")) or re.search(r"%2e|%2f|%5c", path, re.I):
        raise ValueError("Ambiguous URL path")
    return parts.scheme.lower(), host(parts.hostname), (parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)), unquote(path)


def _entry(value, exclusion=False):
    _keys(value, ("type", "value", "note") if exclusion else ("type", "value"), ("type", "value"))
    kind, text = value["type"], value["value"]
    _check(kind in ("repository", "url", "domain", "ip", "cidr") + (("text",) if exclusion else ()), "Unknown scope entry type.")
    _check(_string(text), "Scope entries must have non-empty string values.")
    if "note" in value:
        _check(_string(value["note"]), "Entry notes must be non-empty strings.")
    try:
        if kind == "repository":
            _check(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text)), "Use repository owner/name.")
        elif kind == "url":
            _url(text)
            _check(not urlsplit(text).query and not urlsplit(text).fragment, "Scope URLs must not contain queries or fragments.")
        elif kind == "domain":
            name = text[2:] if text.startswith("*.") else text
            _check(bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host(name))), "Invalid domain.")
            _check(all(label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-") for label in host(name).split(".")), "Invalid domain labels.")
        elif kind == "ip":
            ipaddress.ip_address(text)
        elif kind == "cidr":
            ipaddress.ip_network(text, strict=True)
    except (ValueError, UnicodeError) as exc:
        hint = {"cidr": " Use a network address with no host bits.",
                "url": " Use a valid ASCII host and a path without dot segments, repeated slashes or encoded dots/separators."}.get(kind, "")
        raise Refusal("scope-missing", f"Invalid {kind} scope entry." + hint) from exc


def _timestamp(value):
    if isinstance(value, datetime):  # SafeLoader parses unquoted timestamps.
        stamp = value
    else:
        _check(isinstance(value, str) and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", value)), "Use RFC 3339 UTC window timestamps.")
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Refusal("scope-missing", "Invalid window timestamp.") from exc
    _check(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0, "Window timestamps must be UTC.")
    return stamp


@dataclass
class Scope:
    data: dict
    limits: dict

    @property
    def name(self):
        return self.data["engagement"]["name"]

    def allows(self, target: str, workspace: Path | None = None, repository: str = "") -> bool:
        """Match a URL, host/IP or workspace-local path against both lists."""
        return any(_matches(e, target, workspace, repository) for e in self.data["in_scope"]) and not any(
            _matches(e, target, workspace, repository, exclusion=True) for e in self.data.get("out_of_scope", [])
        )

    def guard_document(self):
        """Only policy fields; the guard never reads the writable checkout."""
        document = {key: self.data[key] for key in
                    ("schema", "status", "engagement", "in_scope", "out_of_scope") if key in self.data}
        if "window" in self.data:
            # Preserve fractional seconds: truncating starts could widen a window.
            document["window"] = {key: _timestamp(value).isoformat().replace("+00:00", "Z")
                                  for key, value in self.data["window"].items()}
        return document

    def instructions(self):
        lines = [f"Scope for this run ({self.name}). Follow it exactly.", "", "In scope:"]
        lines += [f"- {e['type']}: {e['value']}" for e in self.data["in_scope"]]
        for entry in self.data["in_scope"]:
            if entry["type"] != "url":
                continue
            name = urlsplit(entry["value"]).hostname
            try:
                loopback = ipaddress.ip_address(name).is_loopback
            except ValueError:
                loopback = name == "localhost"
            if loopback or name == "0.0.0.0":
                lines += ["", "Inside the sandbox, in-scope loopback URLs (including 0.0.0.0) use host.docker.internal with the same scheme, port and path; these are the same in-scope apps, with only the listed URL scopes allowed and all exclusions still applying."]
                break
        lines += ["", "Out of scope:"]
        for e in self.data.get("out_of_scope", []):
            value = e["value"] if e["type"] == "text" else f"{e['type']}: {e['value']}"
            lines.append("- " + value + (f" ({e['note']})" if e.get("note") else ""))
        lines.append("- Any host, URL or repository not listed in scope, including ones found in source, config, specs or responses.")
        prohibited = self.data.get("techniques", {}).get("prohibited", [])
        if prohibited:
            lines += ["", "Prohibited techniques:"] + [f"- {p}" for p in prohibited]
        lines += ["", f"Limits: at most {self.limits['requests_per_second']:g} requests per second and {self.limits['concurrency']} concurrent connections."]
        accounts = self.data.get("test_accounts", [])
        if accounts:
            lines += ["", "Test accounts (seeded test data only):"]
            lines += [f"- {a['label']}: username in ${a['username_env']}, password in ${a['password_env']}" for a in accounts]
        return "\n".join(lines) + "\n"


def load_scope(path: Path, now: datetime | None = None) -> Scope:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise Refusal("scope-missing", "Commit a readable, valid scope YAML file.") from exc
    return parse_scope(raw, now)


def parse_scope(raw: str | bytes, now: datetime | None = None) -> Scope:
    try:
        data = yaml.load(raw, Loader=ScopeLoader)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise Refusal("scope-missing", "Commit a readable, valid scope YAML file.") from exc
    _keys(data, ("schema", "status", "engagement", "in_scope", "out_of_scope", "techniques", "window", "limits", "test_accounts"), ("schema", "status", "engagement", "in_scope"))
    _check(data["schema"] == "redrouter.scope/v1", "Set schema to redrouter.scope/v1.")
    _check(data["status"] in ("draft", "active", "revoked"), "Use status draft, active or revoked.")
    _keys(data["engagement"], ("name", "type"), ("name", "type"))
    _check(_string(data["engagement"]["name"]), "Set a non-empty engagement name.")
    _check(data["engagement"]["type"] in ("own-app-ci", "internal", "client", "bug-bounty"), "Invalid engagement type.")
    _check(isinstance(data["in_scope"], list) and bool(data["in_scope"]), "Add at least one in-scope entry.")
    _check(isinstance(data.get("out_of_scope", []), list), "out_of_scope must be a list.")
    for entry in data["in_scope"]:
        _entry(entry)
    for entry in data.get("out_of_scope", []):
        _entry(entry, exclusion=True)
    techniques = data.get("techniques", {})
    _keys(techniques, ("prohibited",))
    prohibited = techniques.get("prohibited", [])
    _check(isinstance(prohibited, list) and all(_string(x) for x in prohibited), "Prohibited techniques must be strings.")
    limits = data.get("limits", {})
    _keys(limits, DEFAULT_LIMITS)
    limits = DEFAULT_LIMITS | limits
    for key, value in limits.items():
        positive(value, key, integer=key in ("concurrency", "max_turns"))
    accounts = data.get("test_accounts", [])
    _check(isinstance(accounts, list), "test_accounts must be a list.")
    for account in accounts:
        _keys(account, ("label", "username_env", "password_env"), ("label", "username_env", "password_env"))
        _check(_string(account["label"]), "Set a test account label.")
        for key in ("username_env", "password_env"):
            _check(isinstance(account[key], str) and bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", account[key])), "Test accounts accept environment variable names only.")
    start = end = None
    if "window" in data:
        _keys(data["window"], ("starts", "expires"), ("starts", "expires"))
        start, end = (_timestamp(data["window"][key]) for key in ("starts", "expires"))
        _check(start < end, "Window starts must be before expires.")
    if data["status"] != "active":
        raise Refusal("scope-" + data["status"], "Commit an active scope after confirming authorization.")
    now = now or datetime.now(timezone.utc)
    if start is None and data["engagement"]["type"] in ("client", "bug-bounty"):
        raise Refusal("scope-outside-window", "Add an authorized UTC start and expiry window.")
    if end and now >= end:
        raise Refusal("scope-expired", "Renew the authorized scope window before scanning.")
    if start and now < start:
        raise Refusal("scope-outside-window", "Wait until the authorized scope window starts.")
    return Scope(data, limits)


def local_path(target: str, workspace: Path) -> Path | None:
    if "://" in target:
        return None
    path = workspace / target
    if target.startswith((".", "/", "~")) or path.exists():
        return path.resolve()
    return None


def _matches(entry, target, workspace, repository, exclusion=False):
    kind, value = entry["type"], entry["value"]
    if kind == "text":
        return False
    if workspace is not None:
        path = local_path(target, workspace)
        if path is not None:
            return kind == "repository" and path.exists() and path.is_relative_to(workspace.resolve()) and repository.lower() == value.lower()
    try:
        if "://" in target:
            scheme, name, port, path = _url(target)
            if kind == "repository":
                return scheme == "https" and name == "github.com" and port == 443 and path.strip("/").lower() == value.lower()
        else:
            scheme = port = path = None
            name = host(target.strip("[]"))
        if kind == "url":
            s, h, p, prefix = _url(value)
            if scheme is None:
                return exclusion and name == h
            prefix = prefix.rstrip("/")
            return (scheme, name, port) == (s, h, p) and ((path or "/") == (prefix or "/") or (path or "/").startswith(prefix + "/"))
        if kind == "domain":
            return name.endswith("." + host(value[2:])) if value.startswith("*.") else name == host(value)
        if kind == "ip":
            return ipaddress.ip_address(name) == ipaddress.ip_address(host(value))
        if kind == "cidr":
            return ipaddress.ip_address(name) in ipaddress.ip_network(value)
    except (ValueError, UnicodeError):
        return False
    return False


def check_targets(scope: Scope, targets: list[str], workspace: Path, repository: str):
    if not targets or any(any(c.isspace() or ord(c) < 32 for c in t) or not scope.allows(t, workspace, repository) for t in targets):
        raise Refusal("target-out-of-scope", "A target is outside scope or covered by an exclusion; list every target in scope and keep local paths inside the workspace.")
    files = set()
    for target in targets:
        path = local_path(target, workspace)
        if path is None:
            continue
        if path.is_file():
            files.add(path)
        else:
            # Do not recurse into VCS, installed dependencies, or generated runs.
            import os
            for root, dirs, names in os.walk(path, followlinks=False):
                dirs[:] = [d for d in dirs if d not in {".git", ".venv", "node_modules", ".cache", "demo-out", "strix_runs", ".redrouter-results"}]
                files.update(Path(root) / n for n in names if Path(n).suffix.lower() in (".json", ".yaml", ".yml"))
    for path in sorted(files):
        if path.suffix.lower() not in (".json", ".yaml", ".yml"):
            continue
        if not path.resolve().is_relative_to(workspace.resolve()):
            raise Refusal("target-out-of-scope", "Keep specification files inside the workspace.")
        raw = ""
        try:
            raw = path.read_text()
            document = json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
        except (OSError, UnicodeError, ValueError, yaml.YAMLError, RecursionError) as exc:
            # A parse error must not hide a specification's declared servers.
            if path in [local_path(t, workspace) for t in targets] or any(x in path.stem.lower() for x in ("openapi", "swagger")) or re.search(r'''(?m)^\s*["']?(openapi|swagger)["']?\s*:''', raw):
                raise Refusal("openapi-server-out-of-scope", "Provide a readable API specification with allowed servers.") from exc
            continue
        if not isinstance(document, dict) or not ("openapi" in document or "swagger" in document):
            continue
        try:
            for url in _servers(document):
                if not scope.allows(url, workspace, repository):
                    raise ValueError("server outside scope")
        except (ValueError, TypeError, RecursionError) as exc:
            raise Refusal("openapi-server-out-of-scope", "Remove or authorize every absolute API server URL in the specification.") from exc


def _servers(document):
    if "swagger" in document and "host" in document:
        schemes = document.get("schemes", ["http", "https"])
        if not isinstance(schemes, list) or not schemes:
            raise ValueError("invalid Swagger schemes")
        for scheme in schemes:
            yield f"{scheme}://{document['host']}{document.get('basePath', '')}"
    nodes = [document]
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("invalid paths")
    for item in paths.values():
        if isinstance(item, dict):
            nodes.append(item)
            nodes.extend(item[method] for method in ("get", "put", "post", "delete", "options", "head", "patch", "trace") if isinstance(item.get(method), dict))
    for node in nodes:
        servers = node.get("servers", [])
        if not isinstance(servers, list):
            raise ValueError("invalid server list")
        for server in servers:
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                raise ValueError("invalid server URL")
            for url in _server_urls(server):
                if urlsplit(url).scheme or url.startswith("//"):
                    yield url


def _server_urls(server):
    template = server["url"]
    names = list(dict.fromkeys(re.findall(r"\{([^{}]+)\}", template)))
    variables = server.get("variables", {})
    if not isinstance(variables, dict):
        raise ValueError("invalid server variables")
    choices = []
    for name in names:
        variable = variables.get(name)
        if not isinstance(variable, dict) or "default" not in variable:
            raise ValueError("server variable needs a default")
        enum = variable.get("enum", [])
        if not isinstance(enum, list):
            raise ValueError("invalid server variable enum")
        choices.append(list(dict.fromkeys(str(value) for value in [variable["default"], *enum])))
    # Check combinations too: two individually safe substitutions can combine
    # into a different origin. Refuse excessive expansion instead of skipping it.
    if math.prod(len(values) for values in choices) > 256:
        raise ValueError("too many server variable combinations")
    for values in product(*choices):
        url = template
        for name, value in zip(names, values):
            url = url.replace("{" + name + "}", value)
        if "{" in url or "}" in url or url.startswith("\\"):
            raise ValueError("unresolved or ambiguous server URL")
        yield url
