"""Local guarded engine demo: two stand-ins on an isolated Docker network."""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

import yaml

from redrouter import egress
from .cases import ROOT, invoke, prepare
from .mock import server

BASE = 'python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741'


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.STDOUT).strip()


def run(destination):
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    token = 'rr-demo-' + uuid.uuid4().hex[:12]
    network, containers = token + '-upstream', []
    created_network = False
    try:
        docker('network', 'create', '--internal', '--opt', 'com.docker.network.bridge.gateway_mode_ipv4=isolated',
               '--label', 'org.redrouter.action-demo', network)
        created_network = True
        for role in ('app', 'outside'):
            name = token + '-' + role
            containers.append((name, role))
            docker('run', '-d', '--name', name, '--network', network, '--network-alias', 'demo-' + role,
                   '--label', 'org.redrouter.action-demo', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--read-only', '--workdir', '/app',
                   '--mount', f'type=bind,source={ROOT / "sample-app"},target=/app,readonly',
                   BASE, 'python', '-B', '-u', '-c',
                   'from app import App, HTTPServer; HTTPServer(("0.0.0.0", 8080), App).serve_forever()')
        with server(destination) as mock:
            mock.guard_commands = [
                "curl -sS --max-time 8 -w '\\nHTTP=%{http_code}\\n' 'http://demo-app:8080/lookup?id=1'",
                "curl -sS --max-time 8 -w '\\nHTTP=%{http_code}\\n' 'http://demo-outside:8080/lookup?id=1'",
            ]
            env = prepare(destination, mock.origin, real=True)
            env.update(INPUT_EGRESS_GUARD='on', GUARD_UPSTREAM_NETWORK=network)
            scope_path = Path(env['GITHUB_WORKSPACE']) / '.github/scope.yaml'
            scope = yaml.safe_load(scope_path.read_text())
            scope['in_scope'] = [{'type': 'repository', 'value': 'acme/shop'},
                                 {'type': 'url', 'value': 'http://demo-app:8080'}]
            scope['out_of_scope'] = [{'type': 'domain', 'value': 'demo-outside'}]
            scope_path.write_text(yaml.safe_dump(scope, sort_keys=False))
            subprocess.run(['git', 'add', '.'], cwd=env['GITHUB_WORKSPACE'], check=True)
            subprocess.run(['git', '-c', 'user.name=RedRouter', '-c', 'user.email=support@redrouter.org',
                            'commit', '-qm', 'test: authorize isolated guard demo'], cwd=env['GITHUB_WORKSPACE'], check=True)
            env['GITHUB_SHA'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=env['GITHUB_WORKSPACE'], text=True).strip()
            event_path = Path(env['GITHUB_EVENT_PATH'])
            event = json.loads(event_path.read_text())
            event['pull_request']['head']['sha'] = env['GITHUB_SHA']
            event['pull_request']['base']['sha'] = env['GITHUB_SHA']
            event_path.write_text(json.dumps(event))
            result, outputs = invoke(env, destination, timeout=600)
            assert result.returncode == 0, result.stdout + result.stderr
            log = Path(outputs['artifact-path']) / 'egress-guard.jsonl'
            shutil.copyfile(log, destination / log.name)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            assert any(r.get('event') == 'decision' and r['action'] == 'allow' and r['host'] == 'demo-app'
                       and r['protocol'] == 'http' for r in rows), 'In-scope request did not pass'
            assert any(r.get('event') == 'decision' and r['action'] == 'block' and r['host'] == 'demo-outside'
                       and r['protocol'] == 'http' for r in rows), 'Out-of-scope request was not blocked'
            for name, role in containers:
                logs = docker('logs', name)
                (destination / (role + '.log')).write_text(logs + '\n')
                assert ('GET /lookup' in logs) == (role == 'app'), 'Unexpected stand-in access: ' + role
            calls = sum(r['path'] == '/v1/chat/completions' for r in mock.requests)
            (destination / 'proof.json').write_text(json.dumps({
                'engine': 'pinned-real', 'exit_code': result.returncode, 'model_requests': calls,
                'in_scope_reached': True, 'out_of_scope_blocked': True,
            }, indent=2) + '\n')
    finally:
        # Retry Action cleanup too if a timed-out child could not finish it.
        for path in (destination / 'results').glob('run-*/guard/connection.json'):
            egress.down(path, path.parents[1].name, path.parents[1] / 'artifact')
        errors = []
        for name, _ in reversed(containers):
            try:
                docker('rm', '-f', name)
            except subprocess.CalledProcessError as exc:
                errors.append(exc.output)
        if created_network:
            try:
                docker('network', 'rm', network)
            except subprocess.CalledProcessError as exc:
                errors.append(exc.output)
        if errors:
            raise RuntimeError('Demo cleanup failed: ' + '; '.join(errors))
    print(f'demo-out/guard/: summary.md, egress-guard.jsonl, outputs.txt; {calls} local model requests, allowed request reached the app, excluded request blocked.')
    return 0
