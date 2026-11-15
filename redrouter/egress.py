"""Guard lifecycle and artifact capture; also callable by the cleanup step."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

ACTION = Path(__file__).resolve().parents[1]
INSTRUCTIONS = """
Network for this run: only HTTP and HTTPS requests to in-scope hosts work, through the configured proxy.
Raw sockets, nmap, sudo and package installs are unavailable. Do not retry them.
The interception proxy tools are unavailable. Use curl, the browser and the HTTP tooling in the sandbox.
Requests to any other host are blocked and logged.
"""


class GuardError(RuntimeError):
    pass


def check_supported(scope):
    from guard.policy import validate
    try:
        validate(scope.guard_document())
    except (ValueError, KeyError, TypeError) as exc:
        raise GuardError('Egress guard cannot enforce this scope; check its host, address and URL entries.') from exc
    for entry in scope.data['in_scope']:
        kind, value = entry['type'], entry['value']
        if ((kind == 'domain' and value.lower().rstrip('.') == 'localhost') or
                (kind in ('ip', 'cidr') and ipaddress.ip_network(value, strict=False).is_loopback)):
            raise GuardError('Egress guard needs loopback targets as url entries, e.g. http://localhost:8080.')
    for entry in scope.data['in_scope'] + scope.data.get('out_of_scope', []):
        if entry['type'] == 'url':
            url = urlsplit(entry['value'])
            if url.scheme == 'https' and url.path not in ('', '/'):
                raise GuardError('Egress guard cannot enforce HTTPS path scopes; use host-wide HTTPS entries.')


def output(name, value):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(f'{name}={value}\n')


def up(scope, work):
    base = work.parent / 'guard'
    state, logs = base / 'state', base / 'logs'
    state.mkdir(parents=True, mode=0o700)
    base.chmod(0o700)
    logs.mkdir(mode=0o700)
    (state / 'scope.json').write_text(json.dumps(scope.guard_document()))
    manifest = base / 'connection.json'
    # Publish recovery paths before starting; the always-run step retries cleanup.
    output('guard-manifest', manifest)
    output('guard-run-id', work.parent.name)
    try:
        with manifest.open('w') as connection, (work / 'guard-start.log').open('w') as log:
            process = subprocess.Popen([sys.executable, str(ACTION / 'guard/manage.py'), 'up',
                                        str(state / 'scope.json'), str(logs / 'egress-guard.jsonl'), '-'],
                                       stdout=connection, stderr=log)
            try:
                code = process.wait(timeout=300)
            except BaseException:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise
        data = json.loads(manifest.read_text())
        if code or not all(data.get(key) for key in ('network', 'resolver', 'environment')):
            raise ValueError('invalid guard manifest')
        return manifest
    except Exception as exc:
        raise GuardError('Egress guard could not start; the scan was not run.') from exc


def down(manifest, run_id, work, result=None):
    """Remove sandboxes before their network; failures remain retryable."""
    errors = []
    try:
        ids = subprocess.check_output(['docker', 'ps', '-aq', '--filter', 'label=strix-run-id=' + run_id],
                                      text=True, timeout=30).split()
        if ids:
            subprocess.run(['docker', 'rm', '-f', *ids], check=True, capture_output=True, timeout=60)
    except Exception as exc:
        errors.append(type(exc).__name__)
    try:
        if manifest.exists() and manifest.stat().st_size:
            subprocess.run([sys.executable, str(ACTION / 'guard/manage.py'), 'down', str(manifest)],
                           check=True, capture_output=True, timeout=60)
    except Exception as exc:
        errors.append(type(exc).__name__)
    try:
        log = manifest.parent / 'logs/egress-guard.jsonl'
        shutil.copyfile(log, work / log.name)
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        if result is not None:
            blocks = [r for r in rows if r.get('action') == 'block' and r.get('event') == 'decision']
            result.guard_blocked = len(blocks)
            result.guard_ended = next((r['reason'] for r in rows if r.get('reason') in
                                       ('scope-expired', 'scope-revoked')), '')
    except (OSError, ValueError):
        pass  # Missing or unreadable log is reported without a count.
    if errors:
        print('::notice::Egress guard cleanup needs a retry; check Docker access and the run artifact.', flush=True)
    return bool(errors)


if __name__ == '__main__':
    sys.exit(down(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])))
