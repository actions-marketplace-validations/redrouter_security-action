"""Lifecycle CLI; stdout is a single JSON manifest suitable for Docker SDK callers."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid
from policy import load_scope, model_endpoint, validate

HERE = Path(__file__).resolve().parent
IMAGE = 'redrouter-egress-guard:local'
LABEL = 'org.redrouter.egress-guard'


def docker(*args):
    return subprocess.check_output(['docker', *map(str, args)], text=True).strip()


def cleanup(state):
    errors = []
    for kind, name in [('container', state['container'])] + [('network', n) for n in state['owned_networks']]:
        result = subprocess.run(['docker', kind, 'rm', *(['-f'] if kind == 'container' else []), name],
                                capture_output=True, text=True)
        if result.returncode and 'No such' not in result.stderr and 'not found' not in result.stderr:
            errors.append(result.stderr.strip())
    if not errors:
        shutil.rmtree(state['state_dir'], ignore_errors=True)
    else:
        raise RuntimeError('; '.join(errors))


def up(scope_path, log_path, endpoint):
    scope, log = Path(scope_path).resolve(), Path(log_path).resolve()
    validate(load_scope(scope))
    model = model_endpoint(endpoint)
    if int(docker('version', '--format', '{{.Server.Version}}').split('.')[0]) < 28:
        raise RuntimeError('egress guard needs Docker Engine 28 or newer')
    subprocess.run(['docker', 'build', '-q', '-t', IMAGE, str(HERE)], check=True, stdout=sys.stderr)
    token = 'rrg-' + uuid.uuid4().hex[:12]
    network, container = token + '-sandbox', token + '-proxy'
    state_dir = log.parent / ('.' + token)
    state = dict(container=container, network=network, owned_networks=[], state_dir=str(state_dir))
    try:
        state_dir.mkdir(parents=True)
        log.touch()
        docker('network', 'create', '--internal', '--opt', 'com.docker.network.bridge.gateway_mode_ipv4=isolated',
               '--opt', 'com.docker.network.bridge.gateway_mode_ipv6=isolated', '--label', LABEL, network)
        state['owned_networks'].append(network)
        subnet = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config'][0]['Subnet']
        address = str(ipaddress.ip_network(subnet).network_address + 2)
        upstream = os.environ.get('GUARD_UPSTREAM_NETWORK')
        if not upstream:
            upstream = token + '-egress'
            docker('network', 'create', '--label', LABEL, upstream)
            state['owned_networks'].append(upstream)
        resolver = state_dir / 'resolv.conf'
        resolver.write_text(f'nameserver {address}\noptions timeout:1 attempts:1\n')
        # Mount the directory so atomic replacement of scope.yaml is observed.
        docker('create', '--name', container, '--label', LABEL, '--network', network, '--ip', address,
               '--user', f'{os.getuid()}:{os.getgid()}', '--add-host', 'host.docker.internal:host-gateway',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=4m', '--sysctl', 'net.ipv4.ip_forward=0',
               '--sysctl', 'net.ipv6.conf.all.forwarding=0',
               '--mount', f'type=bind,source={scope.parent},target=/state,readonly',
               '--mount', f'type=bind,source={log.parent},target=/logs',
               '-e', f'SCOPE_FILE={scope.name}', '-e', f'LOG_FILE={log.name}',
               '-e', f'MODEL_ENDPOINT={endpoint}', '-e', f'GUARD_BIND={address}', IMAGE)
        docker('network', 'connect', upstream, container)
        docker('start', container)
        for _ in range(100):
            result = subprocess.run(['docker', 'exec', container, 'test', '-f', '/tmp/ready'], capture_output=True)
            if result.returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('guard failed to start: ' + docker('logs', container))
        proxy = f'http://{address}:3128'
        env = {key: proxy for key in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')}
        env.update(no_proxy='', NO_PROXY='')
        args = ['--network', network, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--mount', f'type=bind,source={resolver},target=/etc/resolv.conf,readonly']
        for key, value in env.items():
            args += ['-e', key + '=' + value]
        state.update(proxy_url=proxy, dns=address, resolver=str(resolver), environment=env, docker_args=args)
        state.update(model_endpoint={'host': model[0], 'port': model[1], 'tls': True} if model else None,
                     loopback_host='host.docker.internal')
        return state
    except BaseException:
        cleanup(state)
        raise


if __name__ == '__main__':
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if len(sys.argv) == 5 and sys.argv[1] == 'up':
            print(json.dumps(up(*sys.argv[2:])))
        elif len(sys.argv) == 3 and sys.argv[1] == 'down':
            cleanup(json.loads(Path(sys.argv[2]).read_text()))
        else:
            sys.exit('usage: up SCOPE_PATH LOG_PATH MODEL_ENDPOINT > connection.json; down connection.json')
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
