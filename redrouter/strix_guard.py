"""Attach Strix's sandbox to the guard, under the engine's interpreter."""
import json
from pathlib import Path
import sys

# This directory also contains http.py; do not shadow the standard library.
sys.path.pop(0)
import docker.models.containers
from docker.types import Mount

settings = json.loads(Path(sys.argv.pop(1)).read_text())
original_create = docker.models.containers.ContainerCollection.create


def guarded_create(self, *args, **kwargs):
    kwargs['network'] = settings['network']
    kwargs['entrypoint'] = ['/bin/sh', '-c']
    kwargs['command'] = ['mkdir -p /workspace/.agent-browser-screenshots; exec sleep infinity']
    kwargs['cap_add'] = []
    kwargs['cap_drop'] = ['NET_ADMIN', 'NET_RAW', 'SYS_ADMIN']
    kwargs['security_opt'] = ['no-new-privileges']
    for key in ('extra_hosts', 'devices', 'ports'):
        kwargs.pop(key, None)
    kwargs.setdefault('mounts', []).append(
        Mount('/etc/resolv.conf', settings['resolver'], type='bind', read_only=True))
    environment = kwargs.setdefault('environment', {})
    for key in list(environment):
        if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
            del environment[key]
    environment.update(settings['environment'])
    environment['NO_PROXY'] = environment['no_proxy'] = '127.0.0.1,localhost'
    return original_create(self, *args, **kwargs)


docker.models.containers.ContainerCollection.create = guarded_create
from strix.interface.main import main
main()
