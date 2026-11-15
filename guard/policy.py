"""Fail-closed scope decisions. No networking and no third-party dependencies."""
import datetime as dt
import ipaddress
import json
import re
from urllib.parse import unquote, urlsplit

GATEWAY = 'host.docker.internal'
LOOPBACK = ('localhost', '127.0.0.1', '::1')


def load_scope(path):
    """Read JSON (also YAML) or the schema's builder YAML subset, not general YAML."""
    text = path.read_text()
    if text.lstrip().startswith('{'):
        return json.loads(text, object_pairs_hook=unique)
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(' '))
        if '\t' in line or indent % 2:
            raise ValueError('invalid indentation')
        rows.append((indent, line.strip()))

    def scalar(value):
        if value.startswith('"'):
            result = json.loads(value)
            if not isinstance(result, str):
                raise ValueError('expected string')
            return result
        if re.fullmatch(r'-?\d+(\.\d+)?', value):
            return json.loads(value)
        # Also accept the unquoted simple strings used in the contract example.
        if re.fullmatch(r'[A-Za-z0-9_./*-]+', value):
            return value
        raise ValueError('unsupported YAML scalar; use builder YAML or JSON')

    def block(index, indent):
        sequence = rows[index][1].startswith('- ')
        result = [] if sequence else {}
        while index < len(rows) and rows[index][0] == indent:
            line = rows[index][1]
            index += 1
            if sequence:
                if not line.startswith('- '):
                    raise ValueError('mixed collection')
                line = line[2:]
                if ': ' not in line:
                    result.append(scalar(line))
                    continue
                key, value = line.split(': ', 1)
                item = {key: scalar(value)}
                if index < len(rows) and rows[index][0] > indent:
                    extra, index = block(index, indent + 2)
                    if not isinstance(extra, dict) or item.keys() & extra.keys():
                        raise ValueError('invalid sequence mapping')
                    item.update(extra)
                result.append(item)
            else:
                key, sep, value = line.partition(':')
                if not sep or not re.fullmatch(r'[a-z_]+', key) or key in result:
                    raise ValueError('invalid or duplicate key')
                value = value.strip()
                if value:
                    result[key] = scalar(value)
                elif index < len(rows) and rows[index][0] == indent + 2:
                    result[key], index = block(index, indent + 2)
                else:
                    raise ValueError('empty mapping')
        return result, index

    if not rows or rows[0][0] != 0:
        raise ValueError('empty scope')
    value, end = block(0, 0)
    if end != len(rows):
        raise ValueError('invalid nesting')
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def host_name(host):
    host = host.lower().removesuffix('.')
    if '%' in host:
        raise ValueError('zone identifiers are unsupported')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s)
                                     for s in host.split('.')):
            raise ValueError('invalid host')
        return host
    if getattr(address, 'ipv4_mapped', None) is not None:
        raise ValueError('mapped IPv4 addresses are unsupported')
    return str(address)


def model_endpoint(value):
    """A bare host means HTTPS:443; '-' disables the optional exception."""
    if value == '-':
        return None
    u = urlsplit(value if '://' in value else 'https://' + value)
    if u.scheme != 'https' or u.username or u.password or u.query or u.fragment:
        raise ValueError('model endpoint must use HTTPS')
    port = u.port if u.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError('invalid model port')
    return host_name(u.hostname or ''), port


def url_path(path):
    """Match the Action's 236d23b URL semantics, before decoding."""
    if ('\\' in path or '//' in path or any(s in ('.', '..') for s in path.split('/'))
            or re.search(r'%2e|%2f|%5c', path, re.I)
            or any(c.isspace() or ord(c) < 32 for c in path)):
        raise ValueError('ambiguous URL path')
    return unquote(path)


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)', value):
        raise ValueError('expected UTC timestamp')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def validate(scope):
    keys = {'schema', 'status', 'engagement', 'in_scope', 'out_of_scope',
            'techniques', 'window', 'limits', 'test_accounts'}
    if not isinstance(scope, dict) or scope.keys() - keys or scope.get('schema') != 'redrouter.scope/v1':
        raise ValueError('invalid schema')
    if scope.get('status') not in ('draft', 'active', 'revoked'):
        raise ValueError('invalid status')
    engagement = scope['engagement']
    if not isinstance(engagement.get('name'), str) or not engagement['name'].strip():
        raise ValueError('missing engagement name')
    if engagement['type'] not in ('own-app-ci', 'internal', 'client', 'bug-bounty'):
        raise ValueError('invalid engagement type')
    if not scope.get('in_scope'):
        raise ValueError('empty in_scope')
    for key in ('in_scope', 'out_of_scope'):
        if not isinstance(scope.get(key, []), list):
            raise ValueError('expected entries')
        for entry in scope.get(key, []):
            kind, value = entry['type'], entry['value']
            if not isinstance(value, str) or not value:
                raise ValueError('empty entry')
            if kind == 'url':
                if any(c.isspace() or ord(c) < 32 for c in value):
                    raise ValueError('invalid URL')
                u = urlsplit(value)
                host_name(u.hostname or '')
                url_path(u.path)
                if u.scheme not in ('http', 'https') or u.username or u.password or u.fragment or u.query:
                    raise ValueError('unsupported URL')
                if u.port is not None and not 1 <= u.port <= 65535:
                    raise ValueError('invalid port')
            elif kind == 'domain':
                host_name(value[2:] if value.startswith('*.') else value)
            elif kind == 'ip':
                ipaddress.ip_address(host_name(value))
            elif kind == 'cidr':
                ipaddress.ip_network(value, strict=True)
            elif kind == 'repository':
                if not re.fullmatch(r'[^/\s]+/[^/\s]+', value):
                    raise ValueError('invalid repository')
            elif kind != 'text' or key != 'out_of_scope':
                raise ValueError('invalid entry type')
    if 'window' in scope:
        start, end = (timestamp(scope['window'][k]) for k in ('starts', 'expires'))
        if start >= end:
            raise ValueError('invalid window')
    elif engagement['type'] in ('client', 'bug-bounty'):
        raise ValueError('missing window')
    if 'techniques' in scope and not all(isinstance(x, str) for x in scope['techniques'].get('prohibited', [])):
        raise ValueError('invalid techniques')
    for key, value in scope.get('limits', {}).items():
        if key not in ('requests_per_second', 'concurrency', 'max_budget_usd', 'max_turns') or type(value) not in (int, float) or value <= 0:
            raise ValueError('invalid limits')
    for account in scope.get('test_accounts', []):
        if set(account) != {'label', 'username_env', 'password_env'} or not isinstance(account['label'], str):
            raise ValueError('invalid account')
        if not all(re.fullmatch(r'[A-Z_][A-Z0-9_]*', account[k]) for k in ('username_env', 'password_env')):
            raise ValueError('invalid account env')


def matches(entry, host, port, protocol, path, excluded=False):
    kind, value = entry['type'], entry['value']
    if kind in ('repository', 'text'):
        return False
    if kind == 'domain':
        return host.endswith('.' + host_name(value[2:])) if value.startswith('*.') else host == host_name(value)
    if kind in ('ip', 'cidr'):
        try:
            address = ipaddress.ip_address(host)
            return address == ipaddress.ip_address(host_name(value)) if kind == 'ip' else address in ipaddress.ip_network(value)
        except ValueError:
            return False
    u = urlsplit(value)
    if host != host_name(u.hostname):
        return False
    # DNS projects URL grants onto names. Path/port checks still occur at connect.
    # URL exclusions conservatively deny DNS for the whole host.
    if protocol == 'dns':
        return True
    scheme = 'https' if protocol == 'connect' else 'http'
    if u.scheme != scheme or (u.port if u.port is not None else (443 if u.scheme == 'https' else 80)) != port:
        return False
    if protocol == 'connect':
        return excluded or u.path in ('', '/')
    prefix = url_path(u.path).rstrip('/')
    path = url_path(path) or '/'
    return path == (prefix or '/') or path.startswith(prefix + '/')


def address_exclusion(scope, addresses, port, protocol, path, named_addresses):
    """Apply exclusions to pinned addresses, including resolved exact names.

    Resolution is supplied by the server once per connection, never done here.
    Wildcard names cannot be enumerated from an IP address.
    """
    for entry in scope.get('out_of_scope', []):
        kind, value = entry['type'], entry['value']
        if kind in ('ip', 'cidr'):
            if any(matches(entry, address, port, protocol, path, True) for address in addresses):
                return entry
        elif kind == 'url' or (kind == 'domain' and not value.startswith('*.')):
            name = host_name(urlsplit(value).hostname if kind == 'url' else value)
            if (set(addresses).intersection(named_addresses.get(name, ()))
                    and matches(entry, name, port, protocol, path, True)):
                return entry
    return None


def decide(scope, host, port, protocol, model, now=None, path='/', addresses=(), named_addresses=None):
    """Return (action, reason, matching entry). All terminal states block the model too."""
    now = dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now
    try:
        validate(scope)
        host = host_name(host)
        if scope['status'] == 'revoked':
            return 'block', 'scope-revoked', None
        if 'window' in scope and now >= timestamp(scope['window']['expires']):
            return 'block', 'scope-expired', None
        if scope['status'] != 'active' or ('window' in scope and now < timestamp(scope['window']['starts'])):
            return 'block', 'not-in-scope', None
        if protocol not in ('dns', 'http', 'connect'):
            return 'block', 'not-in-scope', None
        if protocol == 'http':
            url_path(path)
        names = (host, *LOOPBACK) if host == GATEWAY else (host,)
        for entry in scope.get('out_of_scope', []):
            if any(matches(entry, name, port, protocol, path, excluded=True) for name in names):
                return 'block', 'out-of-scope', entry
        entry = address_exclusion(scope, addresses, port, protocol, path, named_addresses or {})
        if entry is not None:
            return 'block', 'out-of-scope', entry
        # The engine rewrites runner loopback URLs to GATEWAY. Never dial our
        # own loopback or let a model exception open the runner's other ports.
        if host in LOOPBACK:
            return 'block', 'not-in-scope', None
        if host != GATEWAY and model and host == model[0] and (
                protocol == 'dns' or (protocol == 'connect' and port == model[1])):
            return 'allow', 'allowed', None
        for entry in scope['in_scope']:
            if host == GATEWAY:
                if entry['type'] != 'url':
                    continue
                granted = any(matches(entry, name, port, protocol, path) for name in names)
            else:
                granted = matches(entry, host, port, protocol, path)
            if granted:
                return 'allow', 'allowed', entry
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        pass
    return 'block', 'not-in-scope', None
