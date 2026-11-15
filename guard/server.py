"""Explicit HTTP/CONNECT proxy and A/AAAA DNS. Only this process has egress."""
import asyncio
import contextlib
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
from urllib.parse import urlsplit

from policy import GATEWAY, LOOPBACK, decide, host_name, load_scope, model_endpoint, validate

SCOPE = Path('/state') / os.environ['SCOPE_FILE']
LOG = Path('/logs') / os.environ['LOG_FILE']
MODEL = model_endpoint(os.environ['MODEL_ENDPOINT'])
BIND = os.environ['GUARD_BIND']
POLL = 0.05


def log(host, port, protocol, decision, **extra):
    action, reason, entry = decision
    row = dict(ts=dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
               action=action, host=host, port=port, protocol=protocol, reason=reason, **extra)
    if entry is not None:
        row['entry'] = entry
    with LOG.open('a') as handle:
        handle.write(json.dumps(row, separators=(',', ':')) + '\n')


def assess(host, port, protocol, path='/', addresses=(), named_addresses=None, record=True, event='decision'):
    try:
        scope = load_scope(SCOPE)
        decision = decide(scope, host, port, protocol, MODEL, path=path,
                          addresses=addresses, named_addresses=named_addresses)
    except (OSError, ValueError, TypeError, KeyError):
        decision = ('block', 'not-in-scope', None)
    if record or decision[0] == 'block':
        log(host, port, protocol, decision, path=path, event=event)
    return decision[0] == 'allow'


async def resolve(host, port):
    results = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM), 5)
    return list(dict.fromkeys(r[4][0] for r in results))


async def excluded_addresses():
    """Resolve exact exclusions once per connection without blocking streams."""
    scope = load_scope(SCOPE)
    validate(scope)
    names = set()
    for entry in scope.get('out_of_scope', []):
        if entry['type'] == 'url':
            names.add(host_name(urlsplit(entry['value']).hostname))
        elif entry['type'] == 'domain' and not entry['value'].startswith('*.'):
            names.add(host_name(entry['value']))

    async def lookup(name):
        try:
            return name, await resolve(GATEWAY if name in LOOPBACK else name, 0)
        except (OSError, asyncio.TimeoutError):
            return name, []
    return dict(await asyncio.gather(*(lookup(name) for name in names)))


async def checked_read(reader, count, target, addresses, named_addresses):
    task = asyncio.create_task(reader.read(count))
    try:
        while True:
            if not assess(*target, addresses=addresses, named_addresses=named_addresses, record=False, event='closed'):
                raise PermissionError('scope changed')
            done, _ = await asyncio.wait([task], timeout=POLL)
            if done:
                if not assess(*target, addresses=addresses, named_addresses=named_addresses, record=False, event='closed'):
                    raise PermissionError('scope changed')
                return task.result()
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def checked_drain(writer, target, addresses, named_addresses):
    task = asyncio.create_task(writer.drain())
    try:
        while not task.done():
            if not assess(*target, addresses=addresses, named_addresses=named_addresses, record=False, event='closed'):
                raise PermissionError('scope changed')
            await asyncio.wait([task], timeout=POLL)
        task.result()
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def pump(reader, writer, target, addresses, named_addresses):
    while data := await checked_read(reader, 16384, target, addresses, named_addresses):
        writer.write(data)
        await checked_drain(writer, target, addresses, named_addresses)


async def tls_hello(reader, host, port):
    """Require a TLS ClientHello. CONNECT is not an arbitrary TCP forwarding port."""
    wire, hello = b'', b''
    while len(hello) < 4 or len(hello) < 4 + int.from_bytes(hello[1:4], 'big'):
        header = await asyncio.wait_for(reader.readexactly(5), 5)
        size = int.from_bytes(header[3:5], 'big')
        if header[0] != 22 or header[1] != 3 or not 0 < size <= 18432 or len(wire) + size > 65536:
            raise ValueError('not TLS')
        chunk = await asyncio.wait_for(reader.readexactly(size), 5)
        wire += header + chunk
        hello += chunk
    if hello[0] != 1:
        raise ValueError('not ClientHello')
    data = hello[4:]
    p = 34
    p += 1 + data[p]
    p += 2 + int.from_bytes(data[p:p+2], 'big')
    p += 1 + data[p]
    end = p + 2 + int.from_bytes(data[p:p+2], 'big')
    p += 2
    names = []
    while p < end:
        kind, size = struct.unpack('!HH', data[p:p+4])
        item = data[p+4:p+4+size]
        if kind == 0:
            q = 2
            while q < len(item):
                n = int.from_bytes(item[q+1:q+3], 'big')
                if item[q] == 0:
                    names.append(host_name(item[q+3:q+3+n].decode('ascii')))
                q += 3 + n
        p += 4 + size
    if names and names != [host]:
        log(host, port, 'connect', ('block', 'not-in-scope', None), detail='sni-mismatch', sni=names[0])
        raise PermissionError('SNI mismatch')
    return wire


async def proxy(reader, writer):
    upstream = None
    target = ('', 0, 'tcp', '/')
    tasks = []
    try:
        raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        lines = raw.decode('iso-8859-1').split('\r\n')
        method, uri, version = lines[0].split(' ')
        if version not in ('HTTP/1.0', 'HTTP/1.1') or not method.isalpha():
            raise ValueError('invalid request')
        headers = {}
        for line in lines[1:-2]:
            name, value = line.split(':', 1)
            if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-' for c in name):
                raise ValueError('invalid header')
            name = name.lower()
            if name in headers or '\r' in value or '\n' in value:
                raise ValueError('duplicate header')
            headers[name] = value.strip()
        if method == 'CONNECT':
            u = urlsplit('https://' + uri)
            if u.path or u.query or u.fragment or u.username:
                raise ValueError('invalid CONNECT')
            host, port, protocol, path = host_name(u.hostname or ''), u.port if u.port is not None else 443, 'connect', '/'
        else:
            u = urlsplit(uri)
            if u.scheme != 'http' or u.username or u.password or u.fragment:
                raise ValueError('absolute HTTP URL required')
            host, port, protocol, path = host_name(u.hostname or ''), u.port if u.port is not None else 80, 'http', u.path or '/'
        if not 1 <= port <= 65535:
            raise ValueError('invalid port')
        target = (host, port, protocol, path)
        if any(k in headers for k in ('transfer-encoding', 'upgrade', 'expect')):
            raise ValueError('unsupported framing')
        if not assess(*target, record=False):
            writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
            return
        if protocol == 'connect':
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            payload = await tls_hello(reader, host, port)
        else:
            length = int(headers.get('content-length', '0'))
            if not 0 <= length <= 8 * 1024 * 1024:
                raise ValueError('body too large')
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            request_path = path + ('?' + u.query if u.query else '')
            authority = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
            dropped = {'host', 'connection', 'proxy-connection', 'proxy-authorization', 'keep-alive', 'te', 'trailer'}
            dropped.update(x.strip().lower() for x in headers.get('connection', '').split(','))
            cleaned = ''.join(f'{k}: {v}\r\n' for k, v in headers.items() if k not in dropped and k != 'content-length')
            payload = (f'{method} {request_path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n'
                       f'Content-Length: {length}\r\n{cleaned}\r\n').encode('iso-8859-1') + body
        addresses = await resolve(host, port)
        named_addresses = await excluded_addresses()
        if not assess(*target, addresses=addresses, named_addresses=named_addresses):
            if protocol == 'http':
                writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                await writer.drain()
            return
        remote, upstream = await asyncio.wait_for(asyncio.open_connection(addresses[0], port), 5)
        if not assess(*target, addresses=addresses, named_addresses=named_addresses, record=False):
            return
        upstream.write(payload)
        await checked_drain(upstream, target, addresses, named_addresses)
        tasks = [asyncio.create_task(pump(remote, writer, target, addresses, named_addresses))]
        if protocol == 'connect':
            tasks.append(asyncio.create_task(pump(reader, upstream, target, addresses, named_addresses)))
        else:
            # Discard any pipelined bytes and stop on EOF; never forward them.
            tasks.append(asyncio.create_task(reader.read(1)))
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, ValueError, IndexError, UnicodeError, struct.error, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError, asyncio.TimeoutError) as exc:
        if not isinstance(exc, PermissionError):
            log(*target[:3], ('block', 'not-in-scope', None), path=target[3], detail=str(exc) or type(exc).__name__)
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (upstream, writer):
            if stream:
                stream.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(stream.wait_closed(), 1)


async def dns_reply(data):
    host = ''
    try:
        ident, flags, count, _, _, _ = struct.unpack('!6H', data[:12])
        if count != 1 or flags & 0xF800:
            raise ValueError('invalid DNS query')
        p, labels = 12, []
        while data[p]:
            size = data[p]
            if size > 63:
                raise ValueError('compressed query unsupported')
            labels.append(data[p+1:p+size+1].decode('ascii'))
            p += size + 1
        host = host_name('.'.join(labels))
        p += 1
        kind, cls = struct.unpack('!HH', data[p:p+4])
        question = data[12:p+4]
        allow = assess(host, 53, 'dns', record=kind not in (1, 28) or cls != 1)
        answers = []
        if allow and kind in (1, 28) and cls == 1:
            addresses = await resolve(host, 0)
            named_addresses = await excluded_addresses()
            allow = assess(host, 53, 'dns', addresses=addresses, named_addresses=named_addresses)
            if allow:
                for address in addresses:
                    ip = ipaddress.ip_address(address)
                    if ip.version == (4 if kind == 1 else 6):
                        answers.append(b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(ip.packed)) + ip.packed)
        return struct.pack('!6H', ident, 0x8180 if allow else 0x8185, 1, len(answers), 0, 0) + question + b''.join(answers)
    except (ValueError, OSError, IndexError, UnicodeError, struct.error, asyncio.TimeoutError):
        log(host, 53, 'dns', ('block', 'not-in-scope', None))
        return data[:2] + struct.pack('!5H', 0x8185, 0, 0, 0, 0)


class DNS(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        async def answer():
            self.transport.sendto(await dns_reply(data), peer)
        asyncio.create_task(answer())


async def dns_tcp(reader, writer):
    try:
        size = struct.unpack('!H', await asyncio.wait_for(reader.readexactly(2), 5))[0]
        data = await asyncio.wait_for(reader.readexactly(size), 5)
        reply = await dns_reply(data)
        writer.write(struct.pack('!H', len(reply)) + reply)
        await writer.drain()
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def main():
    # Fail before readiness on native Linux DAC errors, including private dirs.
    LOG.open('a').close()
    validate(load_scope(SCOPE))
    await asyncio.start_server(proxy, BIND, 3128, limit=16384)
    await asyncio.start_server(dns_tcp, BIND, 53)
    await asyncio.get_running_loop().create_datagram_endpoint(DNS, local_addr=(BIND, 53))
    Path('/tmp/ready').touch()
    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(main())
