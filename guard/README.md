# RedRouter egress guard

Requires Python 3 and Docker Engine 28+ (checked).

```sh
guard/up scope.json guard.jsonl https://model.example:443 > connection.json
guard/down connection.json # remove sandbox first; repeatable
```

Use `-` to disable the model exception; bare hosts mean HTTPS:443.
Exclusions override its host/port/TLS grant. DNS permits its name.

A pinned Python proxy bridges an isolated internal sandbox network to upstream;
forwarding is disabled. `GUARD_UPSTREAM_NETWORK` selects existing upstream.
Never add sandbox networks, privileges, or Docker sockets.

Manifest: `network`, `container`, `owned_networks`, `state_dir`, `proxy_url`,
`dns`, `resolver`, `environment`, `docker_args`, `model_endpoint`, `loopback_host`.
Use all `docker_args`. The guard runs as the invoking UID/GID.

Input: builder YAML or raw JSON `redrouter.scope/v1`: `schema`, `status`,
`engagement`, `in_scope`, optional `out_of_scope`/`window`; UTC strings accept
`Z`/`+00:00`. Atomically replace this private document for revocation.
Decisions reread it; streams recheck every 50ms.

HTTP paths follow Action 236d23b. CONNECT requires TLS and matching visible SNI.
Exact named exclusions resolve against destination IPs; wildcard exclusions cannot
identify IP requests. Other egress has no route; kernel drops are unlogged.
JSONL: `ts/action/host/port/protocol/reason`, optional `entry/path/event/detail/sni`.

`host.docker.internal` maps scoped loopback URLs, preserving port/path and exclusions;
direct loopback is refused. Linux apps need a reachable bind/published port;
Linux mapping is untested.

No TLS interception: HTTPS path grants require root; path exclusions deny endpoints.
Encrypted routing, authorized relays and container escapes are uncovered.

## Third-party engine

Strix [685bbc8 docker_client.py:54–66,220–289](https://github.com/usestrix/strix/blob/685bbc8138d35fc9fe378ac37ec0d9198b9c46a3/strix/runtime/docker_client.py#L54)
accepts `STRIX_DOCKER_SANDBOX_NETWORK`. A pre-create wrapper drops capabilities/host-gateway,
sets resolver/proxies/no-new-privileges, and replaces startup;
[session_manager.py:312–329](https://github.com/usestrix/strix/blob/685bbc8138d35fc9fe378ac37ec0d9198b9c46a3/strix/runtime/session_manager.py#L312)
otherwise selects its interception proxy. See NOTICE.

2026-11-15: Engine 29.8.0/Desktop 4.92.0 (macOS, arm64): policy tests, `./demo.sh --guard`.
Hosted runners untested.
