# wgplex Public API (skeleton)

The RPC interface of the wgplex daemon: JSON-RPC 2.0 over HTTP over a unix
domain socket, served by [`github.com/mrFokin/jrpc/v2`](https://pkg.go.dev/github.com/mrFokin/jrpc/v2)
(Echo v5).

- Socket: `<prefix>/var/run/wgplex.sock` (the Homebrew prefix of the installed
  binary; `-socket` overrides it).
- Endpoint: `POST /rpc`, body and response are JSON. Requests over 1 MiB are
  rejected with HTTP 413 (library limit).
- No push notifications: clients poll `status.get`.

**Document status.** This is a skeleton — a minimal description of the current
contract after M2. The full contract (complete reply schemas, per-method
rights, `api_version`, the rest of the planned methods) is scheduled with
milestone M3 per design 21.1.
Everything below is derived from the working code; nothing is speculative
except the items explicitly marked *planned*.

## Transport and access control

The socket file is created with mode `0666` so that any local process can
`connect(2)`; access is checked per connection, not per file (`peer_darwin.go`).

The daemon reads the peer uid of each connection via `LOCAL_PEERCRED` and
checks it against an `allow` function before the method runs:

- **Current (until M3):** `allow` = `uid == 0` — every method requires root.
  A connection from any other uid gets **HTTP 403** ("forbidden") and never
  reaches a JSON-RPC method. The daemon logs the refused uid.
- **Planned (M3):** per-method rights, the `control_group` group check with
  its membership cache, and a JSON-RPC error for denying a method (error
  code `5`, see below) instead of a premature HTTP 403 for read methods.

If the peer credentials cannot be read, the connection is refused the same
way (HTTP 403). The socket file is removed when the daemon closes the
listener; a stale file left by a crashed daemon is removed at the next
start, and a file that answers is an error (a second daemon must not start).

## Methods

Lowercase `object.verb` naming, no boolean params. Mutating methods are idempotent;
the only exception is `tunnel.enable` on a tunnel in state `error` — it retries
bringing the tunnel up.

| Method | Params | Result | Notes |
|---|---|---|---|
| `status.get` | — | `Status` | full daemon snapshot |
| `diag.explain` | `{ "query": string }` | `Explanation` | domain or IP |
| `diag.routes` | — | `Routes` | the last synced route table |
| `config.reload` | — | `ReloadResult` | the daemon re-reads its own config directory |
| `tunnel.enable` | `{ "name": string }` | `null` | turn one tunnel on; on a tunnel in state `error` it retries the start |
| `tunnel.disable` | `{ "name": string }` | `null` | turn one tunnel off |
| `tunnel.disableAll` | — | `null` | turn every enabled tunnel off |

### status.get → `Status`

Tunnels and rules are in config order. An optional field is absent from the
JSON rather than `null`: a timestamp marked *(omitted when zero)* has no value
yet (no handshake, no successful check), and a client should read an absent
field as its zero value.

| Field | Type | Description |
|---|---|---|
| `configured` | bool | a config has been applied |
| `icon` | string | `"off" \| "on" \| "warn"` — `"warn"` when there are config errors or an enabled tunnel in `"error"`/`"dead"`; else `"on"` when some tunnel is `"up"`; else `"off"` |
| `config_errors` | string[] *(present if non-empty)* | errors of the last failed config load; cleared by the next successful one |
| `warnings` | string[] *(present if non-empty)* | warnings of the applied config |
| `tunnels` | `TunnelStatus[]` | |
| `rules` | `RuleStatus[]` | |

`TunnelStatus`:

| Field | Type | Description |
|---|---|---|
| `name` | string | |
| `enabled` | bool | the user's switch, not the fact of running |
| `state` | string | `"off" \| "starting" \| "up" \| "dead" \| "error"` — `"dead"`: running but considered unhealthy; `"error"`: failed to start |
| `error` | string *(state `"error"`)* | |
| `interface` | string *(state `"up"`/`"dead"`)* | `utunN` |
| `addresses` | string[] *(optional)* | addresses of the `.conf`; absent when it has none |
| `routes` | string | `"config" \| "rules"` |
| `route_count` | int | routes of the table targeting this tunnel |
| `peers` | `PeerStatus[]` *(running tunnel)* | `.conf` order |
| `reason` | string *(state `"dead"`)* | why it is unhealthy |
| `check` | `CheckStatus` *(state `"up"`/`"dead"` with a check configured)* | |

`PeerStatus` (the public key is deliberately not shown; see design 10.1):

| Field | Type | Description |
|---|---|---|
| `endpoint` | string | as written in the `.conf` (`""` if none) |
| `resolved` | string *(optional)* | `addr:port` currently in use; absent until the endpoint is resolved |
| `last_handshake` | time *(omitted when zero)* | time of the last handshake; the field is absent until the first one |
| `rx_bytes`, `tx_bytes` | int | |

`CheckStatus`:

| Field | Type | Description |
|---|---|---|
| `addr` | string | the check address or URL |
| `last_ok` | time *(omitted when zero)* | time of the last successful check; the field is absent until the first one |
| `rtt_ms` | number *(present after a success)* | of the last successful check |
| `fails` | int | consecutive failures |

`RuleStatus`:

| Field | Type | Description |
|---|---|---|
| `index` | int | index in the config, from 0 |
| `services` | string[] | |
| `via` | string[] | tunnel names |
| `fallback` | string | as configured: `"default" \| "block"` |
| `tunnel` | string *(optional)* | the serving tunnel; absent when the rule is direct or in fallback |
| `in_fallback` | bool | the rule is on a fallback tunnel |
| `degraded` | bool | `via` is non-empty and the serving tunnel is not `via[0]` |

### diag.explain `{ query }` → `Explanation`

`query` is a domain name or an IP; a malformed domain produces the standard
invalid params error (`-32602`).

| Field | Type | Description |
|---|---|---|
| `query` | string | normalized: lowercase, no trailing dot; IP unmapped |
| `kind` | string | `"domain" \| "ip"` |
| `rule` | `RuleStatus` | the matched rule |
| `skipped` | `RuleStatus` *(domain, when set)* | the best match by domain alone, passed over because it sits in `fallback: default` |
| `upstream` | string | tunnel name, `"system"` or `"block"`; absent for an IP without a route |
| `zone` | string *(domain, when a tunnel upstream was chosen)* | `dns_domains` zone that chose it |
| `servers` | string[] *(domain, tunnel upstream)* | DNS servers of that tunnel |
| `drop_aaaa` | bool | |
| `addrs` | string[] *(domain)* | dynamic addresses of the name now |
| `route` | `RouteInfo` *(IP)* | the longest-prefix match from the table; absent — the system default route applies |

### diag.routes → `Routes`

| Field | Type | Description |
|---|---|---|
| `routes` | `RouteInfo[]` | the last synced table, by prefix |
| `sync_error` | string *(errors present)* | error text of the last synchronization |

`RouteInfo` (a tunnel route of a tunnel that has no utun yet — starting or
failed — is reported as `target: "reject"` with `tunnel` kept, for both
`diag.routes` and `diag.explain`):

| Field | Type | Description |
|---|---|---|
| `prefix` | string | |
| `target` | string | `"tunnel" \| "direct" \| "reject"` |
| `tunnel` | string *(target `"tunnel"`/`"reject"`)* | |
| `source` | string | `"endpoint" \| "allowed-ips" \| "rule-cidr" \| "dynamic"` |
| `rule` | int | rule index; `-1` — none |
| `names` | string[] | `source: "dynamic"`: names whose DNS answers gave the address |
| `skipped` | string | present: the route was not installed in the kernel (why) |

### config.reload → `ReloadResult`

The daemon re-reads its own config directory (since M2 the daemon owns the
config; the client sends nothing). A successful reload returns even when
some enabled tunnels failed to start:

| Field | Type | Description |
|---|---|---|
| `warnings` | string[] | of the new config |
| `tunnels` | `{ "name": string, "error": string }[]` *(present if any)* | enabled tunnels that failed to start |

If the config fails validation, the reply is a JSON-RPC error `1` with
`data: { "errors": string[], "warnings": string[] }`; the daemon keeps
running the previous config.

### tunnel.enable `{ name }` → `null`

Sets the user's switch on; it survives daemon restarts through `state.json`.
Enabling an already enabled tunnel succeeds; on a tunnel in state `error` it
retries starting it. Errors: `2` (no config applied yet), `3` (unknown
tunnel), `4` (the tunnel failed to start). An empty `name` is the standard
invalid params error (`-32602`).

### tunnel.disable `{ name }` → `null`

Sets the user's switch off; the record in `state.json` survives daemon
restarts. Disabling an already disabled tunnel succeeds. Errors: `2` (no
config applied yet), `3` (unknown tunnel). An empty `name` is the standard
invalid params error (`-32602`).

### tunnel.disableAll → `null`

Turns every enabled tunnel off. Errors: `2` (no config applied yet).

## Error codes

Daemon codes (distinguished from the standard JSON-RPC codes `-32700`…`-32603`
of the library):

| Code | Meaning | Methods |
|---|---|---|
| `1` | the config failed validation (`data`: `errors`, `warnings`) | `config.reload` |
| `2` | no config has been applied yet | `tunnel.*` |
| `3` | the tunnel name is not in the config | `tunnel.enable`, `tunnel.disable` |
| `4` | the tunnel failed to start | `tunnel.enable` |
| `5` | *planned (M3):* not permitted to use the method (`data`: `control_group`) | managing methods |

Any error not meant for the client (internal failure) becomes the standard
internal error (`-32603`).

## Compatibility

Within one `api_version`, fields and methods are only added; a client must
ignore unknown fields. An incompatible change is a new `api_version`
(design 14). `api_version` itself appears in `status.get` with M3.

## Limitations of this skeleton

To keep the boundary clear: the following exist in the design but are not
in the code yet, and are therefore not documented above in full. Expect them
with milestone M3:

- complete, generated reply schemas and a stable `api_version` field in
  `status.get` (along with `version`, `can_control`, `control_group`,
  `paused`, `config_dir`, `log_path`);
- the `daemon.pause` / `daemon.resume` methods (pause, block snapshot), and
  `down -all` semantics of the CLI;
- error `5` and per-method rights (the current root-only access and HTTP 403
  on denial are transitional);
- additional `TunnelStatus`/`RuleStatus` fields (`reason` of a rule on
  reserve, `icon: "paused"` and its priority rules), rewritten responses for
  users without the managing rights, and `wgplex check -json`.
