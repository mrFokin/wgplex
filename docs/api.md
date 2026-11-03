# wgplex API

The public contract of the wgplex daemon: JSON-RPC 2.0 over HTTP over a unix
socket. The CLI (`wgplex`) and the app (`Wgplex.app`, repository
`wgplex-app`) are clients of this API. This document lives in the engine
repository and changes only there, together with the code.

Current `api_version`: **1**.

## Contents

1. [Transport](#transport)
2. [Authentication and authorization](#authentication-and-authorization)
3. [Errors](#errors)
4. [Methods](#methods)
5. [Data structures](#data-structures)
6. [Redaction](#redaction)
7. [State semantics](#state-semantics)
8. [Versioning and compatibility](#versioning-and-compatibility)

## Transport

| | |
|---|---|
| Socket | `<prefix>/var/run/wgplex.sock`, mode `0666` |
| `<prefix>` | `HOMEBREW_PREFIX`: `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel |
| Protocol | JSON-RPC 2.0 over HTTP/1.1 |
| Endpoint | `POST /rpc`, `Content-Type: application/json` |
| Request body | at most 1 MiB |
| Notifications | none: the daemon does not push; clients poll |

- One HTTP request carries one JSON-RPC request or a batch (JSON array).
  A request without `id` is a notification: HTTP 200 with an empty body.
- Every JSON-RPC reply, including errors, is HTTP 200. Other HTTP statuses
  come only from the transport: `413` (body over 1 MiB), `415` (not
  `application/json`), and Echo's statuses for a wrong path or HTTP method.
  There is no HTTP 403: a denied call is JSON-RPC error `5`.
- `params`, when present, is a JSON object (by-name params); methods without
  params take it omitted or `{}`. `params: null` or a scalar is `-32600`.
- The socket file is created by the daemon at start and removed when it
  stops. A socket file nobody answers on (left after a crash) is replaced; if
  another daemon answers, the second one exits with an error.

Example:

```sh
curl --unix-socket /opt/homebrew/var/run/wgplex.sock \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"status.get"}' \
  http://wgplex/rpc
```

## Authentication and authorization

Every connection is accepted. The daemon takes the uid of the peer from
`LOCAL_PEERCRED` and checks it in each method.

A caller **can control** (`can_control`) when any of these holds:

1. uid is `0` (root);
2. uid is the owner of the config directory (`stat` on every check; no
   directory: only root controls);
3. a config is applied and uid is a member of its `control_group` (Directory
   Services, `mbr_check_membership`: nested groups count). A numeric
   `control_group` is a gid. A group that does not exist means "not a member".

Without an applied config only root and the owner of the config directory
control. The membership answer is cached per uid for 30 seconds: adding or
removing a user from the group takes effect within 30 seconds, without a
restart. A change of `control_group` in the config drops the cache. A failed
membership lookup means "not a member" and is not cached. If the daemon
cannot get the peer uid, the caller reads as one that cannot control.

| Methods | Who |
|---|---|
| `status.get`, `diag.explain`, `diag.routes` | everybody; redacted unless `can_control` ([Redaction](#redaction)) |
| `config.reload`, `tunnel.enable`, `tunnel.disable`, `tunnel.disableAll`, `daemon.pause`, `daemon.resume` | `can_control` only; otherwise error `5` |

The right is checked before params: a caller that cannot control gets error
`5` even with invalid params.

## Errors

Errors are JSON-RPC error objects `{"code", "message", "data"}`. `message`
is human-readable English text and is not part of the contract; `data` is
omitted when not listed.

| Code | Meaning | Methods | `data` |
|---|---|---|---|
| `1` | the config is invalid; the previous config keeps running | `config.reload` | [`ConfigErrorData`](#configerrordata) |
| `2` | no config applied (`configured: false`) | `tunnel.enable`, `tunnel.disable`, `tunnel.disableAll` | — |
| `3` | unknown tunnel: the name is not in the applied config | `tunnel.enable`, `tunnel.disable` | — |
| `4` | the tunnel failed to start; its toggle stays on | `tunnel.enable` | — |
| `5` | permission denied: the caller cannot control | all mutating methods | [`PermissionData`](#permissiondata) |
| `-32700` | parse error | any | — |
| `-32600` | invalid request | any | — |
| `-32601` | method not found | any | — |
| `-32602` | invalid params (empty `name`, invalid `query`) | `tunnel.enable`, `tunnel.disable`, `diag.explain` | — |
| `-32603` | internal error (for example, the daemon is stopping) | any | — |

### PermissionData

| Field | Type | Description |
|---|---|---|
| `control_group` | string | `control_group` of the applied config; `""` without one (then only root and the owner of the config directory control) |

A client shows something like: `permission denied: requires root, the
config owner or membership in group "<control_group>"` (without the group
part when it is empty).

### ConfigErrorData

| Field | Type | Description |
|---|---|---|
| `errors` | string[] | config errors, one per entry |
| `warnings` | string[] | config warnings, one per entry |

## Methods

| Method | Params | Result | Rights | CLI |
|---|---|---|---|---|
| `status.get` | — | [`Status`](#status) | everybody | `wgplex status` |
| `diag.explain` | `{"query": string}` | [`Explanation`](#explanation) | everybody | `wgplex explain` |
| `diag.routes` | — | [`Routes`](#routes) | everybody | `wgplex routes` |
| `config.reload` | — | [`ApplyResult`](#applyresult) | control | `wgplex reload` |
| `tunnel.enable` | `{"name": string}` | [`EnableResult`](#enableresult) | control | `wgplex up <tunnel>` |
| `tunnel.disable` | `{"name": string}` | `null` | control | `wgplex down <tunnel>` |
| `tunnel.disableAll` | — | `null` | control | `wgplex down -all` |
| `daemon.pause` | — | `null` | control | `wgplex pause` |
| `daemon.resume` | — | `null` | control | `wgplex resume` |

Names are `object.verb`, with no boolean params. Mutating methods are
idempotent, with one exception: `tunnel.enable` of a tunnel in state `error`
brings it up again.

### status.get

The state of the daemon. Params: none. Result: [`Status`](#status), redacted
for a caller that cannot control. Errors: none of `1`–`5`.

Meant to be polled (the app polls every 1–10 s).

### diag.explain

Which rule, tunnel and DNS upstream a domain or an IP gets, and why.

| Param | Type | Description |
|---|---|---|
| `query` | string | a domain name or an IP address; surrounding spaces are trimmed |

Result: [`Explanation`](#explanation), redacted for a caller that cannot
control. Errors: `-32602` when `query` is neither an IP address nor a valid
domain name (labels of 1–63 characters `a-z`, `0-9`, `-`, `_`; at most 253
bytes; case and a trailing dot are ignored).

### diag.routes

The routing table the daemon last synced to the kernel. Params: none.
Result: [`Routes`](#routes), redacted for a caller that cannot control.

### config.reload

The daemon re-reads its config directory, validates it and applies it.
Params: none.

- Valid config: it is applied; result [`ApplyResult`](#applyresult) with the
  warnings of the config and the enabled tunnels that failed to start.
  `config_errors` of `status.get` are cleared.
- Invalid config: error `1` with [`ConfigErrorData`](#configerrordata); the
  previous config keeps running and the errors show in `config_errors` of
  `status.get`.
- On pause the config is applied, but no tunnel is brought up.

Errors: `1`, `5`.

### tunnel.enable

Switches the toggle of tunnel `name` on (persisted in the state file) and
brings the tunnel up.

| Param | Type | Description |
|---|---|---|
| `name` | string | the tunnel name from the config; required |

Result: [`EnableResult`](#enableresult). When the daemon is paused the toggle
is switched on but nothing is brought up: `{"starts_on_resume": true}`.
Otherwise `{}`. A running tunnel stays as is; a tunnel in state `error` is
brought up again.

Errors: `2`, `3`, `4` (the toggle stays on: the tunnel is retried on network
changes and every 60 s), `5`, `-32602` (empty `name`).

### tunnel.disable

Switches the toggle of tunnel `name` off (persisted) and stops the tunnel.

| Param | Type | Description |
|---|---|---|
| `name` | string | the tunnel name from the config; required |

Result: `null`. On pause only the toggle changes. Errors: `2`, `3`, `5`,
`-32602` (empty `name`).

### tunnel.disableAll

Switches the toggles of all tunnels of the applied config off (persisted)
and stops them. A one-time action, not a mode: a tunnel added later by
`config.reload` follows its `autostart`. The system DNS capture does not
change. Params: none. Result: `null`. Errors: `2`, `5`.

### daemon.pause

Pauses the daemon: every tunnel is stopped, the toggles are kept. The pause
is persisted and survives a daemon restart. Rules go to their fallback;
`fallback: block` keeps blocking. The system DNS capture does not change.
Works without an applied config. Idempotent. Params: none. Result: `null`.
Errors: `5`.

The pause is shared by all users.

### daemon.resume

Clears the pause and brings up the tunnels by their toggles (a tunnel
without a toggle by `autostart`). Works without an applied config.
Idempotent. Params: none. Result: `null`. Errors: `5`.

## Data structures

Conventions:

- Times are RFC 3339 strings. A field marked "omitted when zero" is absent
  when the event never happened.
- "omitted when empty" fields are absent instead of `""`, `0`, `false`,
  `null` or `[]`.
- Arrays not marked so are always present (possibly `[]`).
- No reply carries a WireGuard key, private or public.

### Status

Result of `status.get`.

| Field | Type | Description |
|---|---|---|
| `api_version` | int | `1`; see [Versioning](#versioning-and-compatibility) |
| `version` | string | version of the engine (the daemon binary) |
| `can_control` | bool | the caller may call the mutating methods and sees full replies |
| `control_group` | string | `control_group` of the applied config; `""` without one |
| `configured` | bool | a config has been applied |
| `paused` | bool | the daemon is paused (`daemon.pause`) |
| `config_dir` | string | the config directory of the daemon |
| `log_path` | string | the log file of the daemon |
| `icon` | string | `off` \| `on` \| `warn` \| `paused`; see [Icon](#icon) |
| `config_errors` | string[] | errors of the last failed apply (start or `config.reload`); cleared by a successful one; omitted when empty; **redacted** |
| `config_error_count` | int | number of `config_errors`; always present |
| `warnings` | string[] | warnings of the applied config; omitted when empty; **redacted** |
| `warning_count` | int | number of `warnings`; always present |
| `tunnels` | [TunnelStatus](#tunnelstatus)[] | tunnels in config order |
| `rules` | [RuleStatus](#rulestatus)[] | rules in config order |

### TunnelStatus

| Field | Type | Description |
|---|---|---|
| `name` | string | tunnel name |
| `enabled` | bool | the toggle (see [enabled vs state](#enabled-vs-state)) |
| `state` | string | `off` \| `starting` \| `up` \| `dead` \| `error` |
| `error` | string | state `error`: why it failed to start; omitted when empty |
| `interface` | string | `utunN`, states `up` and `dead`; omitted when empty |
| `addresses` | string[] | `Address` of the `.conf` (CIDR); omitted when empty |
| `routes` | string | route mode: `config` \| `rules` |
| `route_count` | int | routes of the table via this tunnel |
| `peers` | [PeerStatus](#peerstatus)[] | states `up` and `dead`, in `.conf` order; omitted otherwise |
| `reason` | string | state `dead`: why; omitted otherwise |
| `check` | [CheckStatus](#checkstatus) | the active check, when `check` is set, states `up` and `dead`; omitted otherwise |

### PeerStatus

| Field | Type | Description |
|---|---|---|
| `endpoint` | string | `Endpoint` as in the `.conf` (`host:port`); omitted when none; **redacted** |
| `resolved` | string | `addr:port` in use; omitted when not resolved; **redacted** |
| `last_handshake` | time | last handshake; omitted when zero (never) |
| `rx_bytes` | int | bytes received |
| `tx_bytes` | int | bytes sent |

### CheckStatus

The active health check: ping of the check address or `GET` of the check URL.

| Field | Type | Description |
|---|---|---|
| `addr` | string | the check address or URL; **redacted** (omitted) |
| `last_ok` | time | last successful check; omitted when zero (never) |
| `rtt_ms` | number | round-trip time of the last successful check, ms; omitted when zero |
| `fails` | int | consecutive failures |

### RuleStatus

| Field | Type | Description |
|---|---|---|
| `index` | int | index of the rule in the config, from 0 |
| `services` | string[] | service names of the rule |
| `via` | string[] | tunnels of the rule in priority order; `[]`: always direct |
| `fallback` | string | configured fallback: `default` \| `block` |
| `tunnel` | string | the serving tunnel; omitted when direct or in fallback |
| `in_fallback` | bool | no tunnel of `via` serves the rule: its fallback applies |
| `degraded` | bool | `via` is not empty and the rule is not on `via[0]` (on a backup or in fallback) |
| `reason` | string | `degraded` only: `dead` \| `disabled` \| `paused`; omitted otherwise; see [Rule reason](#rule-reason) |

### Explanation

Result of `diag.explain`. `kind` decides which fields may be set.

| Field | Type | Description |
|---|---|---|
| `query` | string | normalized: lowercase, no trailing dot; an IPv4-mapped IPv6 address unmapped |
| `kind` | string | `domain` \| `ip` |
| `rule` | [RuleStatus](#rulestatus) | the matched rule; omitted when none |
| `skipped` | [RuleStatus](#rulestatus) | `domain`: the best rule by domain, passed over because it is in fallback `default`; omitted when none |
| `upstream` | string | `domain`: the DNS upstream: a tunnel name, `system` or `block` |
| `zone` | string | `domain`: the `dns_domains` zone that chose the tunnel; omitted when none |
| `servers` | string[] | `domain`: DNS servers of the tunnel upstream; omitted when none; **redacted** |
| `drop_aaaa` | bool | `domain`: AAAA answers are dropped; omitted when false |
| `addrs` | string[] | `domain`: addresses the daemon currently routes for the name (from DNS answers); omitted when none |
| `route` | [RouteInfo](#routeinfo) | `ip`: the longest-prefix route of the table; omitted when none (the system default route applies) |

For `kind: ip`, `rule` is set too when the route comes from a rule. Without
an applied config a domain gets `upstream: system`.

### Routes

Result of `diag.routes`.

| Field | Type | Description |
|---|---|---|
| `routes` | [RouteInfo](#routeinfo)[] | the last synced table, by prefix |
| `sync_error` | string | error of the last sync with the kernel; omitted when none |

### RouteInfo

| Field | Type | Description |
|---|---|---|
| `prefix` | string | CIDR |
| `target` | string | `tunnel` \| `direct` \| `reject`; a tunnel route whose tunnel has no utun yet (starting or failed) is shown as `reject` with `tunnel` kept, as it is in the kernel |
| `tunnel` | string | the tunnel of a `tunnel` target; omitted when none |
| `source` | string | `endpoint` \| `allowed-ips` \| `rule-cidr` \| `dynamic` |
| `rule` | int | index of the rule in the config; `-1`: none |
| `names` | string[] | `source: dynamic`: domain names whose DNS answers gave the address; omitted when none; **redacted** |
| `skipped` | string | the route is not in the kernel, why (`no physical gateway`, `a route not added by wgplex exists`); omitted when it is |

### ApplyResult

Result of `config.reload`.

| Field | Type | Description |
|---|---|---|
| `warnings` | string[] | warnings of the applied config; always present |
| `tunnels` | [TunnelError](#tunnelerror)[] | enabled tunnels that failed to start; omitted when none |

### TunnelError

| Field | Type | Description |
|---|---|---|
| `name` | string | tunnel name |
| `error` | string | why it failed to start |

### EnableResult

Result of `tunnel.enable`.

| Field | Type | Description |
|---|---|---|
| `starts_on_resume` | bool | `true`: the daemon is paused, the toggle is on, the tunnel comes up on `daemon.resume`; omitted otherwise (the result is `{}`) |

## Redaction

A caller that can control (`can_control: true`) sees everything. For any
other caller `status.get`, `diag.explain` and `diag.routes` return a
redacted reply: the listed fields are removed (omitted from the JSON), the
shape of the reply is otherwise the same.

| Method | Removed | Instead |
|---|---|---|
| `status.get` | `tunnels[].peers[].endpoint`, `tunnels[].peers[].resolved` | — |
| `status.get` | `tunnels[].check.addr` (the URL may contain a token) | — |
| `status.get` | `config_errors` | `config_error_count` |
| `status.get` | `warnings` | `warning_count` |
| `diag.explain` | `servers` | — |
| `diag.explain` | `route.names` | — |
| `diag.routes` | `routes[].names` (names other users resolved) | — |

Kept for everybody: names, toggles and states of tunnels, their interfaces,
addresses, route counts, handshakes and traffic, check results; services,
`via`, the serving tunnel, fallback and `reason` of rules; `configured`,
`paused`, `icon`, `control_group`, `config_dir`, `log_path`, `version`.

The redaction is a list of removed fields: a field added to the API later is
visible to everybody unless this list is extended.

The daemon log (`log_path`) is mode `0640`, group `control_group`: callers
that cannot control usually cannot read it.

## State semantics

### enabled vs state

`enabled` of a tunnel is its **toggle**, not "running": the value set by
`tunnel.enable` / `tunnel.disable` / `tunnel.disableAll` and persisted in the
state file; a tunnel never toggled follows `autostart` of the config. The
toggle is kept on pause.

`state` is what actually runs:

| `state` | Meaning |
|---|---|
| `off` | not running: toggled off, or paused |
| `starting` | being brought up, no utun yet |
| `up` | running, healthy |
| `dead` | running (utun exists), but the health check considers it dead; `reason` says why |
| `error` | failed to start; `error` says why; retried on network changes and every 60 s |

On pause every tunnel is `off` while `enabled` keeps the toggles.

### paused

`paused: true` after `daemon.pause` until `daemon.resume`, across daemon
restarts. While paused:

- no tunnel runs; `config.reload` and daemon start bring none up;
- `tunnel.enable` and `tunnel.disable` change only the toggle;
  `tunnel.enable` returns `starts_on_resume: true`;
- rules with `via` are in fallback with `reason: paused`; `fallback: block`
  keeps blocking;
- the system DNS capture does not change.

### starts_on_resume

`true` in the result of `tunnel.enable` when the daemon is paused: the toggle
is on, nothing was brought up, the tunnel starts on `daemon.resume`. The app
shows the tunnel as enabled with a "starts on resume" mark.

### Rule reason

A rule is `degraded` when its `via` is not empty and it is not served by
`via[0]`: on a backup tunnel or in fallback. Only then `reason` is set:

1. `paused` — the daemon is paused;
2. `dead` — some tunnel of `via` above the serving one (all of `via` in
   fallback) is toggled on but is dead, failed or not up yet;
3. `disabled` — all those tunnels are toggled off.

`dead` is a failure; `disabled` and `paused` are deliberate. A client uses
`reason` to tell them apart.

### Icon

`icon` summarizes the state for a menu bar icon, first match wins:

| Condition | `icon` |
|---|---|
| no config applied (`configured: false`), or the system DNS capture failed | `warn` |
| paused | `paused` |
| config errors (`config_error_count > 0`), or a tunnel in `dead` or `error` | `warn` |
| at least one tunnel `up` | `on` |
| otherwise | `off` |

A tunnel in `starting` and a rule in fallback because its tunnels are
toggled off do not change the icon.

### configured

`configured: false` means no config has been applied since the daemon
started (invalid config at start, or no config directory). With
`config_errors` it reads as "running without tunnels". In this state the
daemon still enforces the block snapshot of the last applied config: rules
with `fallback: block` keep blocking. `tunnel.*` return error `2`;
`daemon.pause` and `daemon.resume` work.

## Versioning and compatibility

- `api_version` (in `status.get`) is an integer, currently `1`.
- Within one `api_version` fields and methods are only added, never removed
  or changed in meaning. Clients must ignore unknown fields.
- An incompatible change raises `api_version`.
- `version` is the engine version (semver). The engine and the app are
  versioned independently; the app knows the minimum `api_version` it needs.
- After `brew upgrade wgplex` the running daemon keeps the old version until
  `sudo brew services restart --sudo-service-user=root wgplex`. The CLI warns
  when its version differs from `version` of the daemon.
