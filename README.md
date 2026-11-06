# wgplex

Several WireGuard tunnels at once on macOS, with rule-based routing by domain
and CIDR. One binary is both the daemon (runs as root) and the CLI.

## Install

```sh
brew install mrfokin/tap/wgplex
```

Use the full name: Homebrew loads formulae from a third-party tap only when
it is trusted, and the full name trusts it.

## Run

```sh
sudo brew services start --sudo-service-user=root wgplex
```

Always pass `--sudo-service-user=root` to `start` and `restart`: without it
brew makes root the owner of the formula's files, and later `brew upgrade`,
`cleanup` and `uninstall` fail or leave garbage. `brew services` without
`sudo` manages a copy for your user, not the root service.

`brew upgrade` does not restart the service. After an upgrade:

```sh
sudo brew services restart --sudo-service-user=root wgplex
wgplex version   # CLI and daemon versions must match
```

## Configuration

The config directory is `$(brew --prefix)/etc/wgplex` (mode `0700`):
`wgplex.yaml` plus the tunnels' `.conf` files next to it (mode `0600`).
The installed `wgplex.yaml` is a commented template with an example.

```sh
wgplex check     # validate the config
wgplex reload    # apply it
wgplex status
```

Files are read only at start and on `wgplex reload`; edits are not picked up
automatically. A config with errors is not applied; on `reload` the previous
one keeps running.

### wgplex.yaml

| Key | Default | Meaning |
|---|---|---|
| `control_group` | `admin` | group, besides root and the config owner, that may control the daemon |
| `ipv6_filter` | `true` | drop AAAA answers for rule domains when the target tunnel has no IPv6 |
| `tunnels` | — | tunnels; list order is the priority for overlapping `AllowedIPs` |
| `services` | — | named sets of `domains` (suffix, or `=name` for an exact match) and/or `cidrs` |
| `rules` | — | `services` (required), `via` (ordered tunnels; empty means direct), `fallback` (`default` or `block`, default `default`) |

Each tunnel has `name`, `conf` (a `.conf` file name in the config directory),
`routes` (`config` puts `AllowedIPs` into the routing table, `rules` uses only
routes from the rules; required), and optional `autostart` (default `false`),
`dns_domains` (zones resolved through the DNS from the `.conf`) and `check`
(an IP to ping or an `http(s)` URL, through the tunnel).

### .conf files

Standard `wg-quick` format. `[Interface]` uses `PrivateKey` (required),
`Address`, `DNS` (IP addresses only), `MTU` (default `1420`) and `ListenPort`.
`[Peer]` (one or more) uses `PublicKey` (required), `PresharedKey`,
`AllowedIPs`, `Endpoint` and `PersistentKeepalive`. `Table`, `PreUp`, `PostUp`,
`PreDown`, `PostDown`, `SaveConfig` and `FwMark` are ignored with a warning.

The full reference, including validation rules and limits, is in
[docs/design.md](docs/design.md), section 10.

Logs: `$(brew --prefix)/var/log/wgplex/wgplex.log`.

## Uninstall

Strictly in this order:

```sh
sudo brew services stop wgplex   # unloads the service and removes its plist
brew uninstall wgplex
```

In the reverse order the plist stays behind and `brew services` no longer
sees it. On stop the daemon removes its routes and DNS capture. The config
directory `etc/wgplex` stays; `var/wgplex` and `var/log/wgplex` stay too
(owned by root, remove with `sudo rm -rf`).

## Limitations

With FileVault the daemon starts only after the disk is unlocked at preboot;
tunnels are down until then. For headless machines use no FileVault or
`fdesetup authrestart` for planned reboots.

## Build

Needs Go and the Command Line Tools (cgo).

```sh
make check     # gofmt, go vet, go test
make build     # universal build/wgplex, ad-hoc signed
make release   # build/wgplex-<version>-darwin-universal.tar.gz and .sha256
```

For development: `sudo ./build/wgplex daemon`.

## License

MIT, see [LICENSE](LICENSE).
