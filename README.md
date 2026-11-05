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
