#!/usr/bin/env bash
# vm.sh — disposable tart VMs for wgplex checks.
#
# Builds the wgp-base image and manages its clones wgp-check-<name>.
# Only wgp-check-* VMs are ever started, stopped, changed or deleted;
# wgp-base is only cloned (and deleted by `base --force`). Other VMs
# in ~/.tart are never touched.
#
# Dependencies: tart, ssh, scp, ssh-keygen.

set -euo pipefail

readonly PREFIX="wgp-check-"
readonly BASE="wgp-base"
readonly BUILD="${PREFIX}base"
readonly SOURCE_IMAGE="ghcr.io/cirruslabs/macos-tahoe-vanilla:latest"
readonly AGENT_URL="https://github.com/cirruslabs/tart-guest-agent/releases/latest/download/tart-guest-agent-darwin-all.tar.gz"
readonly USER_NAME="admin"
readonly USER_PASSWORD="admin" # default password of the vanilla image
readonly KEY="${HOME}/.ssh/wgplex-vm"
readonly TART_DIR="${TART_HOME:-${HOME}/.tart}"
readonly BRIDGE_IF="${WGP_VM_IF:-en0}"
readonly WAIT_SECONDS=300

if [[ -n "${TART:-}" ]]; then
	:
elif command -v tart >/dev/null 2>&1; then
	TART="$(command -v tart)"
else
	TART="${HOME}/bin/tart"
fi

SSH_OPTS=(
	-i "$KEY"
	-o IdentitiesOnly=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=10
	-o ServerAliveInterval=15
	-o ServerAliveCountMax=4
)

usage() {
	cat <<'EOF'
Usage: vm.sh <command> [args]

  base [--force]                  build wgp-base from macos-tahoe-vanilla
  up <name> [--gui] [--nat] [--dir <path>]
                                  clone wgp-base to wgp-check-<name>, start it
                                  in the background, wait for SSH, print the IP
  ssh <name> [cmd...]             ssh admin@<ip> with ~/.ssh/wgplex-vm
  cp <name> <src>... <dst>        scp -r host files into the VM (dst is a VM path)
  get <name> <src> <dst>          scp -r a VM path to the host
  ip <name>                       print the VM IP
  down <name>                     stop and delete wgp-check-<name>
  list                            list wgp-base and wgp-check-* VMs

<name> is a suffix: `vm.sh up dns` manages wgp-check-dns.
Network: bridged on $WGP_VM_IF (default en0); --nat uses tart NAT and sets
the VM DNS to 1.1.1.1 and 9.9.9.9. --gui opens the VM window. --dir shares
<path> read-only as "spike".
EOF
}

log() { printf '==> %s\n' "$*" >&2; }
die() {
	printf 'vm.sh: %s\n' "$*" >&2
	exit 1
}

# ---- names and guards -------------------------------------------------------

# vm_name turns a suffix into a wgp-check-* name.
vm_name() {
	local suffix="$1"
	[[ "$suffix" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "bad VM name '$suffix' (want [a-z0-9-]+)"
	printf '%s%s' "$PREFIX" "$suffix"
}

# guard refuses to act on anything but wgp-check-*.
guard() {
	[[ "$1" == "${PREFIX}"?* ]] || die "refusing to touch '$1': only ${PREFIX}* VMs are managed"
}

vm_dir() { printf '%s/vms/%s' "$TART_DIR" "$1"; }

vm_exists() { [[ -n "$1" && -d "$(vm_dir "$1")" ]]; }

vm_running() {
	"$TART" list --source local --format json |
		tr -d ' \n' | grep -Eq "\"Running\":true,[^}]*\"Name\":\"$1\"|\"Name\":\"$1\"[^}]*\"Running\":true"
}

# ---- guarded tart mutations -------------------------------------------------

tart_clone() { # <src> <dst wgp-check-*>
	guard "$2"
	log "tart clone $1 $2"
	"$TART" clone "$1" "$2"
}

tart_stop() {
	guard "$1"
	if vm_running "$1"; then
		log "tart stop $1"
		"$TART" stop "$1"
	fi
}

tart_delete() {
	guard "$1"
	vm_exists "$1" || return 0
	tart_stop "$1"
	log "tart delete $1"
	"$TART" delete "$1"
}

# tart_start <vm> <net: bridged|nat> <gui: 0|1> [dir]
tart_start() {
	local vm="$1" net="$2" gui="$3" dir="${4:-}"
	guard "$vm"
	local d
	d="$(vm_dir "$vm")"
	local args=(run "$vm")
	[[ "$net" == bridged ]] && args+=("--net-bridged=${BRIDGE_IF}")
	[[ "$gui" == 1 ]] || args+=(--no-graphics)
	[[ -n "$dir" ]] && args+=("--dir=spike:${dir}:ro")
	printf '%s\n' "$net" >"$d/wgp-net"
	log "tart ${args[*]} (log: $d/run.log)"
	nohup "$TART" "${args[@]}" </dev/null >"$d/run.log" 2>&1 &
	printf '%s\n' "$!" >"$d/run.pid"
	disown || true
}

# ---- addresses and ssh ------------------------------------------------------

vm_net() {
	local f
	f="$(vm_dir "$1")/wgp-net"
	if [[ -f "$f" ]]; then cat "$f"; else printf 'bridged'; fi
}

# vm_ip prints the current IP or fails.
vm_ip() {
	local vm="$1"
	if [[ "$(vm_net "$vm")" == nat ]]; then
		"$TART" ip "$vm" 2>/dev/null
	else
		"$TART" ip --resolver=arp "$vm" 2>/dev/null
	fi
}

# check_alive fails with the log tail if the background tart run exited.
check_alive() {
	local d pid
	d="$(vm_dir "$1")"
	pid="$(cat "$d/run.pid" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null && ! vm_running "$1"; then
		tail -n 20 "$d/run.log" >&2 || true
		die "$1: tart run exited, see $d/run.log"
	fi
}

wait_ip() {
	local vm="$1" deadline=$((SECONDS + WAIT_SECONDS)) ip
	log "waiting for $vm IP"
	while ((SECONDS < deadline)); do
		check_alive "$vm"
		if ip="$(vm_ip "$vm")" && [[ -n "$ip" ]]; then
			printf '%s' "$ip"
			return 0
		fi
		sleep 3
	done
	die "$vm: no IP after ${WAIT_SECONDS}s"
}

# wait_sshd waits until sshd answers (key or password, either is fine).
wait_sshd() {
	local vm="$1" ip="$2" deadline=$((SECONDS + WAIT_SECONDS)) out
	log "waiting for sshd on $ip"
	while ((SECONDS < deadline)); do
		check_alive "$vm"
		if out="$(ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o ConnectTimeout=5 "$USER_NAME@$ip" true 2>&1)"; then
			return 0
		fi
		[[ "$out" == *"Permission denied"* ]] && return 0
		sleep 3
	done
	die "$vm: sshd on $ip not reachable after ${WAIT_SECONDS}s"
}

ensure_key() {
	[[ -f "$KEY" ]] && return 0
	log "creating $KEY"
	mkdir -p "$(dirname "$KEY")"
	ssh-keygen -q -t ed25519 -N '' -C wgplex-vm -f "$KEY"
}

key_ok() { ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$USER_NAME@$1" true 2>/dev/null; }

# rssh runs a command in the VM with the key.
rssh() {
	local ip="$1"
	shift
	ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$USER_NAME@$ip" "$@"
}

ASKPASS_DIR=""
cleanup_askpass() { if [[ -n "$ASKPASS_DIR" ]]; then rm -rf "$ASKPASS_DIR"; fi; }

# pssh runs a command with password authentication only (no sshpass on the host).
pssh() {
	local ip="$1"
	shift
	if [[ -z "$ASKPASS_DIR" ]]; then
		ASKPASS_DIR="$(mktemp -d)"
		trap cleanup_askpass EXIT
		printf '#!/bin/sh\necho %s\n' "$USER_PASSWORD" >"$ASKPASS_DIR/askpass"
		chmod 700 "$ASKPASS_DIR/askpass"
	fi
	SSH_ASKPASS="$ASKPASS_DIR/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-:0}" \
		ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o ConnectTimeout=10 -o PubkeyAuthentication=no -o IdentitiesOnly=yes \
		-o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 \
		"$USER_NAME@$ip" "$@" </dev/null
}

# ---- commands ---------------------------------------------------------------

cmd_up() {
	local suffix="" gui=0 net=bridged dir=""
	while (($#)); do
		case "$1" in
		--gui) gui=1 ;;
		--nat) net=nat ;;
		--dir)
			(($# >= 2)) || die "--dir needs a path"
			dir="$2"
			shift
			;;
		--dir=*) dir="${1#--dir=}" ;;
		-*) die "up: unknown flag $1" ;;
		*)
			[[ -z "$suffix" ]] || die "up: extra argument $1"
			suffix="$1"
			;;
		esac
		shift
	done
	[[ -n "$suffix" ]] || die "up: <name> required"
	[[ "$suffix" != base ]] || die "up: name 'base' is reserved for 'vm.sh base'"
	local vm
	vm="$(vm_name "$suffix")"
	if [[ -n "$dir" ]]; then
		[[ -d "$dir" ]] || die "--dir: $dir is not a directory"
		dir="$(cd "$dir" && pwd)"
	fi
	ensure_key

	if vm_running "$vm"; then
		log "$vm is already running"
		vm_ip "$vm" || die "$vm: no IP yet"
		return 0
	fi
	if ! vm_exists "$vm"; then
		vm_exists "$BASE" || die "$BASE not found, run 'vm.sh base' first"
		tart_clone "$BASE" "$vm"
	fi
	tart_start "$vm" "$net" "$gui" "$dir"
	local ip
	ip="$(wait_ip "$vm")"
	wait_sshd "$vm" "$ip"
	key_ok "$ip" || die "$vm: key login to $ip failed"
	if [[ "$net" == nat ]]; then
		log "setting VM DNS to 1.1.1.1 9.9.9.9"
		rssh "$ip" bash -s <<'EOF'
set -euo pipefail
networksetup -listallnetworkservices | tail -n +2 | sed 's/^\*//' | while IFS= read -r svc; do
	sudo -n networksetup -setdnsservers "$svc" 1.1.1.1 9.9.9.9 </dev/null
done
EOF
	fi
	printf '%s\n' "$ip"
}

need_vm() { # <suffix> -> name of an existing VM
	local vm
	# Runs inside $(...), where bash 3.2 drops errexit: fail explicitly.
	vm="$(vm_name "$1")" || exit 1
	vm_exists "$vm" || die "$vm does not exist"
	printf '%s' "$vm"
}

cur_ip() {
	local vm="$1" ip
	ip="$(vm_ip "$vm")" && [[ -n "$ip" ]] || die "$vm: no IP (is it running?)"
	printf '%s' "$ip"
}

cmd_ip() {
	(($# == 1)) || die "usage: vm.sh ip <name>"
	local vm
	vm="$(need_vm "$1")"
	cur_ip "$vm"
	printf '\n'
}

cmd_ssh() {
	(($# >= 1)) || die "usage: vm.sh ssh <name> [cmd...]"
	local vm ip
	vm="$(need_vm "$1")"
	shift
	ip="$(cur_ip "$vm")"
	exec ssh "${SSH_OPTS[@]}" "$USER_NAME@$ip" "$@"
}

cmd_cp() {
	(($# >= 3)) || die "usage: vm.sh cp <name> <src>... <dst>"
	local vm ip
	vm="$(need_vm "$1")"
	shift
	ip="$(cur_ip "$vm")"
	local dst="${!#}"
	local srcs=("${@:1:$#-1}")
	exec scp -r "${SSH_OPTS[@]}" "${srcs[@]}" "$USER_NAME@$ip:$dst"
}

cmd_get() {
	(($# == 3)) || die "usage: vm.sh get <name> <src> <dst>"
	local vm ip
	vm="$(need_vm "$1")"
	ip="$(cur_ip "$vm")"
	exec scp -r "${SSH_OPTS[@]}" "$USER_NAME@$ip:$2" "$3"
}

cmd_down() {
	(($# == 1)) || die "usage: vm.sh down <name>"
	local vm
	vm="$(vm_name "$1")"
	if ! vm_exists "$vm"; then
		log "$vm does not exist"
		return 0
	fi
	tart_delete "$vm"
}

cmd_list() {
	(($# == 0)) || die "usage: vm.sh list"
	"$TART" list --source local | awk -v p="$PREFIX" -v b="$BASE" \
		'NR == 1 || $2 == b || index($2, p) == 1'
}

# ---- base -------------------------------------------------------------------

cmd_base() {
	local force=0
	while (($#)); do
		case "$1" in
		--force) force=1 ;;
		*) die "base: unknown argument $1" ;;
		esac
		shift
	done

	if vm_exists "$BASE" && ((force == 0)); then
		log "$BASE already exists (use --force to rebuild)"
		return 0
	fi
	if ((force)); then
		if vm_exists "$BASE"; then
			if vm_running "$BASE"; then die "$BASE is running, stop it first"; fi
			log "tart delete $BASE (--force)"
			"$TART" delete "$BASE"
		fi
		tart_delete "$BUILD" # start from scratch
	fi
	ensure_key

	if ! vm_exists "$BUILD"; then
		tart_clone "$SOURCE_IMAGE" "$BUILD"
	else
		log "reusing existing $BUILD"
	fi
	# NAT for the build: it does not depend on the Wi-Fi bridge and leaves
	# the image DNS settings untouched.
	if ! vm_running "$BUILD"; then
		tart_start "$BUILD" nat 0
	fi
	local ip
	ip="$(wait_ip "$BUILD")"
	wait_sshd "$BUILD" "$ip"
	log "$BUILD is at $ip"

	base_key "$ip"
	base_sudoers "$ip"
	base_sshd "$ip"
	base_brew "$ip"
	base_agent "$ip"

	tart_stop "$BUILD"
	log "tart clone $BUILD $BASE"
	"$TART" clone "$BUILD" "$BASE"
	tart_delete "$BUILD"
	log "$BASE is ready"
}

base_key() {
	local ip="$1"
	if key_ok "$ip"; then
		log "authorized_keys: key login works, skipping"
		return 0
	fi
	log "authorized_keys: installing $KEY.pub with a password login"
	local pub
	pub="$(cat "$KEY.pub")"
	pssh "$ip" "umask 077 && mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF '$pub' ~/.ssh/authorized_keys || printf '%s\n' '$pub' >> ~/.ssh/authorized_keys)" ||
		die "password login to $ip failed"
	key_ok "$ip" || die "key login to $ip still fails"
}

base_sudoers() {
	log "sudoers: /etc/sudoers.d/admin (NOPASSWD)"
	rssh "$1" bash -s "$USER_PASSWORD" <<'EOF'
set -euo pipefail
pw="$1"
if sudo -n test -f /etc/sudoers.d/admin 2>/dev/null; then
	echo "sudoers: already present"
	exit 0
fi
SUDO=(sudo -n)
sudo -n true 2>/dev/null || SUDO=(sudo -S -p '')
tmp="$(mktemp)"
echo 'admin ALL=(ALL) NOPASSWD: ALL' >"$tmp"
printf '%s\n' "$pw" | "${SUDO[@]}" sh -c "visudo -cf '$tmp' && mkdir -p /etc/sudoers.d && install -m 0440 -o root -g wheel '$tmp' /etc/sudoers.d/admin && visudo -c"
rm -f "$tmp"
sudo -n true
EOF
}

base_sshd() {
	local ip="$1"
	log "sshd: key-only login (drop-in in /etc/ssh/sshd_config.d)"
	rssh "$ip" bash -s <<'EOF'
set -euo pipefail
f=/etc/ssh/sshd_config.d/000-wgplex.conf
want=$'PasswordAuthentication no\nKbdInteractiveAuthentication no'
if [ "$(sudo -n cat "$f" 2>/dev/null || true)" != "$want" ]; then
	printf '%s\n' "$want" | sudo -n tee "$f" >/dev/null
	sudo -n chmod 0644 "$f"
fi
sudo -n sshd -t
sudo -n sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication) '
# sshd is socket-activated on macOS; kickstart is a no-op when it is idle.
sudo -n launchctl kickstart -k system/com.openssh.sshd 2>/dev/null || true
EOF
	log "sshd: checking that password login is rejected"
	local out
	if out="$(pssh "$ip" true 2>&1)"; then
		die "password login to $ip still works"
	fi
	[[ "$out" == *"Permission denied"* ]] || die "unexpected password login failure: $out"
	key_ok "$ip" || die "key login to $ip broke after sshd change"
}

base_brew() {
	log "homebrew: install if missing"
	rssh "$1" bash -s <<'EOF'
set -euo pipefail
if [ ! -x /opt/homebrew/bin/brew ]; then
	NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" </dev/null
else
	echo "homebrew: already installed"
fi
line='eval "$(/opt/homebrew/bin/brew shellenv)"'
touch ~/.zprofile
grep -qxF "$line" ~/.zprofile || printf '%s\n' "$line" >>~/.zprofile
/opt/homebrew/bin/brew --version
EOF
}

base_agent() {
	local ip="$1"
	if "$TART" exec "$BUILD" true >/dev/null 2>&1; then
		log "guest agent: tart exec works, skipping"
		return 0
	fi
	log "guest agent: installing from $AGENT_URL"
	rssh "$ip" bash -s "$AGENT_URL" <<'EOF'
set -euo pipefail
url="$1"
bin=/usr/local/bin/tart-guest-agent
plist=/Library/LaunchAgents/org.cirruslabs.tart-guest-agent.plist
if [ ! -x "$bin" ]; then
	tmp="$(mktemp -d)"
	curl -fsSL -o "$tmp/agent.tar.gz" "$url"
	tar -xzf "$tmp/agent.tar.gz" -C "$tmp"
	sudo -n mkdir -p /usr/local/bin
	sudo -n install -m 0755 -o root -g wheel "$tmp/tart-guest-agent" "$bin"
	rm -rf "$tmp"
fi
"$bin" --version || true
# Global agent: runs in the auto-login GUI session of admin, gives
# tart exec (as admin) and clipboard sharing.
sudo -n tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>org.cirruslabs.tart-guest-agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>$bin</string>
		<string>--run-agent</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>WorkingDirectory</key>
	<string>/Users/admin</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/tmp/tart-guest-agent.log</string>
	<key>StandardErrorPath</key>
	<string>/tmp/tart-guest-agent.log</string>
</dict>
</plist>
PLIST
sudo -n chown root:wheel "$plist"
sudo -n chmod 0644 "$plist"
uid="$(id -u)"
if ! launchctl print "gui/$uid/org.cirruslabs.tart-guest-agent" >/dev/null 2>&1; then
	sudo -n launchctl bootstrap "gui/$uid" "$plist"
fi
EOF
	log "guest agent: checking tart exec"
	local deadline=$((SECONDS + 60))
	until "$TART" exec "$BUILD" true >/dev/null 2>&1; do
		((SECONDS < deadline)) || die "tart exec $BUILD true still fails (see /tmp/tart-guest-agent.log in the VM)"
		sleep 3
	done
	log "guest agent: tart exec works"
}

# ---- main -------------------------------------------------------------------

main() {
	(($#)) || {
		usage
		exit 2
	}
	local cmd="$1"
	shift
	case "$cmd" in
	-h | --help | help)
		usage
		return 0
		;;
	esac
	[[ -x "$TART" ]] || die "tart not found (set TART or put it in PATH)"
	case "$cmd" in
	base) cmd_base "$@" ;;
	up) cmd_up "$@" ;;
	ssh) cmd_ssh "$@" ;;
	cp) cmd_cp "$@" ;;
	get) cmd_get "$@" ;;
	ip) cmd_ip "$@" ;;
	down) cmd_down "$@" ;;
	list) cmd_list "$@" ;;
	*)
		usage >&2
		exit 2
		;;
	esac
}

main "$@"
