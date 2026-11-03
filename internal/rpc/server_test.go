package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrFokin/jrpc/v2"
)

// Tests follow design 5 and 14 (JSON-RPC 2.0 over the unix socket, POST
// /rpc, socket 0666, a stale file removed, a second instance refused, rights
// per method: a caller that cannot control reads redacted replies and gets
// error 5 on mutating methods, no HTTP 403; the error codes), not the
// implementation. The socket lives in
// os.MkdirTemp("", "wgp"): t.TempDir() is too long for sun_path.
// No root and no network: the client is net/http over the unix socket.

// --- fake daemon ----------------------------------------------------------------

type recordedCall struct {
	method  string
	name    string
	enabled bool
}

// fakeDaemon records calls and returns what the test set.
type fakeDaemon struct {
	mu          sync.Mutex
	calls       []recordedCall
	applyResult ApplyResult
	applyErr    error
	setErr      error
	disableErr  error
	state       *State
}

func (d *fakeDaemon) Reload() (ApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "Reload"})
	return d.applyResult, d.applyErr
}

func (d *fakeDaemon) Enable(name string) (EnableResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "Enable", name: name, enabled: true})
	return EnableResult{}, d.setErr
}

func (d *fakeDaemon) Disable(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "Disable", name: name})
	return d.setErr
}

func (d *fakeDaemon) Pause() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "Pause"})
	return nil
}

func (d *fakeDaemon) Resume() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "Resume"})
	return nil
}

func (d *fakeDaemon) DisableAll() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "DisableAll"})
	return d.disableErr
}

func (d *fakeDaemon) State() *State {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedCall{method: "State"})
	if d.state == nil {
		return &State{}
	}
	return d.state
}

func (d *fakeDaemon) Calls() []recordedCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls)
}

// mutating lists the calls that change the daemon (not State).
func (d *fakeDaemon) mutating() []recordedCall {
	var out []recordedCall
	for _, c := range d.Calls() {
		if c.method != "State" {
			out = append(out, c)
		}
	}
	return out
}

// --- server harness --------------------------------------------------------------

// sockDir is a short temporary folder for the socket.
func sockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	var ln net.Listener
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Listen panicked: %v", r)
			}
		}()
		ln, err = Listen(path)
	}()
	if err != nil {
		t.Fatalf("Listen(%s): %v", path, err)
	}
	return ln
}

// testServer is a running Serve.
type testServer struct {
	path   string
	client *http.Client
	cancel context.CancelFunc
	done   chan error
}

// owner is an Access under which the test process owns the config
// directory: it controls.
func owner() *Access {
	return &Access{OwnerUID: func() (uint32, bool) { return uint32(os.Getuid()), true }}
}

// stranger is an Access under which the test process (not root) cannot
// control: another owner, control_group "wgpctl" without it.
func stranger(t *testing.T) *Access {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root always controls")
	}
	return &Access{
		OwnerUID:    func() (uint32, bool) { return uint32(os.Getuid()) + 1, true },
		ConfigGroup: func() string { return "wgpctl" },
		IsMember:    func(uint32, string) (bool, error) { return false, nil },
	}
}

// startServe listens in a fresh folder and serves d under acc; nil: owner().
// The server is stopped at cleanup.
func startServe(t *testing.T, d Daemon, acc *Access) *testServer {
	t.Helper()
	path := filepath.Join(sockDir(t), "s.sock")
	ln := listenUnix(t, path)
	return serveOn(t, path, ln, d, acc, Meta{})
}

func serveOn(t *testing.T, path string, ln net.Listener, d Daemon, acc *Access, meta Meta) *testServer {
	t.Helper()
	if acc == nil {
		acc = owner()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &testServer{path: path, cancel: cancel, done: make(chan error, 1), client: unixClient(path)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.done <- errors.New("Serve panicked")
			}
		}()
		s.done <- Serve(ctx, ln, d, acc, meta, log)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(15 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return s
}

// unixClient is an HTTP client that dials the unix socket path.
func unixClient(path string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
			DisableKeepAlives: true,
		},
	}
}

// reply is a JSON-RPC response.
type reply struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *jrpc.JRPCError `json:"error"`
}

// post sends body to Path with the content type and returns the status and body.
func (s *testServer) post(t *testing.T, contentType string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := s.client.Post("http://wgplex"+Path, contentType, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// call sends one JSON-RPC request; params nil sends none.
func (s *testServer) call(t *testing.T, method string, params any) reply {
	t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "id": 7, "method": method}
	if params != nil {
		req["params"] = params
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	code, b := s.post(t, "application/json", body)
	var r reply
	if code != http.StatusOK {
		t.Fatalf("%s: HTTP %d %s", method, code, b)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("%s: reply %s: %v", method, b, err)
	}
	if string(r.ID) != "7" {
		t.Errorf("%s: id %s, want 7", method, r.ID)
	}
	return r
}

func wantResult(t *testing.T, method string, r reply) {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("%s: error %+v, want a result", method, *r.Error)
	}
}

func wantCode(t *testing.T, method string, r reply, code int) {
	t.Helper()
	if r.Error == nil {
		t.Fatalf("%s: result %s, want error %d", method, r.Result, code)
	}
	if r.Error.Code != code {
		t.Errorf("%s: error %+v, want code %d", method, *r.Error, code)
	}
}

// sameJSON compares the JSON of a reply result with the JSON of want.
func sameJSON(t *testing.T, method string, got json.RawMessage, want any) {
	t.Helper()
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("%s: result %s: %v", method, got, err)
	}
	if err := json.Unmarshal(w, &b); err != nil {
		t.Fatal(err)
	}
	ga, _ := json.Marshal(a)
	gb, _ := json.Marshal(b)
	if !bytes.Equal(ga, gb) {
		t.Errorf("%s: result %s\nwant %s", method, ga, gb)
	}
}

// --- methods ------------------------------------------------------------------------

// design 14: config.reload (no params) makes the daemon re-read its config
// directory and returns its result.
func TestServeReload(t *testing.T) {
	d := &fakeDaemon{applyResult: ApplyResult{
		Warnings: []string{`service "tg" is not used by any rule`},
		Tunnels:  []TunnelError{{Name: "bad", Error: "resolve endpoints: no such host"}},
	}}
	s := startServe(t, d, nil)
	r := s.call(t, "config.reload", nil)
	wantResult(t, "config.reload", r)
	sameJSON(t, "config.reload", r.Result, d.applyResult)

	calls := d.mutating()
	if len(calls) != 1 || calls[0].method != "Reload" {
		t.Errorf("daemon calls = %+v, want one Reload", calls)
	}
}

// CodeConfigInvalid passes as is, with ConfigErrorData in data.
func TestServeReloadConfigInvalid(t *testing.T) {
	data := ConfigErrorData{
		Errors:   []string{`tunnel "x": conf "x.conf" not found`},
		Warnings: []string{"w1"},
	}
	d := &fakeDaemon{applyErr: jrpc.NewError(CodeConfigInvalid, "config is invalid", data)}
	s := startServe(t, d, nil)
	r := s.call(t, "config.reload", nil)
	wantCode(t, "config.reload", r, CodeConfigInvalid)
	if r.Error.Message != "config is invalid" {
		t.Errorf("message %q", r.Error.Message)
	}
	js, _ := json.Marshal(r.Error.Data)
	var got ConfigErrorData
	if err := json.Unmarshal(js, &got); err != nil {
		t.Fatalf("data %s: %v", js, err)
	}
	if !sameStrings(got.Errors, data.Errors) || !sameStrings(got.Warnings, data.Warnings) {
		t.Errorf("data = %+v, want %+v", got, data)
	}
}

// design 14: tunnel.enable passes the name and returns EnableResult;
// tunnel.disable passes the name and returns null.
func TestServeEnableDisable(t *testing.T) {
	d := &fakeDaemon{}
	s := startServe(t, d, nil)
	r := s.call(t, "tunnel.enable", EnableParams{Name: "de"})
	wantResult(t, "tunnel.enable", r)
	sameJSON(t, "tunnel.enable", r.Result, EnableResult{})
	r = s.call(t, "tunnel.disable", EnableParams{Name: "de"})
	wantResult(t, "tunnel.disable", r)
	if string(r.Result) != "null" {
		t.Errorf("tunnel.disable: result %s, want null", r.Result)
	}
	calls := d.mutating()
	if len(calls) != 2 ||
		calls[0].method != "Enable" || calls[0].name != "de" ||
		calls[1].method != "Disable" || calls[1].name != "de" {
		t.Errorf("daemon calls = %+v", calls)
	}
}

// The daemon codes pass as is; any other error is Internal error.
func TestServeEnableDisableErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{jrpc.NewError(CodeNoConfig, "no config applied", nil), CodeNoConfig},
		{jrpc.NewError(CodeUnknownTunnel, `unknown tunnel "nosuch"`, nil), CodeUnknownTunnel},
		{jrpc.NewError(CodeTunnelStart, "resolve endpoints: no such host", nil), CodeTunnelStart},
		{errors.New("boom"), -32603},
	}
	for _, c := range cases {
		d := &fakeDaemon{setErr: c.err}
		s := startServe(t, d, nil)
		for _, m := range []string{"tunnel.enable", "tunnel.disable"} {
			r := s.call(t, m, EnableParams{Name: "nosuch"})
			wantCode(t, m, r, c.code)
			var je *jrpc.JRPCError
			if errors.As(c.err, &je) && r.Error != nil && r.Error.Message != je.Message {
				t.Errorf("%s: message %q, want %q", m, r.Error.Message, je.Message)
			}
		}
	}
}

// An empty tunnel name and params that do not bind are Invalid params.
func TestServeEnableInvalidParams(t *testing.T) {
	d := &fakeDaemon{}
	s := startServe(t, d, nil)
	for _, m := range []string{"tunnel.enable", "tunnel.disable"} {
		wantCode(t, m+" empty name", s.call(t, m, EnableParams{}), -32602)
		wantCode(t, m+" bad types", s.call(t, m, map[string]any{"name": 5}), -32602)
	}
	if calls := d.mutating(); len(calls) != 0 {
		t.Errorf("daemon called with invalid params: %+v", calls)
	}
}

// design 12, 14: daemon.pause and daemon.resume take no params and return null.
func TestServePauseResume(t *testing.T) {
	d := &fakeDaemon{}
	s := startServe(t, d, nil)
	for _, m := range []string{"daemon.pause", "daemon.resume"} {
		r := s.call(t, m, nil)
		wantResult(t, m, r)
		if string(r.Result) != "null" {
			t.Errorf("%s: result %s, want null", m, r.Result)
		}
	}
	if calls := d.mutating(); len(calls) != 2 || calls[0].method != "Pause" || calls[1].method != "Resume" {
		t.Errorf("daemon calls = %+v, want Pause, Resume", calls)
	}
}

// design 14: tunnel.disableAll takes no params and returns null.
func TestServeDisableAll(t *testing.T) {
	d := &fakeDaemon{}
	s := startServe(t, d, nil)
	r := s.call(t, "tunnel.disableAll", nil)
	wantResult(t, "tunnel.disableAll", r)
	if string(r.Result) != "null" {
		t.Errorf("result %s, want null", r.Result)
	}
	if calls := d.mutating(); len(calls) != 1 || calls[0].method != "DisableAll" {
		t.Errorf("daemon calls = %+v, want one DisableAll", calls)
	}

	d2 := &fakeDaemon{disableErr: errors.New("sync: boom")}
	s2 := startServe(t, d2, nil)
	wantCode(t, "tunnel.disableAll", s2.call(t, "tunnel.disableAll", nil), -32603)
}

// design 14: status.get, diag.routes, diag.explain answer from a State
// snapshot through StatusOf, RoutesOf, Explain.
func TestServeReads(t *testing.T) {
	f := newFixture(t)
	st := newState(f)
	d := &fakeDaemon{state: st}
	s := startServe(t, d, nil)

	r := s.call(t, "status.get", nil)
	wantResult(t, "status.get", r)
	want := statusOf(t, st)
	want.APIVersion, want.CanControl = APIVersion, true
	sameJSON(t, "status.get", r.Result, want)

	r = s.call(t, "diag.routes", nil)
	wantResult(t, "diag.routes", r)
	sameJSON(t, "diag.routes", r.Result, routesOf(t, st))

	for _, q := range []string{"ifconfig.me", "34.160.111.145"} {
		r = s.call(t, "diag.explain", ExplainParams{Query: q})
		wantResult(t, "diag.explain", r)
		want, err := explainOf(t, st, q)
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, "diag.explain "+q, r.Result, want)
	}

	r = s.call(t, "diag.explain", ExplainParams{Query: "не_домен!"})
	wantCode(t, "diag.explain invalid", r, -32602)

	if calls := d.mutating(); len(calls) != 0 {
		t.Errorf("reads changed the daemon: %+v", calls)
	}
}

// An empty daemon (no config) answers status.get: not configured, icon warn
// (design 14).
func TestServeStatusEmpty(t *testing.T) {
	s := startServe(t, &fakeDaemon{}, nil)
	r := s.call(t, "status.get", nil)
	wantResult(t, "status.get", r)
	var st Status
	if err := json.Unmarshal(r.Result, &st); err != nil {
		t.Fatal(err)
	}
	if st.Configured || st.Icon != "warn" {
		t.Errorf("status = %+v, want not configured, icon warn", st)
	}
}

func TestServeUnknownMethod(t *testing.T) {
	s := startServe(t, &fakeDaemon{}, nil)
	wantCode(t, "nosuch.method", s.call(t, "nosuch.method", nil), -32601)
}

// --- access -------------------------------------------------------------------------

// design 5, 14: CanControl gets the uid of the peer (LOCAL_PEERCRED): here
// our own. status.get carries api_version, meta, can_control and
// control_group.
func TestServeAccessGetsUID(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root controls without IsMember")
	}
	var mu sync.Mutex
	var uids []uint32
	acc := &Access{
		ConfigGroup: func() string { return "wgpctl" },
		IsMember: func(uid uint32, _ string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			uids = append(uids, uid)
			return true, nil
		},
	}
	path := filepath.Join(sockDir(t), "s.sock")
	meta := Meta{Version: "1.2.3", ConfigDir: "/etc/wgplex", LogPath: "/var/log/wgplex.log"}
	s := serveOn(t, path, listenUnix(t, path), &fakeDaemon{}, acc, meta)
	r := s.call(t, "status.get", nil)
	wantResult(t, "status.get", r)
	var st Status
	if err := json.Unmarshal(r.Result, &st); err != nil {
		t.Fatal(err)
	}
	if st.APIVersion != APIVersion || st.Version != meta.Version || st.ConfigDir != meta.ConfigDir ||
		st.LogPath != meta.LogPath || !st.CanControl || st.ControlGroup != "wgpctl" {
		t.Errorf("status = %+v, want api_version, meta, can_control, control_group wgpctl", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(uids) == 0 {
		t.Fatal("IsMember was not called")
	}
	for _, u := range uids {
		if u != uint32(os.Getuid()) {
			t.Errorf("IsMember got uid %d, want %d", u, os.Getuid())
		}
	}
}

// design 5, 14: a caller that cannot control gets error 5 with control_group
// on every mutating method, a JSON-RPC error over HTTP 200, not HTTP 403; the
// daemon is not changed.
func TestServeNoPermission(t *testing.T) {
	d := &fakeDaemon{}
	s := startServe(t, d, stranger(t))
	for _, c := range []struct {
		method string
		params any
	}{
		{"config.reload", nil},
		{"tunnel.enable", EnableParams{Name: "de"}},
		{"tunnel.disable", EnableParams{Name: "de"}},
		{"tunnel.disableAll", nil},
		{"daemon.pause", nil},
		{"daemon.resume", nil},
	} {
		r := s.call(t, c.method, c.params)
		wantCode(t, c.method, r, CodeNoPermission)
		js, _ := json.Marshal(r.Error.Data)
		var data PermissionData
		if err := json.Unmarshal(js, &data); err != nil || data.ControlGroup != "wgpctl" {
			t.Errorf("%s: data %s, want control_group wgpctl", c.method, js)
		}
	}
	if calls := d.mutating(); len(calls) != 0 {
		t.Errorf("daemon changed for a caller that cannot control: %+v", calls)
	}
}

// design 5, Visibility: a caller that cannot control reads status.get and
// diag.*, redacted; can_control false.
func TestServeReadsRedacted(t *testing.T) {
	f := newFixture(t)
	st := newState(f)
	s := startServe(t, &fakeDaemon{state: st}, stranger(t))

	r := s.call(t, "status.get", nil)
	wantResult(t, "status.get", r)
	want := RedactStatus(statusOf(t, st))
	want.APIVersion, want.ControlGroup = APIVersion, "wgpctl"
	sameJSON(t, "status.get", r.Result, want)
	var got Status
	if err := json.Unmarshal(r.Result, &got); err != nil {
		t.Fatal(err)
	}
	if got.CanControl || len(got.Warnings) != 0 || got.WarningCount != len(st.Warnings) {
		t.Errorf("status = %+v, want can_control false, warnings hidden, warning_count %d", got, len(st.Warnings))
	}

	r = s.call(t, "diag.routes", nil)
	wantResult(t, "diag.routes", r)
	sameJSON(t, "diag.routes", r.Result, RedactRoutes(routesOf(t, st)))

	r = s.call(t, "diag.explain", ExplainParams{Query: "ifconfig.me"})
	wantResult(t, "diag.explain", r)
	e, err := explainOf(t, st, "ifconfig.me")
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, "diag.explain", r.Result, RedactExplanation(e))
}

// Not JSON is 415.
func TestServeNotJSON(t *testing.T) {
	s := startServe(t, &fakeDaemon{}, nil)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"status.get"}`)
	if code, _ := s.post(t, "text/plain", body); code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: HTTP %d, want 415", code)
	}
}

// --- Listen ---------------------------------------------------------------------------

// design 14: the socket is 0666; access is checked per connection.
func TestListenMode(t *testing.T) {
	path := filepath.Join(sockDir(t), "s.sock")
	ln := listenUnix(t, path)
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("%s: mode %v, not a socket", path, fi.Mode())
	}
	if fi.Mode().Perm() != 0o666 {
		t.Errorf("%s: perm %v, want 0666", path, fi.Mode().Perm())
	}
}

// design 14: a socket file nobody answers on (after a crash) is removed and
// the socket is created again.
func TestListenStale(t *testing.T) {
	path := filepath.Join(sockDir(t), "s.sock")
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file not left: %v", err)
	}

	ln := listenUnix(t, path)
	s := serveOn(t, path, ln, &fakeDaemon{}, nil, Meta{})
	wantResult(t, "status.get", s.call(t, "status.get", nil))
}

// design 14: a socket that answers is another wgplex daemon: Listen fails and
// the first one keeps answering.
func TestListenRunning(t *testing.T) {
	s := startServe(t, &fakeDaemon{}, nil)
	wantResult(t, "status.get", s.call(t, "status.get", nil))

	var ln net.Listener
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Listen panicked: %v", r)
			}
		}()
		ln, err = Listen(s.path)
	}()
	if err == nil {
		ln.Close()
		t.Fatal("Listen on a live socket: no error")
	}
	wantResult(t, "status.get after the second Listen", s.call(t, "status.get", nil))
}

// Listen doc: a file at the path that is not a socket is an
// error and is left alone: still there, same content.
func TestListenNotSocket(t *testing.T) {
	cases := []struct {
		name string
		make func(path string) error
	}{
		{"regular file", func(p string) error { return os.WriteFile(p, []byte("keep me\n"), 0o600) }},
		{"empty file", func(p string) error { return os.WriteFile(p, nil, 0o600) }},
		{"directory", func(p string) error { return os.Mkdir(p, 0o700) }},
	}
	for _, c := range cases {
		path := filepath.Join(sockDir(t), "s.sock")
		if err := c.make(path); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		var content []byte
		if before.Mode().IsRegular() {
			content, _ = os.ReadFile(path)
		}

		var ln net.Listener
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: Listen panicked: %v", c.name, r)
				}
			}()
			ln, err = Listen(path)
		}()
		if err == nil {
			ln.Close()
			t.Errorf("%s: Listen succeeded, want an error", c.name)
		}

		after, err := os.Lstat(path)
		if err != nil {
			t.Errorf("%s: file gone after Listen: %v", c.name, err)
			continue
		}
		if after.Mode() != before.Mode() {
			t.Errorf("%s: mode %v, was %v", c.name, after.Mode(), before.Mode())
		}
		if before.Mode().IsRegular() {
			if got, _ := os.ReadFile(path); !bytes.Equal(got, content) {
				t.Errorf("%s: content %q, was %q", c.name, got, content)
			}
		}
	}
}

// --- Serve shutdown -----------------------------------------------------------------

// Serve returns nil once ctx is done.
func TestServeStops(t *testing.T) {
	path := filepath.Join(sockDir(t), "s.sock")
	ln := listenUnix(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- errors.New("Serve panicked")
			}
		}()
		done <- Serve(ctx, ln, &fakeDaemon{}, &Access{}, Meta{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	s := &testServer{path: path, client: unixClient(path)}
	// Wait until it answers, then stop it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := s.client.Post("http://wgplex"+Path, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"status.get"}`))
		if err == nil {
			resp.Body.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Serve returned before cancel: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server does not answer: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil after cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if _, err := net.Dial("unix", path); err == nil {
		t.Error("socket still accepts connections after Serve returned")
	}
	// Listen doc: the listener removes the file when closed; Serve shuts
	// down and closes ln, so the socket file is gone.
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file after Serve returned: %v, want removed", err)
	}
}
