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

// Tests follow the Wirefork RPC contract (JSON-RPC 2.0 over the unix
// socket, POST /rpc, socket 0666, a stale file removed, a second instance
// refused, a foreign uid gets HTTP 403, the error codes — M1 keeps this,
// plan decisions 4-5; the per-method wgplex API with error 5, design 14,
// comes in M3) and the Wirefork M6 plan ("RPC", decisions 3,
// 5, 8; facts 1–4), not the implementation. The socket lives in
// os.MkdirTemp("", "wgp"): t.TempDir() is too long for sun_path (fact 4).
// No root and no network: the client is net/http over the unix socket.

// --- fake daemon ----------------------------------------------------------------

type m6Call struct {
	method  string
	name    string
	enabled bool
}

// m6FakeDaemon records calls and returns what the test set.
type m6FakeDaemon struct {
	mu           sync.Mutex
	calls        []m6Call
	reloadResult ReloadResult
	reloadErr    error
	setErr       error
	disableErr   error
	state        *State
}

func (d *m6FakeDaemon) Reload() (ReloadResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, m6Call{method: "Reload"})
	return d.reloadResult, d.reloadErr
}

func (d *m6FakeDaemon) SetEnabled(name string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, m6Call{method: "SetEnabled", name: name, enabled: enabled})
	return d.setErr
}

func (d *m6FakeDaemon) DisableAll() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, m6Call{method: "DisableAll"})
	return d.disableErr
}

func (d *m6FakeDaemon) State() *State {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, m6Call{method: "State"})
	if d.state == nil {
		return &State{}
	}
	return d.state
}

func (d *m6FakeDaemon) Calls() []m6Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls)
}

// mutating lists the calls that change the daemon (not State).
func (d *m6FakeDaemon) mutating() []m6Call {
	var out []m6Call
	for _, c := range d.Calls() {
		if c.method != "State" {
			out = append(out, c)
		}
	}
	return out
}

// --- server harness --------------------------------------------------------------

// m6SockDir is a short temporary folder for the socket (fact 4).
func m6SockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func m6Listen(t *testing.T, path string) net.Listener {
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

// m6Server is a running Serve.
type m6Server struct {
	path   string
	client *http.Client
	cancel context.CancelFunc
	done   chan error
}

// m6Serve listens in a fresh folder and serves d; allow nil allows any uid.
// The server is stopped at cleanup.
func m6Serve(t *testing.T, d Daemon, allow func(uint32) bool) *m6Server {
	t.Helper()
	path := filepath.Join(m6SockDir(t), "s.sock")
	ln := m6Listen(t, path)
	return m6ServeOn(t, path, ln, d, allow)
}

func m6ServeOn(t *testing.T, path string, ln net.Listener, d Daemon, allow func(uint32) bool) *m6Server {
	t.Helper()
	if allow == nil {
		allow = func(uint32) bool { return true }
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &m6Server{path: path, cancel: cancel, done: make(chan error, 1), client: m6Client(path)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.done <- errors.New("Serve panicked")
			}
		}()
		s.done <- Serve(ctx, ln, d, allow, log)
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

// m6Client is an HTTP client that dials the unix socket path.
func m6Client(path string) *http.Client {
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

// m6Reply is a JSON-RPC response.
type m6Reply struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *jrpc.JRPCError `json:"error"`
}

// post sends body to Path with the content type and returns the status and body.
func (s *m6Server) post(t *testing.T, contentType string, body []byte) (int, []byte) {
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
func (s *m6Server) call(t *testing.T, method string, params any) m6Reply {
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
	var r m6Reply
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

func m6WantResult(t *testing.T, method string, r m6Reply) {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("%s: error %+v, want a result", method, *r.Error)
	}
}

func m6WantCode(t *testing.T, method string, r m6Reply, code int) {
	t.Helper()
	if r.Error == nil {
		t.Fatalf("%s: result %s, want error %d", method, r.Result, code)
	}
	if r.Error.Code != code {
		t.Errorf("%s: error %+v, want code %d", method, *r.Error, code)
	}
}

// m6Same compares the JSON of a reply result with the JSON of want.
func m6Same(t *testing.T, method string, got json.RawMessage, want any) {
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

// M2: config.reload takes no params — the daemon reads its own config
// directory (design 10.2; formerly the client delivered the files). The
// result follows design 14.
func TestM6ServeReload(t *testing.T) {
	d := &m6FakeDaemon{reloadResult: ReloadResult{
		Warnings: []string{`service "tg" is not used by any rule`},
		Tunnels:  []TunnelError{{Name: "bad", Error: "resolve endpoints: no such host"}},
	}}
	s := m6Serve(t, d, nil)
	r := s.call(t, "config.reload", nil)
	m6WantResult(t, "config.reload", r)
	m6Same(t, "config.reload", r.Result, d.reloadResult)

	if calls := d.mutating(); len(calls) != 1 || calls[0].method != "Reload" {
		t.Errorf("daemon calls = %+v, want one Reload", calls)
	}
}

// Design 14: CodeConfigInvalid passes as is, with ConfigErrorData in data.
func TestM6ServeReloadConfigInvalid(t *testing.T) {
	data := ConfigErrorData{
		Errors:   []string{`tunnel "x": conf "x.conf" not found`},
		Warnings: []string{"w1"},
	}
	d := &m6FakeDaemon{reloadErr: jrpc.NewError(CodeConfigInvalid, "config is invalid", data)}
	s := m6Serve(t, d, nil)
	r := s.call(t, "config.reload", nil)
	m6WantCode(t, "config.reload", r, CodeConfigInvalid)
	if r.Error.Message != "config is invalid" {
		t.Errorf("message %q", r.Error.Message)
	}
	js, _ := json.Marshal(r.Error.Data)
	var got ConfigErrorData
	if err := json.Unmarshal(js, &got); err != nil {
		t.Fatalf("data %s: %v", js, err)
	}
	if !m6Strs(got.Errors, data.Errors) || !m6Strs(got.Warnings, data.Warnings) {
		t.Errorf("data = %+v, want %+v", got, data)
	}
}

// M1, decisions 4-5: tunnel.setEnabled is the Wirefork method and only root
// calls it; tunnel.enable/disable with per-method rights come in M3
// (design 14). It passes name and enabled; the result is null.
func TestM6ServeSetEnabled(t *testing.T) {
	d := &m6FakeDaemon{}
	s := m6Serve(t, d, nil)
	for _, on := range []bool{true, false} {
		r := s.call(t, "tunnel.setEnabled", SetEnabledParams{Name: "de", Enabled: on})
		m6WantResult(t, "tunnel.setEnabled", r)
		if string(r.Result) != "null" {
			t.Errorf("tunnel.setEnabled: result %s, want null", r.Result)
		}
	}
	calls := d.mutating()
	if len(calls) != 2 ||
		calls[0].method != "SetEnabled" || calls[0].name != "de" || !calls[0].enabled ||
		calls[1].method != "SetEnabled" || calls[1].name != "de" || calls[1].enabled {
		t.Errorf("daemon calls = %+v", calls)
	}
}

// Decision 5: the daemon codes pass as is; any other error is Internal error.
func TestM6ServeSetEnabledErrors(t *testing.T) {
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
		d := &m6FakeDaemon{setErr: c.err}
		s := m6Serve(t, d, nil)
		r := s.call(t, "tunnel.setEnabled", SetEnabledParams{Name: "nosuch", Enabled: true})
		m6WantCode(t, "tunnel.setEnabled", r, c.code)
		var je *jrpc.JRPCError
		if errors.As(c.err, &je) && r.Error != nil && r.Error.Message != je.Message {
			t.Errorf("message %q, want %q", r.Error.Message, je.Message)
		}
	}
}

// Wirefork M6 plan: an empty tunnel name and params that do not bind are Invalid params.
func TestM6ServeSetEnabledInvalidParams(t *testing.T) {
	d := &m6FakeDaemon{}
	s := m6Serve(t, d, nil)
	r := s.call(t, "tunnel.setEnabled", SetEnabledParams{Name: "", Enabled: true})
	m6WantCode(t, "empty name", r, -32602)
	r = s.call(t, "tunnel.setEnabled", map[string]any{"name": 5, "enabled": "yes"})
	m6WantCode(t, "bad types", r, -32602)
	if calls := d.mutating(); len(calls) != 0 {
		t.Errorf("daemon called with invalid params: %+v", calls)
	}
}

// M1, decisions 4-5: tunnel.disableAll is the Wirefork method; design 14
// names the wgplex method the same in M3. It takes no params, returns null.
func TestM6ServeDisableAll(t *testing.T) {
	d := &m6FakeDaemon{}
	s := m6Serve(t, d, nil)
	r := s.call(t, "tunnel.disableAll", nil)
	m6WantResult(t, "tunnel.disableAll", r)
	if string(r.Result) != "null" {
		t.Errorf("result %s, want null", r.Result)
	}
	if calls := d.mutating(); len(calls) != 1 || calls[0].method != "DisableAll" {
		t.Errorf("daemon calls = %+v, want one DisableAll", calls)
	}

	d2 := &m6FakeDaemon{disableErr: errors.New("sync: boom")}
	s2 := m6Serve(t, d2, nil)
	m6WantCode(t, "tunnel.disableAll", s2.call(t, "tunnel.disableAll", nil), -32603)
}

// M1, decisions 4-5: status.get, diag.routes, diag.explain are the Wirefork
// read methods (the same names in design 14); they answer from a State
// snapshot through StatusOf, RoutesOf, Explain.
func TestM6ServeReads(t *testing.T) {
	f := m6NewFixture(t)
	st := m6State(f)
	d := &m6FakeDaemon{state: st}
	s := m6Serve(t, d, nil)

	r := s.call(t, "status.get", nil)
	m6WantResult(t, "status.get", r)
	m6Same(t, "status.get", r.Result, m6StatusOf(t, st))

	r = s.call(t, "diag.routes", nil)
	m6WantResult(t, "diag.routes", r)
	m6Same(t, "diag.routes", r.Result, m6RoutesOf(t, st))

	for _, q := range []string{"ifconfig.me", "34.160.111.145"} {
		r = s.call(t, "diag.explain", ExplainParams{Query: q})
		m6WantResult(t, "diag.explain", r)
		want, err := m6Explain(t, st, q)
		if err != nil {
			t.Fatal(err)
		}
		m6Same(t, "diag.explain "+q, r.Result, want)
	}

	r = s.call(t, "diag.explain", ExplainParams{Query: "не_домен!"})
	m6WantCode(t, "diag.explain invalid", r, -32602)

	if calls := d.mutating(); len(calls) != 0 {
		t.Errorf("reads changed the daemon: %+v", calls)
	}
}

// An empty daemon (no config) answers status.get: not configured, icon off.
func TestM6ServeStatusEmpty(t *testing.T) {
	s := m6Serve(t, &m6FakeDaemon{}, nil)
	r := s.call(t, "status.get", nil)
	m6WantResult(t, "status.get", r)
	var st Status
	if err := json.Unmarshal(r.Result, &st); err != nil {
		t.Fatal(err)
	}
	if st.Configured || st.Icon != "off" {
		t.Errorf("status = %+v, want not configured, icon off", st)
	}
}

func TestM6ServeUnknownMethod(t *testing.T) {
	s := m6Serve(t, &m6FakeDaemon{}, nil)
	m6WantCode(t, "nosuch.method", s.call(t, "nosuch.method", nil), -32601)
}

// --- access -------------------------------------------------------------------------

// design 5, 14: allow gets the uid of the peer (LOCAL_PEERCRED): here our own.
func TestM6ServeAllowGetsUID(t *testing.T) {
	var mu sync.Mutex
	var uids []uint32
	allow := func(uid uint32) bool {
		mu.Lock()
		defer mu.Unlock()
		uids = append(uids, uid)
		return true
	}
	s := m6Serve(t, &m6FakeDaemon{}, allow)
	m6WantResult(t, "status.get", s.call(t, "status.get", nil))
	mu.Lock()
	defer mu.Unlock()
	if len(uids) == 0 {
		t.Fatal("allow was not called")
	}
	for _, u := range uids {
		if u != uint32(os.Getuid()) {
			t.Errorf("allow got uid %d, want %d", u, os.Getuid())
		}
	}
}

// Decision 4: a uid that allow refuses gets HTTP 403 with body
// "forbidden", no JSON-RPC; the daemon is not called. In M3 the refusal
// becomes the JSON-RPC error 5 (design 14).
func TestM6ServeForbidden(t *testing.T) {
	d := &m6FakeDaemon{}
	s := m6Serve(t, d, func(uint32) bool { return false })
	for _, method := range []string{"status.get", "tunnel.disableAll"} {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method})
		code, b := s.post(t, "application/json", body)
		if code != http.StatusForbidden {
			t.Errorf("%s: HTTP %d, want 403", method, code)
		}
		if !strings.Contains(string(b), "forbidden") || strings.Contains(string(b), "jsonrpc") {
			t.Errorf("%s: body %q, want \"forbidden\" without JSON-RPC", method, b)
		}
	}
	if calls := d.Calls(); len(calls) != 0 {
		t.Errorf("daemon called for a forbidden uid: %+v", calls)
	}
}

// Wirefork M6 fact 1: not JSON is 415.
func TestM6ServeNotJSON(t *testing.T) {
	s := m6Serve(t, &m6FakeDaemon{}, nil)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"status.get"}`)
	if code, _ := s.post(t, "text/plain", body); code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: HTTP %d, want 415", code)
	}
}

// Decision 4: the uid check comes before anything else: a forbidden peer
// gets 403 even with a body that is not JSON (not 415).
func TestM6ServeForbiddenNotJSON(t *testing.T) {
	d := &m6FakeDaemon{}
	s := m6Serve(t, d, func(uint32) bool { return false })
	for _, body := range []string{`{"jsonrpc":"2.0","id":1,"method":"status.get"}`, "hello"} {
		code, b := s.post(t, "text/plain", []byte(body))
		if code != http.StatusForbidden {
			t.Errorf("text/plain %q: HTTP %d, want 403", body, code)
		}
		if !strings.Contains(string(b), "forbidden") {
			t.Errorf("text/plain %q: body %q, want \"forbidden\"", body, b)
		}
	}
	if calls := d.Calls(); len(calls) != 0 {
		t.Errorf("daemon called for a forbidden uid: %+v", calls)
	}
}

// --- Listen ---------------------------------------------------------------------------

// design 14, decision 8: the socket is 0666; access is checked per connection.
func TestM6ListenMode(t *testing.T) {
	path := filepath.Join(m6SockDir(t), "s.sock")
	ln := m6Listen(t, path)
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
func TestM6ListenStale(t *testing.T) {
	path := filepath.Join(m6SockDir(t), "s.sock")
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file not left: %v", err)
	}

	ln := m6Listen(t, path)
	s := m6ServeOn(t, path, ln, &m6FakeDaemon{}, nil)
	m6WantResult(t, "status.get", s.call(t, "status.get", nil))
}

// design 14: a socket that answers is another wgplex daemon: Listen fails and
// the first one keeps answering.
func TestM6ListenRunning(t *testing.T) {
	s := m6Serve(t, &m6FakeDaemon{}, nil)
	m6WantResult(t, "status.get", s.call(t, "status.get", nil))

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
	m6WantResult(t, "status.get after the second Listen", s.call(t, "status.get", nil))
}

// Listen doc, decision 8: a file at the path that is not a socket is an
// error and is left alone: still there, same content.
func TestM6ListenNotSocket(t *testing.T) {
	cases := []struct {
		name string
		make func(path string) error
	}{
		{"regular file", func(p string) error { return os.WriteFile(p, []byte("keep me\n"), 0o600) }},
		{"empty file", func(p string) error { return os.WriteFile(p, nil, 0o600) }},
		{"directory", func(p string) error { return os.Mkdir(p, 0o700) }},
	}
	for _, c := range cases {
		path := filepath.Join(m6SockDir(t), "s.sock")
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

// Wirefork M6 plan: Serve returns nil once ctx is done.
func TestM6ServeStops(t *testing.T) {
	path := filepath.Join(m6SockDir(t), "s.sock")
	ln := m6Listen(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- errors.New("Serve panicked")
			}
		}()
		done <- Serve(ctx, ln, &m6FakeDaemon{}, func(uint32) bool { return true }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	s := &m6Server{path: path, client: m6Client(path)}
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
