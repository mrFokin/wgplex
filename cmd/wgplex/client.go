package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/mrFokin/jrpc/v2"
)

// httpError is a non-200 HTTP reply of the daemon (403: uid not allowed,
// 413: body too large, 415: not JSON).
type httpError struct {
	Code int
	Body string
}

func (e *httpError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("HTTP %d", e.Code)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body)
}

const (
	maxReply   = 16 << 20 // bounds the reply read from the daemon
	maxRequest = 1 << 20  // the body limit of jrpc: larger requests get HTTP 413
)

// call sends one JSON-RPC request over the unix socket and decodes the
// result into res; an error object is returned as *jrpc.JRPCError, a non-200
// HTTP status as *httpError{Code, Body}. params and res may be nil. A request
// body over maxRequest is an error without contacting the daemon: it would
// reply 413, or reset the connection while the body is still being sent.
func call(ctx context.Context, socket, method string, params, res any) error {
	req := struct {
		Version string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
		ID      int    `json:"id"`
	}{"2.0", method, params, 1}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(body) > maxRequest {
		return fmt.Errorf("the request is %d bytes, over the 1 MiB limit of the daemon", len(body))
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	defer client.CloseIdleConnections()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://wgplex/rpc", bytes.NewReader(body))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hresp, err := client.Do(hreq)
	if err != nil {
		return err
	}
	defer hresp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, maxReply))
	if err != nil {
		return err
	}
	if hresp.StatusCode != http.StatusOK {
		return &httpError{Code: hresp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *jrpc.JRPCError `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("bad reply: %w", err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if res == nil || len(resp.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Result, res); err != nil {
		return fmt.Errorf("bad result: %w", err)
	}
	return nil
}
