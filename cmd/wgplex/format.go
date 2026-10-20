package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/rpc"
)

// The print functions are pure: w gets the text (see "Вывод wf" of the M6
// plan), now is for "12s ago". Rule numbers are printed from 1.

// newTable returns a tabwriter for the column output of the CLI.
func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

// printStatus prints the reply of status.get.
func printStatus(w io.Writer, s rpc.Status, now time.Time) {
	fmt.Fprintf(w, "icon: %s\n", s.Icon)
	if len(s.ConfigErrors) > 0 {
		fmt.Fprintln(w, "config error:")
		for _, e := range s.ConfigErrors {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
	for _, x := range s.Warnings {
		fmt.Fprintf(w, "warning: %s\n", x)
	}
	if !s.Configured {
		fmt.Fprintln(w, "no config applied (wgplex reload)")
		return
	}

	if len(s.Tunnels) > 0 {
		fmt.Fprintln(w)
		tw := newTable(w)
		// Every row has all eight cells tab-terminated: a shorter row would
		// end the column blocks of tabwriter. The error or the reason of
		// "dead" goes after them.
		fmt.Fprintln(tw, "TUNNEL\tSTATE\tIFACE\tHANDSHAKE\tCHECK\tRX\tTX\tROUTES\t")
		for _, t := range s.Tunnels {
			switch t.State {
			case "up", "dead":
				var last time.Time
				var rx, tx uint64
				for _, p := range t.Peers {
					if p.LastHandshake.After(last) {
						last = p.LastHandshake
					}
					rx += p.RxBytes
					tx += p.TxBytes
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", t.Name, t.State, t.Interface,
					formatAgo(last, now), formatCheck(t.Check), formatBytes(rx), formatBytes(tx), t.RouteCount, t.Reason)
			case "off":
				fmt.Fprintf(tw, "%s\t%s\t\t\t\t\t\t\t\n", t.Name, t.State)
			default:
				fmt.Fprintf(tw, "%s\t%s\t\t\t\t\t\t%d\t%s\n", t.Name, t.State, t.RouteCount, t.Error)
			}
		}
		tw.Flush()
	}

	if len(s.Rules) > 0 {
		fmt.Fprintln(w)
		tw := newTable(w)
		fmt.Fprintln(tw, "RULE\tSERVICES\tVIA\t→")
		for _, r := range s.Rules {
			fmt.Fprintf(tw, "#%d\t%s\t%s\t%s\n", r.Index+1, strings.Join(r.Services, ","), via(r), ruleTarget(r))
		}
		tw.Flush()
	}
}

// via formats the via list of r: "nl,de", "-" when empty.
func via(r rpc.RuleStatus) string {
	if len(r.Via) == 0 {
		return "-"
	}
	return strings.Join(r.Via, ",")
}

// ruleTarget formats where r sends traffic: "de", "de (degraded)",
// "block (fallback)", "direct".
func ruleTarget(r rpc.RuleStatus) string {
	switch {
	case len(r.Via) == 0:
		return "direct"
	case r.InFallback:
		return r.Fallback + " (fallback)"
	case r.Degraded:
		return r.Tunnel + " (degraded)"
	default:
		return r.Tunnel
	}
}

// ruleName formats r as "#1 [youtube,telegram]".
func ruleName(r rpc.RuleStatus) string {
	return fmt.Sprintf("#%d [%s]", r.Index+1, strings.Join(r.Services, ","))
}

// printExplain prints the reply of diag.explain.
func printExplain(w io.Writer, e rpc.Explanation) {
	fmt.Fprintf(w, "%s: %s\n", e.Query, e.Kind)
	if e.Kind == "ip" {
		if e.Route == nil {
			fmt.Fprintln(w, "no route: system default route")
			return
		}
		r := e.Route
		to := r.Target
		if r.Tunnel != "" {
			to += " " + r.Tunnel
		}
		src := r.Source
		if r.Rule >= 0 {
			if e.Rule != nil {
				src += ", rule " + ruleName(*e.Rule)
			} else {
				src += fmt.Sprintf(", rule #%d", r.Rule+1)
			}
		}
		line := fmt.Sprintf("route %s → %s (%s)", r.Prefix, to, src)
		if len(r.Names) > 0 {
			line += "; names: " + strings.Join(r.Names, ", ")
		}
		if r.Skipped != "" {
			line += "; not in kernel: " + r.Skipped
		}
		fmt.Fprintln(w, line)
		return
	}

	if e.Rule != nil {
		fmt.Fprintf(w, "rule %s via %s → %s\n", ruleName(*e.Rule), via(*e.Rule), ruleTarget(*e.Rule))
	} else {
		fmt.Fprintln(w, "no rule")
	}
	if e.Skipped != nil {
		fmt.Fprintf(w, "skipped: rule %s is in fallback: %s\n", ruleName(*e.Skipped), e.Skipped.Fallback)
	}
	switch e.Upstream {
	case "", "system":
		fmt.Fprintln(w, "dns: system")
	case "block":
		fmt.Fprintln(w, "dns: block (NODATA)")
	default:
		line := fmt.Sprintf("dns: tunnel %s (%s)", e.Upstream, strings.Join(e.Servers, ", "))
		if e.Zone != "" {
			line += ", zone " + e.Zone
		}
		fmt.Fprintln(w, line)
	}
	if e.DropAAAA {
		fmt.Fprintln(w, "aaaa: filtered")
	}
	if len(e.Addrs) > 0 {
		fmt.Fprintf(w, "addresses: %s\n", strings.Join(e.Addrs, ", "))
	}
}

// printRoutes prints the reply of diag.routes.
func printRoutes(w io.Writer, r rpc.Routes) {
	tw := newTable(w)
	fmt.Fprintln(tw, "PREFIX\tTARGET\tTUNNEL\tSOURCE\tRULE\tNOTE")
	for _, x := range r.Routes {
		tun := x.Tunnel
		if tun == "" {
			tun = "-"
		}
		rule := "-"
		if x.Rule >= 0 {
			rule = fmt.Sprintf("#%d", x.Rule+1)
		}
		var notes []string
		if len(x.Names) > 0 {
			notes = append(notes, strings.Join(x.Names, ","))
		}
		if x.Skipped != "" {
			notes = append(notes, "skipped: "+x.Skipped)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", x.Prefix, x.Target, tun, x.Source, rule, strings.Join(notes, "; "))
	}
	tw.Flush()
	if r.SyncError != "" {
		fmt.Fprintf(w, "sync error: %s\n", r.SyncError)
	}
}

// printApply prints the reply of config.apply.
func printApply(w io.Writer, r rpc.ApplyResult) {
	for _, x := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", x)
	}
	for _, t := range r.Tunnels {
		fmt.Fprintf(w, "tunnel %s: %s\n", t.Name, t.Error)
	}
	fmt.Fprintln(w, "config applied")
}

// printError prints err: a *jrpc.JRPCError by its code (config errors one per
// line from ConfigErrorData), HTTP 403 as "permission denied: ...", a missing
// or dead socket (ENOENT, ECONNREFUSED of the dial) as "wgplex daemon is not
// running"; the same errors elsewhere (reading the config) print as they are.
func printError(w io.Writer, err error) {
	var (
		rpcErr  *jrpc.JRPCError
		httpErr *httpError
	)
	switch {
	case errors.As(err, &rpcErr):
		printRPCError(w, rpcErr)
	case errors.As(err, &httpErr):
		switch httpErr.Code {
		case http.StatusForbidden:
			fmt.Fprintln(w, "permission denied: run as root")
		case http.StatusRequestEntityTooLarge:
			fmt.Fprintln(w, "error: the request is too large for the daemon (over 1 MiB, HTTP 413)")
		default:
			fmt.Fprintf(w, "error: %v\n", httpErr)
		}
	case isDialError(err) && (errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)):
		fmt.Fprintln(w, "wgplex daemon is not running")
	case errors.Is(err, fs.ErrPermission):
		fmt.Fprintf(w, "permission denied: %v\n", err)
	default:
		fmt.Fprintf(w, "error: %v\n", err)
	}
}

// isDialError reports whether err comes from connecting to the socket.
func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// printRPCError prints a JSON-RPC error object of the daemon.
func printRPCError(w io.Writer, e *jrpc.JRPCError) {
	switch e.Code {
	case rpc.CodeConfigInvalid:
		var data rpc.ConfigErrorData
		if b, err := json.Marshal(e.Data); err == nil {
			json.Unmarshal(b, &data)
		}
		fmt.Fprintln(w, "config error:")
		for _, x := range data.Errors {
			fmt.Fprintf(w, "  %s\n", x)
		}
		for _, x := range data.Warnings {
			fmt.Fprintf(w, "warning: %s\n", x)
		}
	case rpc.CodeNoConfig:
		fmt.Fprintf(w, "error: %s (wgplex reload)\n", e.Message)
	case rpc.CodeTunnelStart:
		fmt.Fprintln(w, e.Message) // "tunnel <name>: <error>"
	default:
		if s, ok := e.Data.(string); ok && s != "" {
			fmt.Fprintf(w, "error: %s: %s\n", e.Message, s)
		} else {
			fmt.Fprintf(w, "error: %s\n", e.Message)
		}
	}
}

// formatCheck formats the active check for the CHECK column: "-" without a
// check, "fail N" after N failures in a row, "12ms" (RTT of the last
// successful check, whole ms), "?" before the first check.
func formatCheck(c *rpc.CheckStatus) string {
	switch {
	case c == nil:
		return "-"
	case c.Fails > 0:
		return fmt.Sprintf("fail %d", c.Fails)
	case !c.LastOK.IsZero():
		return fmt.Sprintf("%dms", int64(math.Round(c.RTTMs)))
	default:
		return "?"
	}
}

// formatBytes formats n: "0 B", "512 B", "1.5 KiB", "3.2 MiB", "1.0 GiB".
func formatBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	v := float64(n) / 1024
	i := 0
	// 1023.95 would print as "1024.0": go to the next unit instead.
	for v >= 1023.95 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// formatAgo formats the time since t: "never" (zero t), "5s ago",
// "3m 10s ago", "2h 5m ago". A t after now counts as "0s ago".
func formatAgo(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := max(now.Sub(t), 0)
	s := int64(d / time.Second)
	switch {
	case s < 60:
		return fmt.Sprintf("%ds ago", s)
	case s < 3600:
		return fmt.Sprintf("%dm %ds ago", s/60, s%60)
	default:
		return fmt.Sprintf("%dh %dm ago", s/3600, s%3600/60)
	}
}
