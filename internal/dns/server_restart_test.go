package dns

import (
	"net"
	"testing"
)

// A Start that fails on a busy port leaves nothing bound and may be called
// again: the daemon retries a busy port (design 8).
func TestServerStartAgainAfterBusy(t *testing.T) {
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := busy.LocalAddr().String()
	s := &Server{}
	if err := s.Start(addr); err == nil {
		t.Fatal("Start on a busy port succeeded")
	}
	if s.Err() != nil {
		t.Error("Err() is set after a failed Start")
	}
	busy.Close()
	if err := s.Start(addr); err != nil {
		t.Fatalf("Start after the port was freed: %v", err)
	}
	defer s.Shutdown()
	if s.Err() == nil {
		t.Error("Err() is nil after Start")
	}
	if got := s.Addr().String(); got != addr {
		t.Errorf("Addr = %s, want %s", got, addr)
	}
}

// After Shutdown, Start binds again: the daemon restarts a resolver that
// stopped serving (design 9.1). The new Err channel is not the old one.
func TestServerStartAgainAfterShutdown(t *testing.T) {
	s := &Server{}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	addr := s.Addr().String()
	old := s.Err()
	if err := s.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := s.Start(addr); err != nil {
		t.Fatalf("Start after Shutdown: %v", err)
	}
	defer s.Shutdown()
	if s.Err() == old {
		t.Error("Err() is the channel of the first Start")
	}
	select {
	case err := <-old:
		t.Errorf("old Err() got %v after Shutdown", err)
	default:
	}
}
