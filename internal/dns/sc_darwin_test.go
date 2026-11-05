package dns

import "testing"

// Read-only checks of the SC layer: reading the dynamic store needs no root.
// Writing (Capture, Release) needs root and is checked in the VM.

func TestSCGetAbsent(t *testing.T) {
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	m, ok, err := s.get("State:/Network/Service/00000000-0000-0000-0000-000000000000/DNS")
	if err != nil || ok || m != nil {
		t.Errorf("absent key: %v, %v, %v", m, ok, err)
	}
}

func TestSCGetGlobal(t *testing.T) {
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	m, ok, err := s.get("State:/Network/Global/IPv4")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("no network: State:/Network/Global/IPv4 is absent")
	}
	if id := m["PrimaryService"]; len(id) != 1 || !isUUID(id[0]) {
		t.Errorf("PrimaryService = %q, want one UUID", id)
	}
	// Nested dictionaries are skipped, scalars read; nothing panics on the
	// other keys of the service.
	if _, _, err := s.get("State:/Network/Service/" + m["PrimaryService"][0] + "/IPv4"); err != nil {
		t.Error(err)
	}
}
