package main

import (
	"path/filepath"
	"testing"

	"go.michaelspost.com/gatekit/approval"
)

func totalChanges(t *testing.T, s *Store) int64 {
	t.Helper()
	var count int64
	if err := s.db.QueryRow("SELECT total_changes()").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func observationFixture(t *testing.T) (*Store, Node, Fingerprint) {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "gatehub.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStore(t, s) })
	n := Node{ID: "test-gate", Kind: "tlsgate", Host: "gate.example.com", AllowedCertName: "gate", Status: statusActive}
	if err := s.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint{
		Fingerprint: "test-fingerprint", FirstSeen: "2026-01-01T00:00:00Z",
		LastSeen: "2026-01-02T00:00:00Z", IPs: []string{"192.0.2.1"}, Ports: []int{443},
		Count: 2, Metadata: map[string]any{"sni": "example.com"},
		Sightings: []Sighting{{IP: "192.0.2.1", Port: 443, LastSeen: "2026-01-02T00:00:00Z"}},
	}
	if err := s.UpsertObservations(n, []Fingerprint{fp}); err != nil {
		t.Fatal(err)
	}
	return s, n, fp
}

func TestObservationReplayWritesOnlyHeartbeatAndAudit(t *testing.T) {
	for _, policy := range []string{"none", "blocked", "scoped-approval"} {
		t.Run(policy, func(t *testing.T) {
			s, n, fp := observationFixture(t)
			if policy != "none" {
				d := Decision{ScopeType: "instance", ScopeID: n.ID, Kind: n.Kind, Fingerprint: fp.Fingerprint, Status: decisionBlocked, Label: "Operator label", Actor: "test"}
				if policy == "scoped-approval" {
					if err := s.RecordScopeCapability(n, true); err != nil {
						t.Fatal(err)
					}
					var err error
					d.ApprovalRanges, err = approval.New([]string{"192.0.2.0/24"})
					if err != nil {
						t.Fatal(err)
					}
					d.Status = decisionApproved
				}
				if err := s.CreateDecision(d); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.Fingerprints("")
			if err != nil {
				t.Fatal(err)
			}
			nodeBefore, err := s.Node(n.ID)
			if err != nil {
				t.Fatal(err)
			}
			// Existing first_seen and operator labels survive client replays.
			fp.FirstSeen = "2026-01-03T00:00:00Z"
			changes := totalChanges(t, s)
			if err := s.UpsertObservations(n, []Fingerprint{fp}); err != nil {
				t.Fatal(err)
			}
			if got := totalChanges(t, s) - changes; got != 2 {
				t.Fatalf("replay changed %d rows, want only heartbeat and audit", got)
			}
			after, err := s.Fingerprints("")
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != 1 || after[0].UpdatedAt != before[0].UpdatedAt || after[0].FirstSeen != before[0].FirstSeen || after[0].Label != before[0].Label || after[0].Status != before[0].Status {
				t.Fatalf("replay changed effective fingerprint state: %+v", after)
			}
			nodeAfter, err := s.Node(n.ID)
			if err != nil {
				t.Fatal(err)
			}
			if nodeAfter.LastSeen == nodeBefore.LastSeen {
				t.Fatal("unchanged observations did not refresh node heartbeat")
			}
			var auditCount int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='sync_observations'").Scan(&auditCount); err != nil {
				t.Fatal(err)
			}
			if auditCount != 2 {
				t.Fatalf("audit count = %d, want 2", auditCount)
			}
		})
	}
}

func TestObservationChangesAreStillPersisted(t *testing.T) {
	for _, field := range []string{"kind", "host", "label", "last_seen", "ips", "ports", "count", "metadata", "sighting"} {
		t.Run(field, func(t *testing.T) {
			s, n, fp := observationFixture(t)
			switch field {
			case "kind":
				n.Kind = "sshgate"
			case "host":
				n.Host = "new.example.com"
			case "label":
				fp.Label = "New label"
			case "last_seen":
				fp.LastSeen = "2026-01-03T00:00:00Z"
			case "ips":
				fp.IPs = []string{"192.0.2.2"}
			case "ports":
				fp.Ports = []int{993}
			case "count":
				fp.Count++
			case "metadata":
				fp.Metadata["sni"] = "new.example.com"
			case "sighting":
				fp.Sightings[0].LastSeen = "2026-01-03T00:00:00Z"
			}
			changes := totalChanges(t, s)
			if err := s.UpsertObservations(n, []Fingerprint{fp}); err != nil {
				t.Fatal(err)
			}
			if got := totalChanges(t, s) - changes; got != 3 {
				t.Fatalf("changed %d rows, want observation plus heartbeat and audit", got)
			}
			changes = totalChanges(t, s)
			if err := s.UpsertObservations(n, []Fingerprint{fp}); err != nil {
				t.Fatal(err)
			}
			if got := totalChanges(t, s) - changes; got != 2 {
				t.Fatalf("replay of new observation changed %d rows, want 2", got)
			}
		})
	}
}
