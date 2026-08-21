package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreObservationDecisionPolicy(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	node := Node{ID: "mail-tls", Kind: "tlsgate", Host: "mail-gateway", AllowedCertName: "mail-gateway", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if err := store.UpsertObservations(node, []Fingerprint{{
		Fingerprint: "abc123",
		Status:      decisionBlocked,
		FirstSeen:   "2026-07-01T10:00:00Z",
		LastSeen:    "2026-07-01T10:01:00Z",
		IPs:         []string{"203.0.113.10"},
		Ports:       []int{993},
		Sightings:   []Sighting{{IP: "203.0.113.10", Port: 993, LastSeen: "2026-07-01T10:01:00Z"}},
		Count:       2,
		Metadata:    map[string]any{"sni": "mail.example.com"},
	}}); err != nil {
		t.Fatalf("UpsertObservations: %v", err)
	}
	var sightings int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM fingerprint_sightings WHERE node_id = ? AND fingerprint = ?`, node.ID, "abc123").Scan(&sightings); err != nil {
		t.Fatal(err)
	}
	if sightings != 1 {
		t.Fatalf("sightings = %d, want 1", sightings)
	}
	if err := store.CreateDecision(Decision{
		ScopeType:   "instance",
		ScopeID:     node.ID,
		Kind:        node.Kind,
		Fingerprint: "abc123",
		Status:      decisionApproved,
		Label:       "Alice iPhone",
		Actor:       "test",
	}); err != nil {
		t.Fatalf("CreateDecision: %v", err)
	}

	decisions, cursor, err := store.PolicyForNode(node, "")
	if err != nil {
		t.Fatalf("PolicyForNode: %v", err)
	}
	if cursor == "" {
		t.Fatal("cursor is empty")
	}
	if len(decisions) != 1 || decisions[0].Status != decisionApproved || decisions[0].Label != "Alice iPhone" {
		t.Fatalf("decisions = %+v, want approved decision", decisions)
	}

	fps, err := store.Fingerprints("")
	if err != nil {
		t.Fatalf("Fingerprints: %v", err)
	}
	if len(fps) != 1 || fps[0].Status != decisionApproved || fps[0].Label != "Alice iPhone" {
		t.Fatalf("fingerprints = %+v, want locally updated approved fingerprint", fps)
	}
}

func TestPruneSightingsBefore(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node := Node{ID: "web-tls", Kind: "tlsgate", Host: "web", AllowedCertName: "web", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertObservations(node, []Fingerprint{{
		Fingerprint: "fp1",
		Sightings: []Sighting{
			{IP: "192.0.2.1", Port: 443, LastSeen: "2026-07-01T00:00:00Z"},
			{IP: "192.0.2.2", Port: 443, LastSeen: "2026-08-01T00:00:00Z"},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.PruneSightingsBefore(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	var remaining int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM fingerprint_sightings`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining = %d, want 1", remaining)
	}
}

func TestObservationDoesNotOverrideDecision(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	node := Node{ID: "mail-tls", Kind: "tlsgate", Host: "mail-gateway", AllowedCertName: "mail-gateway", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	// A node cannot self-declare a fingerprint as approved; it lands pending.
	if err := store.UpsertObservations(node, []Fingerprint{{Fingerprint: "abc123", Status: decisionApproved}}); err != nil {
		t.Fatalf("UpsertObservations: %v", err)
	}
	fps, err := store.Fingerprints("")
	if err != nil {
		t.Fatalf("Fingerprints: %v", err)
	}
	if len(fps) != 1 || fps[0].Status != decisionPending {
		t.Fatalf("first observation status = %+v, want pending", fps)
	}
	// Admin blocks it, then the node re-syncs claiming approved again.
	if err := store.CreateDecision(Decision{ScopeType: "instance", ScopeID: node.ID, Kind: node.Kind, Fingerprint: "abc123", Status: decisionBlocked, Actor: "admin"}); err != nil {
		t.Fatalf("CreateDecision: %v", err)
	}
	if err := store.UpsertObservations(node, []Fingerprint{{Fingerprint: "abc123", Status: decisionApproved}}); err != nil {
		t.Fatalf("UpsertObservations resync: %v", err)
	}
	fps, err = store.Fingerprints("")
	if err != nil {
		t.Fatalf("Fingerprints: %v", err)
	}
	if len(fps) != 1 || fps[0].Status != decisionBlocked {
		t.Fatalf("status after resync = %+v, want blocked (decision preserved)", fps)
	}
}

func TestGlobalDecisionUpdatesMatchingFingerprintsAndPolicies(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	nodes := []Node{
		{ID: "mail-tls", Kind: "tlsgate", Host: "mail-gateway", AllowedCertName: "mail-gateway", Status: statusActive},
		{ID: "shell-ssh", Kind: "sshgate", Host: "shell-gateway", AllowedCertName: "shell-gateway", Status: statusActive},
	}
	for _, node := range nodes {
		if err := store.UpsertNode(node); err != nil {
			t.Fatalf("UpsertNode(%s): %v", node.ID, err)
		}
		if err := store.UpsertObservations(node, []Fingerprint{{Fingerprint: "abc123"}}); err != nil {
			t.Fatalf("UpsertObservations(%s): %v", node.ID, err)
		}
	}

	if err := store.CreateDecision(Decision{
		ScopeType:   "global",
		Fingerprint: "abc123",
		Status:      decisionApproved,
		Label:       "Shared key",
		Actor:       "test",
	}); err != nil {
		t.Fatalf("CreateDecision: %v", err)
	}

	fps, err := store.Fingerprints("")
	if err != nil {
		t.Fatalf("Fingerprints: %v", err)
	}
	if len(fps) != len(nodes) {
		t.Fatalf("got %d fingerprints, want %d", len(fps), len(nodes))
	}
	for _, fp := range fps {
		if fp.Status != decisionApproved || fp.Label != "Shared key" {
			t.Errorf("fingerprint for %s = %+v, want globally approved and labeled", fp.NodeID, fp)
		}
	}
	for _, node := range nodes {
		decisions, _, err := store.PolicyForNode(node, "")
		if err != nil {
			t.Fatalf("PolicyForNode(%s): %v", node.ID, err)
		}
		if len(decisions) != 1 || decisions[0].ScopeType != "global" || decisions[0].Status != decisionApproved {
			t.Errorf("decisions for %s = %+v, want one global approval", node.ID, decisions)
		}
	}
}

func TestGroupFingerprintsCollapsesHostsAndPreservesInstances(t *testing.T) {
	groups := groupFingerprints([]Fingerprint{
		{
			NodeID:      "node-b",
			Kind:        "sshgate",
			Host:        "shell-b",
			Fingerprint: "shared",
			Status:      decisionApproved,
			Label:       "workstation",
			LastSeen:    "2026-07-01T10:00:00Z",
			IPs:         []string{"203.0.113.10"},
			Count:       2,
		},
		{
			NodeID:      "node-a",
			Kind:        "sshgate",
			Host:        "shell-a",
			Fingerprint: "shared",
			Status:      decisionBlocked,
			Label:       "unexpected",
			LastSeen:    "2026-07-01T11:00:00Z",
			IPs:         []string{"203.0.113.10", "203.0.113.11"},
			Count:       3,
		},
		{
			NodeID:      "node-c",
			Kind:        "tlsgate",
			Host:        "mail-a",
			Fingerprint: "other",
			Status:      decisionPending,
			LastSeen:    "2026-07-01T09:00:00Z",
			Count:       1,
		},
	})

	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	shared := groups[0]
	if shared.Fingerprint != "shared" {
		t.Fatalf("first group fingerprint = %q, want shared (blocked sorts first)", shared.Fingerprint)
	}
	if shared.Status != decisionBlocked {
		t.Fatalf("shared status = %q, want worst status blocked", shared.Status)
	}
	if shared.Label != "" {
		t.Fatalf("shared label = %q, want empty for differing labels", shared.Label)
	}
	if !shared.LabelsVary {
		t.Fatal("shared LabelsVary = false, want true for differing labels")
	}
	if shared.LastSeen != "2026-07-01T11:00:00Z" || shared.Count != 5 {
		t.Fatalf("shared aggregates = last seen %q, count %d", shared.LastSeen, shared.Count)
	}
	if len(shared.HostNames) != 2 || shared.HostNames[0] != "shell-a" || shared.HostNames[1] != "shell-b" {
		t.Fatalf("shared hosts = %v, want sorted unique hosts", shared.HostNames)
	}
	if len(shared.IPs) != 2 || len(shared.Instances) != 2 {
		t.Fatalf("shared IPs/instances = %v/%d, want unique IPs and both instances", shared.IPs, len(shared.Instances))
	}
}

func TestAdminGlobalDecisionClearsInstanceScopeID(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	a := app{store: store, auth: &AuthService{}}
	req := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader(
		"scope_type=global&scope_id=mail-tls&kind=tlsgate&fingerprint=abc123&status=approved",
	))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.handleAdminDecision(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /decisions = %d, want %d; body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}

	decisions, _, err := store.PolicyForNode(Node{ID: "other", Kind: "sshgate"}, "")
	if err != nil {
		t.Fatalf("PolicyForNode: %v", err)
	}
	if len(decisions) != 1 || decisions[0].ScopeType != "global" || decisions[0].ScopeID != "" {
		t.Fatalf("decisions = %+v, want normalized global scope", decisions)
	}
}

func TestUpsertNodeDoesNotReactivate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	node := Node{ID: "node-a", Kind: "tlsgate", Host: "node-a", AllowedCertName: "node-a", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if err := store.SetNodeStatus("node-a", statusRevoked); err != nil {
		t.Fatalf("SetNodeStatus: %v", err)
	}
	// Editing the node (the admin form always sends active) must not un-revoke it.
	node.Host = "node-b"
	if err := store.UpsertNode(node); err != nil {
		t.Fatalf("UpsertNode edit: %v", err)
	}
	got, err := store.Node("node-a")
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	if got.Status != statusRevoked {
		t.Fatalf("status = %q, want revoked (edit must not reactivate)", got.Status)
	}
	if got.Host != "node-b" {
		t.Fatalf("host = %q, want node-b (edit should still apply)", got.Host)
	}
}

func TestCertMatchesName(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "node-a"},
		DNSNames: []string{"node-a.example.com"},
	}
	for _, name := range []string{"node-a", "node-a.example.com"} {
		if !certMatchesName(cert, name) {
			t.Fatalf("certMatchesName(%q) = false, want true", name)
		}
	}
	if certMatchesName(cert, "node-b") {
		t.Fatal("certMatchesName(node-b) = true, want false")
	}
}

func TestValidateNodeTokenRejectsWeakTokens(t *testing.T) {
	for _, token := range []string{"short", strings.Repeat("a", minNodeTokenLength-1), "abc defghijklmnopqrstuvwxyz123456"} {
		if err := validateNodeToken(token); err == nil {
			t.Fatalf("validateNodeToken(%q) = nil, want error", token)
		}
	}
	if err := validateNodeToken(strings.Repeat("a", minNodeTokenLength)); err != nil {
		t.Fatalf("validateNodeToken(strong) = %v", err)
	}
}

func TestValidateObservationBounds(t *testing.T) {
	if err := validateObservation(Fingerprint{
		Fingerprint: "abc123",
		IPs:         []string{"203.0.113.10"},
		Ports:       []int{22},
		Metadata:    map[string]any{"client": "test"},
	}); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	if err := validateObservation(Fingerprint{Fingerprint: "bad fp"}); err == nil {
		t.Fatal("fingerprint with whitespace accepted")
	}
	if err := validateObservation(Fingerprint{Fingerprint: "abc123", IPs: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid IP accepted")
	}
	if err := validateObservation(Fingerprint{Fingerprint: "abc123", Ports: []int{0}}); err == nil {
		t.Fatal("invalid port accepted")
	}
	if err := validateObservation(Fingerprint{
		Fingerprint: "abc123",
		Metadata:    map[string]any{"large": strings.Repeat("x", maxObservationMetaBytes+1)},
	}); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}
