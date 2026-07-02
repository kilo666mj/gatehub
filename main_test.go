package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"strings"
	"testing"
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
		Count:       2,
		Metadata:    map[string]any{"sni": "mail.example.com"},
	}}); err != nil {
		t.Fatalf("UpsertObservations: %v", err)
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
