package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func closeTestStore(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Errorf("close store: %v", err)
	}
}

func TestCloseWithErrorPreservesPrimaryError(t *testing.T) {
	primaryErr := errors.New("primary")
	closeErr := errors.New("close")
	err := error(primaryErr)
	closeWithError(&err, "close resource", func() error { return closeErr })
	if !errors.Is(err, primaryErr) || !errors.Is(err, closeErr) {
		t.Fatalf("closeWithError() error = %v, want primary and close errors", err)
	}
}

func TestStoreObservationDecisionPolicy(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer closeTestStore(t, store)

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
	defer closeTestStore(t, store)
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

func TestUpsertAbuseSignalsDeduplicatesAndPrunes(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	node := Node{ID: "logs", Kind: "log_watcher", Host: "logs", AllowedCertName: "logs", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	signal := AbuseSignal{
		EventID: "event-1", ObservedAt: "2026-07-01T00:00:00Z", Host: "web-1",
		Site: "example", IP: "192.0.2.10", Trigger: "suspicious_uri",
		Connections: 12, Errors: 10, Successes: 2, WindowSeconds: 120,
	}
	if err := store.UpsertAbuseSignals(node, []AbuseSignal{signal, signal}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM web_abuse_signals`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("signals = %d, want deduplicated 1", count)
	}
	deleted, err := store.PruneAbuseSignalsBefore(time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC))
	if err != nil || deleted != 1 {
		t.Fatalf("prune = (%d, %v), want (1, nil)", deleted, err)
	}
}

func TestValidateAbuseSignalRejectsRawTargetLikeTrigger(t *testing.T) {
	signal := AbuseSignal{
		EventID: "event-1", ObservedAt: "2026-08-01T00:00:00Z", Host: "web-1",
		Site: "example", IP: "192.0.2.10", Trigger: "/hooks/secret",
		Connections: 1, Errors: 1, WindowSeconds: 60,
	}
	if err := validateAbuseSignal(signal); err == nil {
		t.Fatal("raw request target accepted as a trigger")
	}
}

func TestWebCandidatesRequireSameHostAndNearbySighting(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	tlsNode := Node{ID: "web-tls", Kind: "tlsgate", Host: "web.example.com", AllowedCertName: "web", Status: statusActive}
	logNode := Node{ID: "logs", Kind: "log_watcher", Host: "logs", AllowedCertName: "logs", Status: statusActive}
	for _, node := range []Node{tlsNode, logNode} {
		if err := store.UpsertNode(node); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.UpsertObservations(tlsNode, []Fingerprint{{
		Fingerprint: "t13d_example", Sightings: []Sighting{{IP: "192.0.2.10", Port: 443, LastSeen: "2026-08-21T15:00:00Z"}},
	}}); err != nil {
		t.Fatal(err)
	}
	base := AbuseSignal{EventID: "one", ObservedAt: "2026-08-21T15:01:00Z", Host: "web.example.com", Site: "example", IP: "192.0.2.10", Trigger: "suspicious_uri", Connections: 10, Errors: 10, WindowSeconds: 60}
	wrongHost := base
	wrongHost.EventID = "two"
	wrongHost.Host = "other.example.com"
	if err := store.UpsertAbuseSignals(logNode, []AbuseSignal{base, wrongHost}); err != nil {
		t.Fatal(err)
	}
	candidates, err := store.WebCandidates(time.Date(2026, 8, 21, 14, 0, 0, 0, time.UTC), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Signals != 1 || len(candidates[0].Networks) != 1 || candidates[0].Networks[0] != "192.0.2.0/24" {
		t.Fatalf("candidates = %+v", candidates)
	}
}

func TestScoreWebCandidatesShadowPolicy(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	policy := WebShadowPolicy{
		Enabled: true, MinNetworks: 3, MinSignals: 3, MinErrorRatio: 0.90,
		RequireMultiScope: true, ProposedTTL: 12 * time.Hour,
	}
	candidates := []WebCandidate{
		{
			NodeID: "gate-a", Fingerprint: "shared", Status: decisionPending,
			Networks: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
			Sites:    []string{"site-a"}, Signals: 4, Connections: 40, Errors: 38,
		},
		{
			NodeID: "gate-b", Fingerprint: "shared", Status: decisionPending,
			Networks: []string{"2001:db8::/64"}, Sites: []string{"site-b"},
			Signals: 1, Connections: 10, Errors: 10,
		},
		{
			NodeID: "gate-a", Fingerprint: "protected", Status: decisionApproved,
			Networks: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
			Sites:    []string{"site-a", "site-b"}, Signals: 4, Connections: 40, Errors: 40,
		},
	}

	got := ScoreWebCandidates(candidates, policy, now)
	if got[0].ShadowStatus != "would_block" || got[0].ProposedExpiresAt != "2026-08-31T00:00:00Z" {
		t.Fatalf("eligible candidate = %+v", got[0])
	}
	if got[0].ErrorRatio != 0.95 || len(got[0].EvidenceNodes) != 2 || len(got[0].EvidenceSites) != 2 {
		t.Fatalf("eligible evidence = %+v", got[0])
	}
	if got[1].ShadowStatus != "insufficient_evidence" || got[1].ProposedExpiresAt != "" {
		t.Fatalf("weak candidate = %+v", got[1])
	}
	if got[2].ShadowStatus != "protected" || got[2].ProposedExpiresAt != "" {
		t.Fatalf("protected candidate = %+v", got[2])
	}
}

func TestWebSignalActivityIncludesUncorrelatedSignals(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	node := Node{ID: "central-logs", Kind: "log_watcher", Host: "logs", AllowedCertName: "logs", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAbuseSignals(node, []AbuseSignal{{
		EventID: "raw-1", ObservedAt: "2026-08-26T08:30:00Z", Host: "web.example.com",
		Site: "example", IP: "192.0.2.44", Trigger: "error_rate", Connections: 10, Errors: 9, Successes: 1, WindowSeconds: 60,
	}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.WebSignalActivity(time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Network != "192.0.2.0/24" || got[0].Signals != 1 || got[0].Connections != 10 {
		t.Fatalf("activity = %+v", got)
	}
}

func TestObservationDoesNotOverrideDecision(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer closeTestStore(t, store)

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
	defer closeTestStore(t, store)

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
	defer closeTestStore(t, store)

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

func TestAdminHomeShowsCorrelatedWebFindings(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)

	tlsNode := Node{ID: "web-tls", Kind: "tlsgate", Host: "web.example.com", AllowedCertName: "web", Status: statusActive}
	logNode := Node{ID: "central-logs", Kind: "log_watcher", Host: "logs", AllowedCertName: "logs", Status: statusActive}
	for _, node := range []Node{tlsNode, logNode} {
		if err := store.UpsertNode(node); err != nil {
			t.Fatal(err)
		}
	}
	observed := time.Now().UTC().Add(-time.Minute)
	if err := store.UpsertObservations(tlsNode, []Fingerprint{{
		Fingerprint: "t13d_findings_test",
		Sightings:   []Sighting{{IP: "192.0.2.10", Port: 443, LastSeen: observed.Format(time.RFC3339Nano)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAbuseSignals(logNode, []AbuseSignal{{
		EventID: "finding-1", ObservedAt: observed.Add(30 * time.Second).Format(time.RFC3339Nano),
		Host: "web.example.com", Site: "example.com", IP: "192.0.2.10", Trigger: "error_rate",
		Connections: 12, Errors: 10, Successes: 2, WindowSeconds: 120,
	}}); err != nil {
		t.Fatal(err)
	}

	a := app{
		store: store, auth: &AuthService{},
		shadowPolicy: WebShadowPolicy{Enabled: true, MinNetworks: 1, MinSignals: 1, MinErrorRatio: 0.80, ProposedTTL: 12 * time.Hour},
	}
	rec := httptest.NewRecorder()
	a.handleAdminHome(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d; body: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		"Dashboard controls", "density-toggle", "data-collapsible",
		"Web scanner activity", "Web scanner findings", "t13d_findings_test", "example.com", "192.0.2.0/24", "12", "would_block", "83.3%",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("admin page missing %q", want)
		}
	}
}

func TestUpsertNodeDoesNotReactivate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer closeTestStore(t, store)

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

func TestRegisterNodeReadsTokenFromStdinWithoutEchoingIt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gatehub.sqlite")
	token := strings.Repeat("secret-token-", 4)
	var stdout bytes.Buffer
	err := registerNode([]string{
		"--db", dbPath,
		"--id", "logs-central",
		"--kind", "log_watcher",
		"--host", "logwc",
		"--allowed-cert-name", "logs-central",
		"--token-file", "-",
	}, strings.NewReader(token+"\n"), &stdout)
	if err != nil {
		t.Fatalf("registerNode: %v", err)
	}
	if strings.Contains(stdout.String(), token) {
		t.Fatal("command echoed node token")
	}
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer closeTestStore(t, store)
	node, err := store.Node("logs-central")
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	if node.Kind != "log_watcher" || node.TokenHash != hashToken(token) {
		t.Fatalf("stored node = %#v", node)
	}
}

func TestRegisterNodeRequiresTokenFile(t *testing.T) {
	err := registerNode([]string{"--id", "logs-central"}, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--token-file is required") {
		t.Fatalf("registerNode error = %v", err)
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
