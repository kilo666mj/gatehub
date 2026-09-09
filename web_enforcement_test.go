package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestDecisionSchemaMigrationDefaultsExistingRowsToManual(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gatehub.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE decisions (
		id INTEGER PRIMARY KEY AUTOINCREMENT, scope_type TEXT NOT NULL,
		scope_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL,
		status TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
		actor TEXT NOT NULL);
		INSERT INTO decisions (scope_type, scope_id, fingerprint, status, updated_at, actor)
		VALUES ('global', '', 'legacy', 'approved', '2026-09-01T00:00:00Z', 'admin')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	var source, expires, evidence string
	if err := store.db.QueryRow(`SELECT source, expires_at, evidence_json FROM decisions WHERE fingerprint = 'legacy'`).Scan(&source, &expires, &evidence); err != nil {
		t.Fatal(err)
	}
	if source != "manual" || expires != "" || evidence != "{}" {
		t.Fatalf("migrated decision = source=%q expires=%q evidence=%q", source, expires, evidence)
	}
}

func enforcementTestStore(t *testing.T) (*Store, Node) {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "gatehub.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStore(t, store) })
	node := Node{ID: "web-tls-canary", Kind: "tlsgate", Host: "web.example", AllowedCertName: "web", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertObservations(node, []Fingerprint{{Fingerprint: "ja4-test", Status: decisionPending}}); err != nil {
		t.Fatal(err)
	}
	return store, node
}

func enforcementCandidate(node Node, lastSeen time.Time) WebCandidate {
	return WebCandidate{
		NodeID: node.ID, Host: node.Host, Fingerprint: "ja4-test",
		ShadowStatus: "would_block", Networks: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
		Sites: []string{"one", "two"}, EvidenceNodes: []string{node.ID},
		Signals: 3, Connections: 30, Errors: 30,
		FirstSeen: lastSeen.Add(-time.Minute).Format(time.RFC3339Nano), LastSeen: lastSeen.Format(time.RFC3339Nano),
	}
}

func TestWebEnforcementBlocksAndExplicitlyExpires(t *testing.T) {
	store, node := enforcementTestStore(t)
	now := time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC)
	policy := WebEnforcementPolicy{Mode: "canary", CanaryNodes: map[string]struct{}{node.ID: {}}, DecisionTTL: time.Hour}

	result, err := store.ReconcileWebEnforcement([]WebCandidate{enforcementCandidate(node, now.Add(-time.Minute))}, policy, now)
	if err != nil || result.Blocked != 1 || result.Expired != 0 {
		t.Fatalf("block reconcile = (%+v, %v)", result, err)
	}
	decisions, _, err := store.PolicyForNode(node, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Status != decisionBlocked || decisions[0].Source != webAutomationSource || decisions[0].ExpiresAt == "" {
		t.Fatalf("block decision = %+v", decisions)
	}

	result, err = store.ReconcileWebEnforcement(nil, policy, now.Add(2*time.Hour))
	if err != nil || result.Expired != 1 {
		t.Fatalf("expiry reconcile = (%+v, %v)", result, err)
	}
	decisions, _, err = store.PolicyForNode(node, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 2 || decisions[1].Status != decisionPending || decisions[1].Source != "web-automation-expiry" {
		t.Fatalf("expiry decisions = %+v", decisions)
	}

	// Old evidence must not immediately recreate an expired block.
	result, err = store.ReconcileWebEnforcement([]WebCandidate{enforcementCandidate(node, now.Add(-time.Minute))}, policy, now.Add(2*time.Hour+time.Minute))
	if err != nil || result.Blocked != 0 {
		t.Fatalf("stale evidence reconcile = (%+v, %v)", result, err)
	}
}

func TestWebEnforcementManualApprovalWins(t *testing.T) {
	store, node := enforcementTestStore(t)
	if err := store.CreateDecision(Decision{ScopeType: "instance", ScopeID: node.ID, Kind: node.Kind, Fingerprint: "ja4-test", Status: decisionApproved, Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	// A decision in another scope may be newer, but it must not erase the
	// explicit instance approval for purposes of automation protection.
	if err := store.CreateDecision(Decision{ScopeType: "global", Fingerprint: "ja4-test", Status: decisionPending, Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	policy := WebEnforcementPolicy{Mode: "enforce", DecisionTTL: time.Hour}
	result, err := store.ReconcileWebEnforcement([]WebCandidate{enforcementCandidate(node, now)}, policy, now)
	if err != nil || result.Blocked != 0 {
		t.Fatalf("approved reconcile = (%+v, %v)", result, err)
	}
}

func TestWebEnforcementCanaryAndKillSwitch(t *testing.T) {
	store, node := enforcementTestStore(t)
	now := time.Now().UTC()
	excluded := WebEnforcementPolicy{Mode: "canary", CanaryNodes: map[string]struct{}{"other": {}}, DecisionTTL: time.Hour}
	result, err := store.ReconcileWebEnforcement([]WebCandidate{enforcementCandidate(node, now)}, excluded, now)
	if err != nil || result.Blocked != 0 {
		t.Fatalf("excluded canary reconcile = (%+v, %v)", result, err)
	}

	enabled := WebEnforcementPolicy{Mode: "canary", CanaryNodes: map[string]struct{}{node.ID: {}}, DecisionTTL: time.Hour}
	if result, err = store.ReconcileWebEnforcement([]WebCandidate{enforcementCandidate(node, now)}, enabled, now); err != nil || result.Blocked != 1 {
		t.Fatalf("enabled canary reconcile = (%+v, %v)", result, err)
	}
	disabled := WebEnforcementPolicy{Mode: "disabled", DecisionTTL: time.Hour}
	if result, err = store.ReconcileWebEnforcement(nil, disabled, now.Add(time.Minute)); err != nil || result.Expired != 1 {
		t.Fatalf("kill switch reconcile = (%+v, %v)", result, err)
	}
}
