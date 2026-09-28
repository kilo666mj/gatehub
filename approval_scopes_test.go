package main

import (
	"github.com/kilo666mj/gatekit/approval"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopedApprovalCapabilityRemovalAndPolicy(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	n := Node{ID: "mail", Kind: "tlsgate", Host: "mail.example.com", AllowedCertName: "mail", Status: statusActive, TokenHash: hashToken("test-token")}
	if err := s.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertObservations(n, []Fingerprint{{Fingerprint: "fp"}}); err != nil {
		t.Fatal(err)
	}
	scope, err := approval.New([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{ScopeType: "instance", ScopeID: n.ID, Kind: n.Kind, Fingerprint: "fp", Status: decisionApproved, ApprovalRanges: scope}
	if err := s.CreateDecision(d); err == nil {
		t.Fatal("legacy node accepted scoped approval")
	}
	a := app{store: s, auth: &AuthService{}}
	pull := func(capability bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/policy?instance_id=mail", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		if capability {
			req.Header.Set("X-Gatekit-Capabilities", approval.Capability)
		}
		rec := httptest.NewRecorder()
		a.handlePolicy(rec, req)
		return rec
	}
	if rec := pull(true); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if err := s.CreateDecision(d); err != nil {
		t.Fatal(err)
	}
	if rec := pull(true); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"approval_ranges":["192.0.2.0/24"]`) {
		t.Fatalf("scoped policy: %d %s", rec.Code, rec.Body.String())
	}
	if rec := pull(false); rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), `"approved"`) {
		t.Fatalf("legacy received approval: %d %s", rec.Code, rec.Body.String())
	}
	rec := httptest.NewRecorder()
	a.handleAdminHome(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Approved client ranges:") || !strings.Contains(rec.Body.String(), "192.0.2.0/24") {
		t.Fatalf("missing scope display: %d %s", rec.Code, rec.Body.String())
	}
	d.ApprovalRanges = nil
	if err := s.CreateDecision(d); err == nil {
		t.Fatal("implicit restriction removal")
	}
	d.ClearApprovalRanges = true
	if err := s.CreateDecision(d); err != nil {
		t.Fatal(err)
	}
	if rec := pull(false); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "192.0.2.0/24") {
		t.Fatalf("superseded scope delivered: %d %s", rec.Code, rec.Body.String())
	}
	policy, _, err := s.PolicyForNode(n, "")
	if err != nil || len(policy) != 1 || policy[0].ApprovalRanges != nil {
		t.Fatalf("effective policy: %+v %v", policy, err)
	}
}
func TestBroadScopeRequiresEveryNodeAndGuardsRegistration(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	n := Node{ID: "one", Kind: "tlsgate", Host: "one.example.com", AllowedCertName: "one", Status: statusActive}
	if err := s.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
	scope, err := approval.New([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{ScopeType: "kind", ScopeID: "tlsgate", Fingerprint: "shared", Status: decisionApproved, ApprovalRanges: scope}
	if err := s.CreateDecision(d); err == nil {
		t.Fatal("unsupported kind target accepted")
	}
	if err := s.RecordScopeCapability(n, true); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDecision(d); err != nil {
		t.Fatal(err)
	}
	n.ID = "two"
	n.Host = "two.example.com"
	n.AllowedCertName = "two"
	if err := s.UpsertNode(n); err == nil {
		t.Fatal("registered old node under restricted kind policy")
	}
	d.Status = decisionBlocked
	d.ApprovalRanges = nil
	if err := s.CreateDecision(d); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(n); err != nil {
		t.Fatal(err)
	}
}
func TestScopedDecisionAPIRejectsEmptyAndInvalidRanges(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	a := app{store: s, auth: &AuthService{}}
	for _, ranges := range []string{`[]`, `["bad"]`, `["::ffff:192.0.2.0/120"]`} {
		req := httptest.NewRequest(http.MethodPost, "/api/decisions", strings.NewReader(`{"scope_type":"global","fingerprint":"fp","status":"approved","approval_ranges":`+ranges+`}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.handleAdminDecisionAPI(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("accepted %s: %d", ranges, rec.Code)
		}
	}
}
