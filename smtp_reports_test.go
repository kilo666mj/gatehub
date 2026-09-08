package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSMTPReport(nodeID, replay string, generated time.Time) SMTPReport {
	report := SMTPReport{
		SchemaVersion: 1, InstanceID: nodeID, SMTPInstance: "mx-public-smtp", Listener: "[::]:25",
		CoverageStart: generated.Add(-24 * time.Hour), CoverageEnd: generated.Add(-2 * time.Minute), GeneratedAt: generated, ReplayID: replay,
		Summary: SMTPReportSummary{Messages: 3, Matched: 2, Unmatched: 1, Spam: 1, Ham: 1, Reasons: []SMTPReasonCount{{Reason: "no_connection", Count: 1}}, Fingerprints: []SMTPFingerprintAggregate{{JA4: "t13d1516h2_abc_def", Spam: 1, Ham: 1}}, Records: []SMTPCorrelation{{QueueID: "Q1", Classification: "spam", Reason: "matched", MessageAt: generated.Add(-time.Hour).Format(time.RFC3339Nano), Transport: "starttls"}}},
	}
	if replay == "" {
		report.ReplayID, _ = smtpReportReplayID(report)
	}
	return report
}

func TestSMTPReportsAreNodeIsolatedReplaySafeAndMonotonic(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	nodeA := Node{ID: "mail-a", Kind: "tlsgate", Host: "mx-a", AllowedCertName: "mx-a", Status: statusActive}
	nodeB := Node{ID: "mail-b", Kind: "tlsgate", Host: "mx-b", AllowedCertName: "mx-b", Status: statusActive}
	if err := store.UpsertNode(nodeA); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertNode(nodeB); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	reportA := testSMTPReport(nodeA.ID, "", now)
	if replaced, err := store.UpsertSMTPReport(nodeA, reportA); err != nil || !replaced {
		t.Fatalf("first upsert = %v, %v", replaced, err)
	}
	if replaced, err := store.UpsertSMTPReport(nodeA, reportA); err != nil || replaced {
		t.Fatalf("replay = %v, %v", replaced, err)
	}
	stale := testSMTPReport(nodeA.ID, "", now.Add(-time.Minute))
	if _, err := store.UpsertSMTPReport(nodeA, stale); !errors.Is(err, errStaleSMTPReport) {
		t.Fatalf("stale error = %v", err)
	}
	reportB := testSMTPReport(nodeB.ID, "", now)
	if _, err := store.UpsertSMTPReport(nodeB, reportB); err != nil {
		t.Fatal(err)
	}
	reports, err := store.SMTPReports()
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0].NodeID == reports[1].NodeID {
		t.Fatalf("node isolation failed: %+v", reports)
	}
	var decisions int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&decisions); err != nil || decisions != 0 {
		t.Fatalf("report wrote policy: count=%d err=%v", decisions, err)
	}
}

func TestSMTPReportHandlerAuthenticatesKindAndIdentity(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	token := strings.Repeat("secret", 8)
	node := Node{ID: "mail-tls", Kind: "tlsgate", Host: "mx", AllowedCertName: "mx", TokenHash: hashToken(token), Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	a := app{store: store, auth: &AuthService{}}
	report := testSMTPReport(node.ID, "", time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC))
	body, _ := json.Marshal(report)
	request := func(instance, bearer string, payload []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/smtp/reports?instance_id="+instance, bytes.NewReader(payload))
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		a.publicMux().ServeHTTP(w, r)
		return w
	}
	if got := request(node.ID, "wrong", body).Code; got != http.StatusForbidden {
		t.Fatalf("bad token status=%d", got)
	}
	if got := request(node.ID, token, body).Code; got != http.StatusOK {
		t.Fatalf("valid report status=%d", got)
	}
	report.InstanceID = "other"
	mismatch, _ := json.Marshal(report)
	if got := request(node.ID, token, mismatch).Code; got != http.StatusBadRequest {
		t.Fatalf("identity mismatch status=%d", got)
	}
	logNode := Node{ID: "logs", Kind: "log_watcher", Host: "logs", AllowedCertName: "logs", TokenHash: hashToken(token), Status: statusActive}
	if err := store.UpsertNode(logNode); err != nil {
		t.Fatal(err)
	}
	report.InstanceID = logNode.ID
	wrongKind, _ := json.Marshal(report)
	if got := request(logNode.ID, token, wrongKind).Code; got != http.StatusBadRequest {
		t.Fatalf("wrong kind status=%d", got)
	}
	if got := request(node.ID, token, bytes.Repeat([]byte(" "), (2<<20)+1)).Code; got != http.StatusBadRequest {
		t.Fatalf("oversize status=%d", got)
	}
}

func TestSMTPReportsAdminAPIAndDashboard(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	node := Node{ID: "mail-tls", Kind: "tlsgate", Host: "mx", AllowedCertName: "mx", Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertSMTPReport(node, testSMTPReport(node.ID, "", time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
	a := app{store: store, auth: &AuthService{}}
	for _, path := range []string{"/api/smtp-reports", "/"} {
		w := httptest.NewRecorder()
		a.adminMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "mx-public-smtp") {
			t.Fatalf("GET %s status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
}

func TestSMTPReportTLSGateWireContract(t *testing.T) {
	// This is the exact lower-case shape emitted by tlsgate's smtpReportEnvelope
	// and smtpSummary, kept independent from Gatehub's Go marshaler so field-name
	// drift between the two repositories fails visibly.
	wire := `{
  "schema_version":1,"instance_id":"mail-tls","smtp_instance":"mx-public-smtp","listener":"[::]:25",
  "coverage_start":"2026-09-07T12:00:00Z","coverage_end":"2026-09-08T11:58:00Z","generated_at":"2026-09-08T12:00:00Z",
  "replay_id":"REPLAY_ID",
  "summary":{"messages":2,"matched":1,"unmatched":1,"spam":1,"ham":0,"unknown":0,"connections":2,"starttls":1,
    "no_observed_tls":1,"incomplete":0,"malformed_events":0,"malformed_verdicts":0,"tls_messages":1,
    "plaintext_messages":1,"unknown_transport_messages":0,"unmatched_reasons":[{"reason":"message_before_observed_starttls","count":1}],
    "fingerprints":[{"ja4":"t13d1516h2_abc_def","spam":1,"ham":0,"unknown":0}],
    "records":[{"queue_id":"Q1","classification":"spam","ja3":"0123456789abcdef0123456789abcdef","ja4":"t13d1516h2_abc_def",
      "reason":"matched","connection_id":"c1","client":"192.0.2.1:12345","listener":"[::]:25","action":"add header",
      "verdict_at":"2026-09-08T11:00:02Z","message_at":"2026-09-08T11:00:01Z","session_start":"2026-09-08T11:00:00Z",
      "symbols":["BAYES_SPAM"],"score":12.5,"transport":"starttls"}]},
  "truncated":{"fingerprints":0,"records":0}}
`
	var wireReport SMTPReport
	if err := json.Unmarshal([]byte(wire), &wireReport); err != nil {
		t.Fatal(err)
	}
	replayID, err := smtpReportReplayID(wireReport)
	if err != nil {
		t.Fatal(err)
	}
	wire = strings.Replace(wire, "REPLAY_ID", replayID, 1)
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	token := strings.Repeat("wire-secret", 4)
	node := Node{ID: "mail-tls", Kind: "tlsgate", Host: "mx", AllowedCertName: "mx", TokenHash: hashToken(token), Status: statusActive}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	a := app{store: store, auth: &AuthService{}}
	r := httptest.NewRequest(http.MethodPost, "/v1/smtp/reports?instance_id=mail-tls", strings.NewReader(wire))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.publicMux().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("TLSGate wire report status=%d body=%s", w.Code, w.Body.String())
	}
	reports, err := store.SMTPReports()
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Summary.Records[0].ConnectionID != "c1" || reports[0].Summary.UnknownTransportMessages != 0 {
		t.Fatalf("wire report did not round-trip: %+v", reports)
	}
}
