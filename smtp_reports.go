package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const maxSMTPReportItems = 256

var errStaleSMTPReport = errors.New("SMTP report is older than the stored generation")
var replayIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type SMTPReport struct {
	SchemaVersion int               `json:"schema_version"`
	InstanceID    string            `json:"instance_id"`
	SMTPInstance  string            `json:"smtp_instance"`
	Listener      string            `json:"listener"`
	CoverageStart time.Time         `json:"coverage_start"`
	CoverageEnd   time.Time         `json:"coverage_end"`
	GeneratedAt   time.Time         `json:"generated_at"`
	ReplayID      string            `json:"replay_id"`
	Summary       SMTPReportSummary `json:"summary"`
	Truncated     SMTPTruncated     `json:"truncated"`
	NodeID        string            `json:"node_id,omitempty"`
	NodeHost      string            `json:"node_host,omitempty"`
	ReceivedAt    string            `json:"received_at,omitempty"`
}

type SMTPTruncated struct {
	Fingerprints int `json:"fingerprints"`
	Records      int `json:"records"`
}

type SMTPReportSummary struct {
	Messages                 int                        `json:"messages"`
	Matched                  int                        `json:"matched"`
	Unmatched                int                        `json:"unmatched"`
	Spam                     int                        `json:"spam"`
	Ham                      int                        `json:"ham"`
	Unknown                  int                        `json:"unknown"`
	Connections              int                        `json:"connections"`
	STARTTLS                 int                        `json:"starttls"`
	NoObservedTLS            int                        `json:"no_observed_tls"`
	Incomplete               int                        `json:"incomplete"`
	MalformedEvents          int                        `json:"malformed_events"`
	MalformedVerdicts        int                        `json:"malformed_verdicts"`
	TLSMessages              int                        `json:"tls_messages"`
	PlaintextMessages        int                        `json:"plaintext_messages"`
	UnknownTransportMessages int                        `json:"unknown_transport_messages"`
	Reasons                  []SMTPReasonCount          `json:"unmatched_reasons"`
	Fingerprints             []SMTPFingerprintAggregate `json:"fingerprints"`
	Records                  []SMTPCorrelation          `json:"records"`
}

type SMTPReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}
type SMTPFingerprintAggregate struct {
	JA4     string `json:"ja4"`
	Spam    int    `json:"spam"`
	Ham     int    `json:"ham"`
	Unknown int    `json:"unknown"`
}
type SMTPCorrelation struct {
	QueueID        string   `json:"queue_id"`
	Classification string   `json:"classification"`
	JA3            string   `json:"ja3,omitempty"`
	JA4            string   `json:"ja4,omitempty"`
	Reason         string   `json:"reason"`
	ConnectionID   string   `json:"connection_id,omitempty"`
	Client         string   `json:"client,omitempty"`
	Listener       string   `json:"listener,omitempty"`
	Action         string   `json:"action,omitempty"`
	VerdictAt      string   `json:"verdict_at,omitempty"`
	MessageAt      string   `json:"message_at"`
	SessionStart   string   `json:"session_start,omitempty"`
	Transport      string   `json:"transport"`
	Symbols        []string `json:"symbols,omitempty"`
	Score          float64  `json:"score"`
}

func validateSMTPReport(report SMTPReport, node Node) error {
	if report.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", report.SchemaVersion)
	}
	if report.InstanceID != node.ID {
		return errors.New("request instance_id does not match authorized node")
	}
	if node.Kind != "tlsgate" {
		return errors.New("node is not an SMTP report source")
	}
	if report.SMTPInstance == "" || len(report.SMTPInstance) > 128 || strings.TrimSpace(report.SMTPInstance) != report.SMTPInstance {
		return errors.New("invalid smtp_instance")
	}
	if len(report.Listener) > 256 {
		return errors.New("invalid listener")
	}
	if _, _, err := net.SplitHostPort(report.Listener); err != nil {
		return fmt.Errorf("listener must be an exact IP:port endpoint: %w", err)
	}
	if report.CoverageStart.IsZero() || report.CoverageEnd.Before(report.CoverageStart) || report.GeneratedAt.Before(report.CoverageEnd) {
		return errors.New("require coverage_start <= coverage_end <= generated_at")
	}
	if report.CoverageEnd.Sub(report.CoverageStart) > 48*time.Hour {
		return errors.New("coverage window exceeds 48 hours")
	}
	if !replayIDPattern.MatchString(report.ReplayID) {
		return errors.New("invalid replay_id")
	}
	wantReplay, err := smtpReportReplayID(report)
	if err != nil {
		return err
	}
	if report.ReplayID != wantReplay {
		return errors.New("replay_id does not match report content")
	}
	if len(report.Summary.Fingerprints) > maxSMTPReportItems || len(report.Summary.Records) > maxSMTPReportItems || len(report.Summary.Reasons) > maxSMTPReportItems {
		return errors.New("SMTP report evidence exceeds item limit")
	}
	counts := []int{report.Summary.Messages, report.Summary.Matched, report.Summary.Unmatched, report.Summary.Spam, report.Summary.Ham, report.Summary.Unknown, report.Summary.Connections, report.Summary.STARTTLS, report.Summary.NoObservedTLS, report.Summary.Incomplete, report.Summary.MalformedEvents, report.Summary.MalformedVerdicts, report.Summary.TLSMessages, report.Summary.PlaintextMessages, report.Summary.UnknownTransportMessages, report.Truncated.Fingerprints, report.Truncated.Records}
	for _, count := range counts {
		if count < 0 {
			return errors.New("SMTP report counts must be non-negative")
		}
	}
	if report.Summary.Matched+report.Summary.Unmatched != report.Summary.Messages {
		return errors.New("matched and unmatched must equal messages")
	}
	if report.Summary.Spam+report.Summary.Ham+report.Summary.Unknown != report.Summary.Matched {
		return errors.New("spam, ham, and unknown must equal matched")
	}
	reasonTotal := 0
	for _, reason := range report.Summary.Reasons {
		if reason.Reason == "" || len(reason.Reason) > 128 || reason.Count < 0 {
			return errors.New("invalid unmatched reason")
		}
		reasonTotal += reason.Count
	}
	if reasonTotal != report.Summary.Unmatched {
		return errors.New("unmatched reason counts must equal unmatched")
	}
	for _, fingerprint := range report.Summary.Fingerprints {
		if fingerprint.JA4 == "" || len(fingerprint.JA4) > 256 || fingerprint.Spam < 0 || fingerprint.Ham < 0 || fingerprint.Unknown < 0 {
			return errors.New("invalid fingerprint aggregate")
		}
	}
	for _, record := range report.Summary.Records {
		if len(record.QueueID) > 128 || len(record.ConnectionID) > 128 || len(record.Client) > 256 || len(record.Listener) > 256 || len(record.Symbols) > 256 {
			return errors.New("invalid correlation evidence")
		}
		if record.Listener != "" && record.Listener != report.Listener {
			return errors.New("evidence listener does not match report listener")
		}
		switch record.Classification {
		case "spam", "ham", "unknown":
		default:
			return errors.New("invalid evidence classification")
		}
		switch record.Transport {
		case "starttls", "plaintext", "unknown":
		default:
			return errors.New("invalid evidence transport")
		}
	}
	return nil
}

func smtpReportReplayID(report SMTPReport) (string, error) {
	canonical, err := json.Marshal(struct {
		Instance, Listener string
		Start, End         time.Time
		Summary            SMTPReportSummary
		Truncated          SMTPTruncated
	}{report.SMTPInstance, report.Listener, report.CoverageStart.UTC(), report.CoverageEnd.UTC(), report.Summary, report.Truncated})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Store) UpsertSMTPReport(node Node, report SMTPReport) (bool, error) {
	if err := validateSMTPReport(report, node); err != nil {
		return false, err
	}
	report.NodeID, report.NodeHost = "", ""
	body, err := json.Marshal(report)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previousReplay, previousGenerated string
	err = tx.QueryRow(`SELECT replay_id,generated_at FROM smtp_reports WHERE node_id=? AND smtp_instance=? AND listener=?`, node.ID, report.SMTPInstance, report.Listener).Scan(&previousReplay, &previousGenerated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil {
		if previousReplay == report.ReplayID {
			return false, nil
		}
		previous, parseErr := time.Parse(time.RFC3339Nano, previousGenerated)
		if parseErr != nil {
			return false, parseErr
		}
		if !report.GeneratedAt.After(previous) {
			return false, errStaleSMTPReport
		}
	}
	now := nowString()
	_, err = tx.Exec(`INSERT INTO smtp_reports(node_id,smtp_instance,listener,replay_id,coverage_start,coverage_end,generated_at,received_at,report_json) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id,smtp_instance,listener) DO UPDATE SET replay_id=excluded.replay_id,coverage_start=excluded.coverage_start,coverage_end=excluded.coverage_end,generated_at=excluded.generated_at,received_at=excluded.received_at,report_json=excluded.report_json`, node.ID, report.SMTPInstance, report.Listener, report.ReplayID, report.CoverageStart.UTC().Format(time.RFC3339Nano), report.CoverageEnd.UTC().Format(time.RFC3339Nano), report.GeneratedAt.UTC().Format(time.RFC3339Nano), now, string(body))
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) SMTPReports() ([]SMTPReport, error) {
	rows, err := s.db.Query(`SELECT r.node_id,n.host,r.received_at,r.report_json FROM smtp_reports r JOIN nodes n ON n.id=r.node_id ORDER BY r.generated_at DESC,r.node_id,r.smtp_instance,r.listener`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []SMTPReport
	for rows.Next() {
		var nodeID, host, received, raw string
		if err := rows.Scan(&nodeID, &host, &received, &raw); err != nil {
			return nil, err
		}
		var report SMTPReport
		if err := json.Unmarshal([]byte(raw), &report); err != nil {
			return nil, err
		}
		report.NodeID, report.NodeHost, report.ReceivedAt = nodeID, host, received
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (a *app) handleSMTPReport(w http.ResponseWriter, r *http.Request) {
	node, ok := a.authorizeNode(w, r, r.URL.Query().Get("instance_id"))
	if !ok {
		return
	}
	var report SMTPReport
	if err := readJSON(r, &report); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	replaced, err := a.store.UpsertSMTPReport(node, report)
	if errors.Is(err, errStaleSMTPReport) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "replaced": replaced, "replay_id": report.ReplayID})
}

func (a *app) handleAdminSMTPReportsAPI(w http.ResponseWriter, r *http.Request) {
	reports, err := a.store.SMTPReports()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, reports)
}
