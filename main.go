package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var version = "dev"

//go:embed assets/*
var assetsFS embed.FS

const (
	statusActive   = "active"
	statusDisabled = "disabled"
	statusRevoked  = "revoked"

	decisionPending  = "pending"
	decisionApproved = "approved"
	decisionBlocked  = "blocked"

	maxObservationsPerBatch = 1000
	maxFingerprintLength    = 256
	maxObservationIPs       = 128
	maxObservationPorts     = 128
	maxObservationMetaKeys  = 32
	maxObservationMetaBytes = 8192
	maxNodeTokenLength      = 4096
	minNodeTokenLength      = 32
)

type config struct {
	DBPath             string
	AdminListen        string
	PublicListen       string
	PublicCert         string
	PublicKey          string
	ClientCA           string
	ClientCRL          string
	PublicAuth         string
	AdminAuth          string
	AdminRPID          string
	AdminOrigin        string
	AdminRPName        string
	AdminUserName      string
	AdminSessionMaxAge int
}

type app struct {
	store *Store
	auth  *AuthService
}

func main() {
	cfg := parseConfig()
	store, err := NewStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()

	auth, err := newAuthService(cfg, store.db)
	if err != nil {
		log.Fatalf("init admin auth: %v", err)
	}
	a := &app{store: store, auth: auth}
	errCh := make(chan error, 2)
	if cfg.AdminListen != "" {
		go func() {
			log.Printf("admin listening with %s auth on http://%s", cfg.AdminAuth, cfg.AdminListen)
			errCh <- http.ListenAndServe(cfg.AdminListen, a.adminMux())
		}()
	}
	if cfg.PublicListen != "" {
		if cfg.PublicAuth != "token" && (cfg.PublicCert == "" || cfg.PublicKey == "") {
			log.Fatalf("public auth mode %q requires --public-cert and --public-key", cfg.PublicAuth)
		}
		if (cfg.PublicAuth == "mtls" || cfg.PublicAuth == "both") && cfg.ClientCA == "" {
			log.Fatalf("public auth mode %q requires --client-ca", cfg.PublicAuth)
		}
		if cfg.PublicCert == "" && cfg.PublicKey == "" {
			go func() {
				log.Printf("public sync listening with %s auth on http://%s", cfg.PublicAuth, cfg.PublicListen)
				errCh <- http.ListenAndServe(cfg.PublicListen, a.publicMux())
			}()
		} else {
			tlsCfg, err := loadPublicTLSConfig(cfg)
			if err != nil {
				log.Fatalf("load public TLS config: %v", err)
			}
			srv := &http.Server{
				Addr:      cfg.PublicListen,
				Handler:   a.publicMux(),
				TLSConfig: tlsCfg,
			}
			go func() {
				log.Printf("public sync listening with %s auth on https://%s", cfg.PublicAuth, cfg.PublicListen)
				errCh <- srv.ListenAndServeTLS("", "")
			}()
		}
	}
	if cfg.AdminListen == "" && cfg.PublicListen == "" {
		log.Fatal("nothing to listen on; set --admin-listen and/or --public-listen")
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func parseConfig() config {
	var cfg config
	flag.StringVar(&cfg.DBPath, "db", "gatehub.sqlite", "SQLite database path")
	flag.StringVar(&cfg.AdminListen, "admin-listen", "127.0.0.1:8081", "internal admin listen address; empty disables")
	flag.StringVar(&cfg.PublicListen, "public-listen", "", "public mTLS sync listen address; empty disables")
	flag.StringVar(&cfg.PublicCert, "public-cert", "", "server certificate for public mTLS listener")
	flag.StringVar(&cfg.PublicKey, "public-key", "", "server private key for public mTLS listener")
	flag.StringVar(&cfg.ClientCA, "client-ca", "", "CA certificate used to verify node client certificates")
	flag.StringVar(&cfg.ClientCRL, "client-crl", "", "optional PEM CRL for revoked node client certificates")
	flag.StringVar(&cfg.PublicAuth, "public-auth", "mtls", "public sync auth mode: mtls, token, or both")
	flag.StringVar(&cfg.AdminAuth, "admin-auth", authModeWebAuthn, "admin auth mode: webauthn or none (none is for localhost dev only)")
	flag.StringVar(&cfg.AdminRPID, "admin-webauthn-rpid", "", "WebAuthn relying party ID (admin hostname, e.g. gatehub.example.com)")
	flag.StringVar(&cfg.AdminOrigin, "admin-webauthn-origin", "", "WebAuthn origin for the admin UI (e.g. https://gatehub.example.com)")
	flag.StringVar(&cfg.AdminRPName, "admin-webauthn-rpname", "gatehub", "WebAuthn relying party display name")
	flag.StringVar(&cfg.AdminUserName, "admin-webauthn-username", "gatehub admin", "WebAuthn user display name")
	flag.IntVar(&cfg.AdminSessionMaxAge, "admin-session-max-age", 28800, "admin session lifetime in seconds; 0 means no expiry")
	flag.Parse()
	switch cfg.PublicAuth {
	case "mtls", "token", "both":
	default:
		log.Fatalf("invalid --public-auth %q (want mtls, token, or both)", cfg.PublicAuth)
	}
	// Treat an empty value (e.g. an unset environment variable in the systemd
	// unit) as the secure default rather than an error, so a stale env file
	// fails closed with an actionable message instead of "invalid mode".
	if cfg.AdminAuth == "" {
		cfg.AdminAuth = authModeWebAuthn
	}
	switch cfg.AdminAuth {
	case authModeWebAuthn:
		if cfg.AdminListen != "" && (cfg.AdminRPID == "" || cfg.AdminOrigin == "") {
			log.Fatalf("admin auth mode %q requires --admin-webauthn-rpid and --admin-webauthn-origin (use --admin-auth none only for localhost dev)", cfg.AdminAuth)
		}
	case authModeNone:
	default:
		log.Fatalf("invalid --admin-auth %q (want webauthn or none)", cfg.AdminAuth)
	}
	return cfg
}

func loadPublicTLSConfig(cfg config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.PublicCert, cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	var pool *x509.CertPool
	revoked := map[string]bool{}
	if cfg.ClientCA != "" {
		caPEM, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, err
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no CA certs found in %s", cfg.ClientCA)
		}
	}
	if cfg.ClientCRL != "" && cfg.ClientCA != "" {
		crlPEM, err := os.ReadFile(cfg.ClientCRL)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(crlPEM)
		if block == nil {
			return nil, fmt.Errorf("no PEM CRL found in %s", cfg.ClientCRL)
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		for _, cert := range crl.RevokedCertificateEntries {
			revoked[cert.SerialNumber.String()] = true
		}
	}

	clientAuth := tls.NoClientCert
	switch cfg.PublicAuth {
	case "mtls":
		clientAuth = tls.RequireAndVerifyClientCert
	case "both":
		clientAuth = tls.VerifyClientCertIfGiven
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   clientAuth,
		VerifyConnection: func(state tls.ConnectionState) error {
			// token and both modes allow a connection without a client
			// certificate; the app layer then requires a bearer token. Only
			// mtls requires a certificate at the TLS layer.
			if len(state.PeerCertificates) == 0 {
				if cfg.PublicAuth == "mtls" {
					return errors.New("missing client certificate")
				}
				return nil
			}
			leaf := state.PeerCertificates[0]
			if revoked[leaf.SerialNumber.String()] {
				return fmt.Errorf("client certificate serial %s is revoked", leaf.SerialNumber)
			}
			if len(leaf.ExtKeyUsage) > 0 && !hasClientAuthEKU(leaf.ExtKeyUsage) {
				return errors.New("client certificate is not valid for client auth")
			}
			return nil
		},
	}, nil
}

func hasClientAuthEKU(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

type Store struct {
	db *sql.DB
}

type Node struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Host            string `json:"host"`
	AllowedCertName string `json:"allowed_cert_name"`
	TokenHash       string `json:"-"`
	Status          string `json:"status"`
	LastSeen        string `json:"last_seen,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type Fingerprint struct {
	NodeID      string         `json:"node_id"`
	Kind        string         `json:"kind"`
	Host        string         `json:"host"`
	Fingerprint string         `json:"fingerprint"`
	Status      string         `json:"status"`
	Label       string         `json:"label,omitempty"`
	FirstSeen   string         `json:"first_seen,omitempty"`
	LastSeen    string         `json:"last_seen,omitempty"`
	IPs         []string       `json:"ips,omitempty"`
	Ports       []int          `json:"ports,omitempty"`
	Count       int            `json:"count,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	UpdatedAt   string         `json:"updated_at"`
}

type Decision struct {
	ID          int64  `json:"id"`
	ScopeType   string `json:"scope_type"`
	ScopeID     string `json:"scope_id"`
	Kind        string `json:"kind,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	Label       string `json:"label,omitempty"`
	UpdatedAt   string `json:"updated_at"`
	Actor       string `json:"actor"`
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) init() error {
	ctx := context.Background()
	for _, stmt := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA journal_mode = WAL`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			host TEXT NOT NULL,
			allowed_cert_name TEXT NOT NULL,
			token_hash TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			last_seen TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprints (
			node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			fingerprint TEXT NOT NULL,
			kind TEXT NOT NULL,
			host TEXT NOT NULL,
			status TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL DEFAULT '',
			last_seen TEXT NOT NULL DEFAULT '',
			ips_json TEXT NOT NULL DEFAULT '[]',
			ports_json TEXT NOT NULL DEFAULT '[]',
			count INTEGER NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			updated_at TEXT NOT NULL,
			PRIMARY KEY (node_id, fingerprint)
		)`,
		`CREATE TABLE IF NOT EXISTS decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scope_type TEXT NOT NULL,
			scope_id TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL,
			status TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
			actor TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON fingerprints(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_status ON fingerprints(status)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_scope ON decisions(scope_type, scope_id, fingerprint, updated_at)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := addColumnIfMissing(s.db, "nodes", "token_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

func addColumnIfMissing(db *sql.DB, table, column, def string) error {
	rows, err := db.QueryContext(context.Background(), fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.ExecContext(context.Background(), fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}

func (s *Store) UpsertNode(n Node) error {
	if err := validateNode(n); err != nil {
		return err
	}
	now := nowString()
	if n.Status == "" {
		n.Status = statusActive
	}
	_, err := s.db.Exec(`
		INSERT INTO nodes (id, kind, host, allowed_cert_name, token_hash, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			host = excluded.host,
			allowed_cert_name = excluded.allowed_cert_name,
			token_hash = CASE WHEN excluded.token_hash != '' THEN excluded.token_hash ELSE nodes.token_hash END`,
		n.ID, n.Kind, n.Host, n.AllowedCertName, n.TokenHash, n.Status, now)
	if err == nil {
		_ = s.Audit("admin", "upsert_node", n.ID, "")
	}
	return err
}

func (s *Store) SetNodeStatus(id, status string) error {
	if !validNodeStatus(status) {
		return fmt.Errorf("invalid node status %q", status)
	}
	res, err := s.db.Exec(`UPDATE nodes SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if err := requireAffected(res, id); err != nil {
		return err
	}
	return s.Audit("admin", "set_node_status", id, status)
}

func (s *Store) Node(id string) (Node, error) {
	var n Node
	err := s.db.QueryRow(`
		SELECT id, kind, host, allowed_cert_name, token_hash, status, last_seen, created_at
		FROM nodes WHERE id = ?`, id).Scan(
		&n.ID, &n.Kind, &n.Host, &n.AllowedCertName, &n.TokenHash, &n.Status, &n.LastSeen, &n.CreatedAt)
	return n, err
}

func (s *Store) Nodes() ([]Node, error) {
	rows, err := s.db.Query(`
		SELECT id, kind, host, allowed_cert_name, token_hash, status, last_seen, created_at
		FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Kind, &n.Host, &n.AllowedCertName, &n.TokenHash, &n.Status, &n.LastSeen, &n.CreatedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (s *Store) UpsertObservations(node Node, observations []Fingerprint) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := nowString()
	for _, fp := range observations {
		if err := validateObservation(fp); err != nil {
			return err
		}
		ips, err := encodeJSON(fp.IPs)
		if err != nil {
			return err
		}
		ports, err := encodeJSON(fp.Ports)
		if err != nil {
			return err
		}
		meta, err := encodeJSON(fp.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO fingerprints (
				node_id, fingerprint, kind, host, status, label, first_seen, last_seen,
				ips_json, ports_json, count, metadata_json, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(node_id, fingerprint) DO UPDATE SET
				kind = excluded.kind,
				host = excluded.host,
				label = CASE WHEN excluded.label != '' THEN excluded.label ELSE fingerprints.label END,
				first_seen = CASE WHEN fingerprints.first_seen != '' THEN fingerprints.first_seen ELSE excluded.first_seen END,
				last_seen = excluded.last_seen,
				ips_json = excluded.ips_json,
				ports_json = excluded.ports_json,
				count = excluded.count,
				metadata_json = excluded.metadata_json,
				updated_at = excluded.updated_at`,
			node.ID, fp.Fingerprint, node.Kind, node.Host, decisionPending, fp.Label, fp.FirstSeen,
			fp.LastSeen, ips, ports, fp.Count, meta, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE nodes SET last_seen = ? WHERE id = ?`, now, node.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
		node.ID, "sync_observations", node.ID, fmt.Sprintf("%d observations", len(observations)), now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Fingerprints(status string) ([]Fingerprint, error) {
	query := `
		SELECT node_id, fingerprint, kind, host, status, label, first_seen, last_seen,
			ips_json, ports_json, count, metadata_json, updated_at
		FROM fingerprints`
	args := []any{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY last_seen DESC, node_id, fingerprint`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var fps []Fingerprint
	for rows.Next() {
		fp, err := scanFingerprint(rows)
		if err != nil {
			return nil, err
		}
		fps = append(fps, fp)
	}
	return fps, rows.Err()
}

func (s *Store) CreateDecision(d Decision) error {
	if err := validateDecision(d); err != nil {
		return err
	}
	now := nowString()
	if d.Actor == "" {
		d.Actor = "admin"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		INSERT INTO decisions (scope_type, scope_id, kind, fingerprint, status, label, updated_at, actor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ScopeType, d.ScopeID, d.Kind, d.Fingerprint, d.Status, d.Label, now, d.Actor); err != nil {
		return err
	}
	if d.ScopeType == "instance" {
		if _, err := tx.Exec(`
			UPDATE fingerprints
			SET status = ?, label = CASE WHEN ? != '' THEN ? ELSE label END, updated_at = ?
			WHERE node_id = ? AND fingerprint = ?`,
			d.Status, d.Label, d.Label, now, d.ScopeID, d.Fingerprint); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
		d.Actor, "create_decision", d.ScopeType+":"+d.ScopeID+":"+d.Fingerprint, d.Status, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PolicyForNode(node Node, since string) ([]Decision, string, error) {
	query := `
		SELECT id, scope_type, scope_id, kind, fingerprint, status, label, updated_at, actor
		FROM decisions
		WHERE updated_at > ?
		  AND (
			(scope_type = 'instance' AND scope_id = ?)
			OR (scope_type = 'kind' AND scope_id = ?)
			OR (scope_type = 'global')
		  )
		ORDER BY updated_at ASC, id ASC`
	rows, err := s.db.Query(query, since, node.ID, node.Kind)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var decisions []Decision
	cursor := since
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.ID, &d.ScopeType, &d.ScopeID, &d.Kind, &d.Fingerprint, &d.Status, &d.Label, &d.UpdatedAt, &d.Actor); err != nil {
			return nil, "", err
		}
		decisions = append(decisions, d)
		cursor = d.UpdatedAt
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return decisions, cursor, nil
}

func (s *Store) Audit(actor, action, target, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log (actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
		actor, action, target, detail, nowString())
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFingerprint(rows rowScanner) (Fingerprint, error) {
	var fp Fingerprint
	var ips, ports, meta string
	if err := rows.Scan(&fp.NodeID, &fp.Fingerprint, &fp.Kind, &fp.Host, &fp.Status, &fp.Label,
		&fp.FirstSeen, &fp.LastSeen, &ips, &ports, &fp.Count, &meta, &fp.UpdatedAt); err != nil {
		return fp, err
	}
	if err := decodeJSON(ips, &fp.IPs); err != nil {
		return fp, err
	}
	if err := decodeJSON(ports, &fp.Ports); err != nil {
		return fp, err
	}
	if err := decodeJSON(meta, &fp.Metadata); err != nil {
		return fp, err
	}
	return fp, nil
}

func (a *app) publicMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/observations/batch", a.handleObservationBatch)
	mux.HandleFunc("GET /v1/policy", a.handlePolicy)
	return mux
}

func (a *app) adminMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.FileServer(http.FS(assetsFS)))
	mux.HandleFunc("GET /favicon.ico", serveAsset("assets/favicon.png", "image/png"))
	mux.HandleFunc("GET /favicon.png", serveAsset("assets/favicon.png", "image/png"))
	mux.HandleFunc("GET /apple-touch-icon.png", serveAsset("assets/apple-touch-icon.png", "image/png"))
	mux.HandleFunc("GET /site.webmanifest", serveManifest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Authentication endpoints (unauthenticated by design).
	mux.HandleFunc("GET /login", a.auth.loginPage)
	mux.HandleFunc("GET /api/auth/status", a.auth.status)
	mux.HandleFunc("POST /api/auth/register/begin", a.auth.registerBegin)
	mux.HandleFunc("POST /api/auth/register/complete", a.auth.registerComplete)
	mux.HandleFunc("POST /api/auth/login/begin", a.auth.loginBegin)
	mux.HandleFunc("POST /api/auth/login/complete", a.auth.loginComplete)
	mux.HandleFunc("POST /api/auth/logout", a.auth.logout)

	// Gated admin surface.
	mux.HandleFunc("GET /", a.auth.require(a.handleAdminHome))
	mux.HandleFunc("POST /nodes", a.auth.require(a.handleAdminUpsertNode))
	mux.HandleFunc("POST /nodes/status", a.auth.require(a.handleAdminNodeStatus))
	mux.HandleFunc("POST /decisions", a.auth.require(a.handleAdminDecision))
	mux.HandleFunc("GET /api/fingerprints", a.auth.require(a.handleAdminFingerprintsAPI))
	return mux
}

func serveAsset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := assetsFS.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	}
}

func serveManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(`{
  "name": "gatehub",
  "short_name": "gatehub",
  "description": "Gatehub fingerprint control plane",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#f5f7f8",
  "theme_color": "#0f766e",
  "icons": [
    {
      "src": "/assets/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/assets/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}`))
}

type observationBatchRequest struct {
	InstanceID   string        `json:"instance_id"`
	Observations []Fingerprint `json:"observations"`
}

func (a *app) handleObservationBatch(w http.ResponseWriter, r *http.Request) {
	node, ok := a.authorizeNode(w, r, r.URL.Query().Get("instance_id"))
	if !ok {
		return
	}
	var req observationBatchRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.InstanceID != "" && req.InstanceID != node.ID {
		writeError(w, http.StatusForbidden, fmt.Errorf("request instance_id %q does not match certificate-authorized node %q", req.InstanceID, node.ID))
		return
	}
	if len(req.Observations) > maxObservationsPerBatch {
		writeError(w, http.StatusBadRequest, fmt.Errorf("too many observations: %d > %d", len(req.Observations), maxObservationsPerBatch))
		return
	}
	if err := a.store.UpsertObservations(node, req.Observations); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(req.Observations)})
}

func (a *app) handlePolicy(w http.ResponseWriter, r *http.Request) {
	instanceID := r.URL.Query().Get("instance_id")
	node, ok := a.authorizeNode(w, r, instanceID)
	if !ok {
		return
	}
	since := r.URL.Query().Get("since")
	decisions, cursor, err := a.store.PolicyForNode(node, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cursor": cursor, "decisions": decisions})
}

func (a *app) authorizeNode(w http.ResponseWriter, r *http.Request, instanceID string) (Node, bool) {
	if instanceID == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing instance_id"))
		return Node{}, false
	}
	// Return a single, uniform denial for every credential failure so an
	// unauthenticated caller cannot enumerate which instance_ids are registered
	// or probe node status. The specific reason is logged server-side.
	deny := func(reason string) (Node, bool) {
		log.Printf("public auth denied for instance_id=%q: %s", instanceID, reason)
		writeError(w, http.StatusForbidden, errors.New("not authorized"))
		return Node{}, false
	}
	node, err := a.store.Node(instanceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return deny("node is not registered")
		}
		writeError(w, http.StatusInternalServerError, err)
		return Node{}, false
	}
	if node.Status != statusActive {
		return deny(fmt.Sprintf("node is %s", node.Status))
	}

	if token := bearerToken(r); token != "" {
		if node.TokenHash == "" {
			return deny("node has no token configured")
		}
		if subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(node.TokenHash)) != 1 {
			return deny("invalid node token")
		}
		return node, true
	}

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return deny("missing node credentials")
	}
	cert := r.TLS.PeerCertificates[0]
	if !certMatchesName(cert, node.AllowedCertName) {
		return deny("client certificate is not authorized")
	}
	return node, true
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	prefix := "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func certMatchesName(cert *x509.Certificate, name string) bool {
	if name == "" {
		return false
	}
	if cert.Subject.CommonName == name {
		return true
	}
	for _, dns := range cert.DNSNames {
		if dns == name {
			return true
		}
	}
	for _, uri := range cert.URIs {
		if uri.String() == name {
			return true
		}
	}
	return false
}

func (a *app) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.store.Nodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	fps, err := a.store.Fingerprints("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sort.SliceStable(fps, func(i, j int) bool {
		if fingerprintStatusRank(fps[i].Status) != fingerprintStatusRank(fps[j].Status) {
			return fingerprintStatusRank(fps[i].Status) < fingerprintStatusRank(fps[j].Status)
		}
		return fps[i].LastSeen > fps[j].LastSeen
	})
	data := struct {
		Nodes        []Node
		Fingerprints []Fingerprint
		Statuses     []string
		AuthEnabled  bool
		CSRFToken    string
	}{nodes, fps, []string{decisionApproved, decisionBlocked, decisionPending}, a.auth.enabled(), a.auth.csrfToken(r)}
	if err := adminTemplate.Execute(w, data); err != nil {
		log.Printf("render admin: %v", err)
	}
}

func fingerprintStatusRank(status string) int {
	switch status {
	case decisionApproved:
		return 0
	case decisionBlocked:
		return 1
	case decisionPending:
		return 2
	default:
		return 3
	}
}

func (a *app) handleAdminUpsertNode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.auth.requireCSRF(w, r) {
		return
	}
	tokenHash, err := hashTokenOrEmpty(strings.TrimSpace(r.FormValue("token")))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	n := Node{
		ID:              strings.TrimSpace(r.FormValue("id")),
		Kind:            strings.TrimSpace(r.FormValue("kind")),
		Host:            strings.TrimSpace(r.FormValue("host")),
		AllowedCertName: strings.TrimSpace(r.FormValue("allowed_cert_name")),
		TokenHash:       tokenHash,
		Status:          statusActive,
	}
	if err := a.store.UpsertNode(n); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func hashTokenOrEmpty(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	if err := validateNodeToken(token); err != nil {
		return "", err
	}
	return hashToken(token), nil
}

func (a *app) handleAdminNodeStatus(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.auth.requireCSRF(w, r) {
		return
	}
	if err := a.store.SetNodeStatus(r.FormValue("id"), r.FormValue("status")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) handleAdminDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.auth.requireCSRF(w, r) {
		return
	}
	d := Decision{
		ScopeType:   firstNonEmpty(r.FormValue("scope_type"), "instance"),
		ScopeID:     r.FormValue("scope_id"),
		Kind:        r.FormValue("kind"),
		Fingerprint: r.FormValue("fingerprint"),
		Status:      r.FormValue("status"),
		Label:       r.FormValue("label"),
		Actor:       "admin",
	}
	if err := a.store.CreateDecision(d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) handleAdminFingerprintsAPI(w http.ResponseWriter, r *http.Request) {
	fps, err := a.store.Fingerprints(r.URL.Query().Get("status"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fingerprints": fps})
}

func validateNode(n Node) error {
	if n.ID == "" || n.Kind == "" || n.Host == "" || n.AllowedCertName == "" {
		return errors.New("id, kind, host, and allowed_cert_name are required")
	}
	if n.Kind != "tlsgate" && n.Kind != "sshgate" {
		return fmt.Errorf("invalid kind %q", n.Kind)
	}
	if n.Status != "" && !validNodeStatus(n.Status) {
		return fmt.Errorf("invalid node status %q", n.Status)
	}
	return nil
}

func validateObservation(fp Fingerprint) error {
	if fp.Fingerprint == "" {
		return errors.New("fingerprint is required")
	}
	if len(fp.Fingerprint) > maxFingerprintLength || strings.ContainsAny(fp.Fingerprint, " \t\r\n") {
		return fmt.Errorf("invalid fingerprint %q", fp.Fingerprint)
	}
	if len(fp.Label) > 256 || len(fp.Kind) > 64 || len(fp.Host) > 256 {
		return errors.New("observation string field is too long")
	}
	if len(fp.FirstSeen) > 64 || len(fp.LastSeen) > 64 || len(fp.UpdatedAt) > 64 {
		return errors.New("observation timestamp field is too long")
	}
	if len(fp.IPs) > maxObservationIPs {
		return fmt.Errorf("too many IPs for %s: %d > %d", fp.Fingerprint, len(fp.IPs), maxObservationIPs)
	}
	for _, ip := range fp.IPs {
		if len(ip) > 64 {
			return fmt.Errorf("IP value is too long for %s", fp.Fingerprint)
		}
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("invalid IP %q for %s", ip, fp.Fingerprint)
		}
	}
	if len(fp.Ports) > maxObservationPorts {
		return fmt.Errorf("too many ports for %s: %d > %d", fp.Fingerprint, len(fp.Ports), maxObservationPorts)
	}
	for _, port := range fp.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d for %s", port, fp.Fingerprint)
		}
	}
	if len(fp.Metadata) > maxObservationMetaKeys {
		return fmt.Errorf("too many metadata keys for %s: %d > %d", fp.Fingerprint, len(fp.Metadata), maxObservationMetaKeys)
	}
	meta, err := json.Marshal(fp.Metadata)
	if err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	if len(meta) > maxObservationMetaBytes {
		return fmt.Errorf("metadata too large for %s: %d > %d bytes", fp.Fingerprint, len(meta), maxObservationMetaBytes)
	}
	// The node-reported status is intentionally ignored: gatehub is authoritative
	// for a fingerprint's status, which changes only through admin decisions. A
	// newly observed fingerprint is recorded as pending awaiting a decision.
	return nil
}

func validateNodeToken(token string) error {
	if len(token) < minNodeTokenLength {
		return fmt.Errorf("node token must be at least %d characters", minNodeTokenLength)
	}
	if len(token) > maxNodeTokenLength {
		return fmt.Errorf("node token must be at most %d characters", maxNodeTokenLength)
	}
	if strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n\t ") {
		return errors.New("node token must not contain whitespace")
	}
	return nil
}

func validateDecision(d Decision) error {
	switch d.ScopeType {
	case "instance", "kind", "global":
	default:
		return fmt.Errorf("invalid scope_type %q", d.ScopeType)
	}
	if d.ScopeType != "global" && d.ScopeID == "" {
		return errors.New("scope_id is required")
	}
	if d.Fingerprint == "" {
		return errors.New("fingerprint is required")
	}
	if !validDecisionStatus(d.Status) {
		return fmt.Errorf("invalid decision status %q", d.Status)
	}
	return nil
}

func validNodeStatus(status string) bool {
	return status == statusActive || status == statusDisabled || status == statusRevoked
}

func validDecisionStatus(status string) bool {
	return status == decisionPending || status == decisionApproved || status == decisionBlocked
}

func encodeJSON(v any) (string, error) {
	if v == nil {
		return "null", nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func decodeJSON(s string, v any) error {
	if s == "" {
		s = "null"
	}
	return json.Unmarshal([]byte(s), v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	body := http.MaxBytesReader(nil, r.Body, 2<<20)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func requireAffected(res sql.Result, target string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("not found: %s", target)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func nowString() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

var adminTemplate = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0f766e">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-title" content="gatehub">
  <meta name="csrf-token" content="{{.CSRFToken}}">
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <link rel="manifest" href="/site.webmanifest">
  <title>gatehub</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7f8;
      --ink: #17201f;
      --muted: #64716f;
      --panel: #ffffff;
      --line: #d8dfdd;
      --line-strong: #b7c3c0;
      --teal: #0f766e;
      --blue: #2563eb;
      --green: #15803d;
      --amber: #b45309;
      --red: #b42318;
      --violet: #6d28d9;
      --shadow: 0 12px 34px rgba(21, 32, 31, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      padding: 18px 28px;
      color: #f8fafc;
      background: #13201f;
      border-bottom: 4px solid var(--teal);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 18px;
    }
    .brand { display: flex; align-items: center; gap: 16px; min-width: 0; }
    .mascot {
      width: 74px;
      height: 74px;
      object-fit: cover;
      object-position: 45% 24%;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,.22);
      background: #fff;
      box-shadow: 0 10px 24px rgba(0,0,0,.25);
    }
    .header-actions { display: flex; align-items: center; gap: 14px; }
    .service-legend { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
    .logout-btn {
      cursor: pointer;
      min-height: 30px;
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 760;
      color: #edf7f5;
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.28);
    }
    .logout-btn:hover { background: rgba(255,255,255,.16); }
    .logout-btn:disabled { opacity: .55; cursor: progress; }
    .service-chip {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-height: 30px;
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 760;
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.18);
      color: #edf7f5;
    }
    .service-chip::before,
    .kind::before {
      content: "";
      flex: 0 0 auto;
      background-position: center;
      background-repeat: no-repeat;
      background-size: cover;
    }
    .service-chip::before {
      width: 22px;
      height: 16px;
      border-radius: 4px;
      box-shadow: 0 0 0 1px rgba(255,255,255,.18);
    }
    .service-tls::before,
    .kind-tlsgate::before { background-image: url("/assets/porter-icon-green.png"); }
    .service-ssh::before,
    .kind-sshgate::before { background-image: url("/assets/porter-icon-blue.png"); }
    h1 { margin: 0; font-size: 24px; letter-spacing: 0; }
    h2 { margin: 0; font-size: 17px; letter-spacing: 0; }
    main { padding: 24px 28px 44px; display: grid; gap: 26px; }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .section-head {
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      background: #fbfcfc;
    }
    .section-count {
      color: var(--muted);
      font-size: 12px;
      font-weight: 650;
      text-transform: uppercase;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 10px; text-align: left; vertical-align: top; }
    th { font-size: 11px; color: var(--muted); font-weight: 760; text-transform: uppercase; background: #f7f9f9; }
    th[data-sort] { cursor: pointer; user-select: none; }
    th[data-sort]::after { content: " ↆ"; color: #9aa8a5; font-weight: 700; }
    th[data-dir="asc"]::after { content: " ↑"; color: var(--teal); }
    th[data-dir="desc"]::after { content: " ↓"; color: var(--teal); }
    tr:hover td { background: #f8fbfb; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      color: #102a43;
      background: #edf3f2;
      border: 1px solid #d5e2df;
      border-radius: 5px;
      padding: 1px 5px;
      overflow-wrap: anywhere;
    }
    form.inline { display: inline-flex; gap: 7px; align-items: center; margin: 0; flex-wrap: wrap; }
    form.grid {
      padding: 16px 18px;
      display: grid;
      grid-template-columns: repeat(6, minmax(130px, 1fr)) auto;
      gap: 10px;
      align-items: end;
      border-bottom: 1px solid var(--line);
      background: #f8faf9;
    }
    input, select, button {
      font: inherit;
      min-height: 34px;
      padding: 7px 9px;
      border: 1px solid var(--line-strong);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
    }
    input:focus, select:focus { outline: 2px solid rgba(15, 118, 110, .24); border-color: var(--teal); }
    button {
      cursor: pointer;
      border-color: #0f5f58;
      background: var(--teal);
      color: #fff;
      font-weight: 720;
    }
    button:hover { background: #0b5f59; }
    label { display: grid; gap: 5px; color: var(--muted); font-size: 12px; font-weight: 680; }
    label > input, label > select { color: var(--ink); font-size: 14px; font-weight: 450; }
    .muted { color: var(--muted); }
    .subtle { color: #a7b5b2; }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 760;
      border: 1px solid currentColor;
      background: #fff;
    }
    .status-approved, .status-active { color: var(--green); }
    .status-blocked, .status-revoked { color: var(--red); }
    .status-pending, .status-disabled { color: var(--amber); }
    .kind { display: inline-flex; align-items: center; gap: 6px; font-weight: 760; }
    .kind::before { width: 20px; height: 14px; border-radius: 3px; }
    .kind-tlsgate { color: var(--green); }
    .kind-sshgate { color: var(--blue); }
    .token-set { color: var(--blue); font-weight: 720; }
    details.ip-list { min-width: 150px; }
    details.ip-list summary {
      cursor: pointer;
      color: var(--teal);
      font-weight: 720;
      list-style: none;
    }
    details.ip-list summary::-webkit-details-marker { display: none; }
    details.ip-list summary::after { content: " +"; color: var(--muted); }
    details.ip-list[open] summary::after { content: " -"; }
    .ip-preview { display: grid; gap: 4px; margin-top: 6px; }
    .ip-all { display: grid; gap: 4px; margin-top: 8px; max-height: 220px; overflow: auto; padding-right: 6px; }
    .wrap { overflow-x: auto; }
    @media (max-width: 980px) {
      header { align-items: start; flex-direction: column; }
      .brand { align-items: center; }
      .service-legend { justify-content: flex-start; }
      main { padding: 18px 14px 34px; }
      form.grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <img class="mascot" src="/assets/porter-mascot-concept.png" alt="Porter mascot">
      <div>
        <h1>gatehub</h1>
        <span class="subtle">Porter at the control desk for TLS and SSH gates</span>
      </div>
    </div>
    <div class="header-actions">
      <div class="service-legend">
        <span class="service-chip service-tls">tlsgate</span>
        <span class="service-chip service-ssh">sshgate</span>
      </div>
      {{if .AuthEnabled}}<button type="button" class="logout-btn" id="logout-btn">Sign out</button>{{end}}
    </div>
  </header>
  <main>
    <section>
      <div class="section-head">
        <h2>Nodes</h2>
        <span class="section-count">{{len .Nodes}} registered</span>
      </div>
      <form class="grid" method="post" action="/nodes">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <label>Instance ID<input name="id" placeholder="mail-tls" required></label>
        <label>Kind<select name="kind"><option>tlsgate</option><option>sshgate</option></select></label>
        <label>Host<input name="host" placeholder="mail-gateway" required></label>
        <label>Allowed cert name<input name="allowed_cert_name" placeholder="mail-gateway" required></label>
        <label>Node token<input name="token" type="password" placeholder="leave blank to keep"></label>
        <button type="submit">Save Node</button>
      </form>
      <div class="wrap">
        <table>
          <thead><tr><th data-sort="text">ID</th><th data-sort="text">Kind</th><th data-sort="text">Host</th><th data-sort="text">Cert Name</th><th data-sort="text">Token</th><th data-sort="status">Status</th><th data-sort="text">Last Seen</th><th>Actions</th></tr></thead>
          <tbody>
          {{range .Nodes}}
            <tr>
              <td data-value="{{.ID}}"><code>{{.ID}}</code></td><td data-value="{{.Kind}}"><span class="kind kind-{{.Kind}}">{{.Kind}}</span></td><td data-value="{{.Host}}">{{.Host}}</td><td data-value="{{.AllowedCertName}}"><code>{{.AllowedCertName}}</code></td><td data-value="{{if .TokenHash}}set{{else}}-{{end}}">{{if .TokenHash}}<span class="token-set">set</span>{{else}}<span class="muted">-</span>{{end}}</td>
              <td data-value="{{.Status}}"><span class="badge status-{{.Status}}">{{.Status}}</span></td><td data-value="{{.LastSeen}}">{{.LastSeen}}</td>
              <td>
                <form class="inline" method="post" action="/nodes/status">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="id" value="{{.ID}}">
                  <select name="status"><option>active</option><option>disabled</option><option>revoked</option></select>
                  <button>Set</button>
                </form>
              </td>
            </tr>
          {{else}}
            <tr><td colspan="8" class="muted">No nodes registered.</td></tr>
          {{end}}
          </tbody>
        </table>
      </div>
    </section>
    <section>
      <div class="section-head">
        <h2>Fingerprints</h2>
        <span class="section-count">{{len .Fingerprints}} observed</span>
      </div>
      <div class="wrap">
        <table>
          <thead><tr><th data-sort="text">Node</th><th data-sort="text">Fingerprint</th><th data-sort="status">Status</th><th data-sort="text">Label</th><th data-sort="text">Last Seen</th><th data-sort="number">IPs</th><th data-sort="number">Details</th><th>Decision</th></tr></thead>
          <tbody>
          {{range .Fingerprints}}
            <tr>
              <td data-value="{{.NodeID}}"><code>{{.NodeID}}</code><br><span class="muted">{{.Kind}} {{.Host}}</span></td>
              <td data-value="{{.Fingerprint}}"><code>{{.Fingerprint}}</code></td>
              <td data-value="{{.Status}}"><span class="badge status-{{.Status}}">{{.Status}}</span></td>
              <td data-value="{{.Label}}">{{.Label}}</td>
              <td data-value="{{.LastSeen}}">{{.LastSeen}}</td>
              <td data-value="{{len .IPs}}">
                {{if .IPs}}
                  <details class="ip-list">
                    <summary>{{len .IPs}} IP{{if ne (len .IPs) 1}}s{{end}}</summary>
                    <div class="ip-all">{{range .IPs}}<code>{{.}}</code>{{end}}</div>
                  </details>
                {{else}}
                  <span class="muted">-</span>
                {{end}}
              </td>
              <td data-value="{{.Count}}"><span class="muted">count</span> {{.Count}}</td>
              <td>
                <form class="inline" method="post" action="/decisions">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="scope_type" value="instance">
                  <input type="hidden" name="scope_id" value="{{.NodeID}}">
                  <input type="hidden" name="kind" value="{{.Kind}}">
                  <input type="hidden" name="fingerprint" value="{{.Fingerprint}}">
                  <select name="status">{{range $.Statuses}}<option>{{.}}</option>{{end}}</select>
                  <input name="label" value="{{.Label}}" placeholder="label">
                  <button>Apply</button>
                </form>
              </td>
            </tr>
          {{else}}
            <tr><td colspan="8" class="muted">No fingerprints observed.</td></tr>
          {{end}}
          </tbody>
        </table>
      </div>
    </section>
  </main>
  <script>
    const logoutBtn = document.getElementById("logout-btn");
    const csrfToken = document.querySelector("meta[name='csrf-token']")?.content || "";
    if (logoutBtn) {
      logoutBtn.addEventListener("click", async () => {
        logoutBtn.disabled = true;
        try { await fetch("/api/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrfToken } }); } catch (e) {}
        window.location.href = "/login";
      });
    }
    const statusRank = { approved: 0, active: 0, blocked: 1, pending: 2, disabled: 2, revoked: 3 };
    function cellValue(row, index, type) {
      const cell = row.children[index];
      const raw = cell?.dataset.value ?? cell?.textContent ?? "";
      if (type === "number") return Number(raw) || 0;
      if (type === "status") return statusRank[raw.trim().toLowerCase()] ?? 99;
      return raw.trim().toLowerCase();
    }
    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const table = th.closest("table");
        const tbody = table.querySelector("tbody");
        const index = Array.from(th.parentElement.children).indexOf(th);
        const type = th.dataset.sort;
        const nextDir = th.dataset.dir === "asc" ? "desc" : "asc";
        table.querySelectorAll("th[data-dir]").forEach((other) => {
          if (other !== th) other.removeAttribute("data-dir");
        });
        th.dataset.dir = nextDir;
        const rows = Array.from(tbody.querySelectorAll("tr")).filter((row) => row.children.length > 1);
        rows.sort((a, b) => {
          const av = cellValue(a, index, type);
          const bv = cellValue(b, index, type);
          if (av < bv) return nextDir === "asc" ? -1 : 1;
          if (av > bv) return nextDir === "asc" ? 1 : -1;
          return 0;
        });
        rows.forEach((row) => tbody.appendChild(row));
      });
    });
  </script>
</body>
</html>`))
