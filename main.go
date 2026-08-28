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

	maxObservationsPerBatch  = 1000
	maxSignalsPerBatch       = 1000
	maxFingerprintLength     = 256
	maxObservationIPs        = 128
	maxObservationPorts      = 128
	maxObservationMetaKeys   = 32
	maxObservationMetaBytes  = 8192
	maxNodeTokenLength       = 4096
	minNodeTokenLength       = 32
	defaultSightingRetention = 8 * 24 * time.Hour
	sightingPruneInterval    = time.Hour
)

type config struct {
	DBPath                   string
	AdminListen              string
	PublicListen             string
	PublicCert               string
	PublicKey                string
	ClientCA                 string
	ClientCRL                string
	PublicAuth               string
	AdminAuth                string
	AdminOIDCIssuer          string
	AdminOIDCClientID        string
	AdminOIDCClientSecret    string
	AdminOIDCRedirectURL     string
	AdminOIDCScopes          string
	AdminOIDCAllowedSubjects string
	AdminOIDCAllowedEmails   string
	AdminOIDCAllowedGroups   string
	AdminSessionMaxAge       int
	SightingRetention        time.Duration
}

type app struct {
	store *Store
	auth  *AuthService
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "register-node" {
		if err := registerNode(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
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
	if _, err := store.PruneSightingsBefore(time.Now().Add(-cfg.SightingRetention)); err != nil {
		log.Fatalf("prune fingerprint sightings: %v", err)
	}
	if _, err := store.PruneAbuseSignalsBefore(time.Now().Add(-cfg.SightingRetention)); err != nil {
		log.Fatalf("prune web abuse signals: %v", err)
	}
	go startSightingPruner(store, cfg.SightingRetention)
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

func registerNode(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("register-node", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dbPath, id, kind, host, allowedCertName, tokenFile string
	fs.StringVar(&dbPath, "db", "gatehub.sqlite", "SQLite database path")
	fs.StringVar(&id, "id", "", "node ID")
	fs.StringVar(&kind, "kind", "", "node kind")
	fs.StringVar(&host, "host", "", "node host")
	fs.StringVar(&allowedCertName, "allowed-cert-name", "", "allowed client certificate name")
	fs.StringVar(&tokenFile, "token-file", "", "token file, or - for standard input")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("register-node does not accept positional arguments")
	}
	if tokenFile == "" {
		return errors.New("--token-file is required (use - for standard input)")
	}
	var tokenBytes []byte
	var err error
	if tokenFile == "-" {
		tokenBytes, err = io.ReadAll(io.LimitReader(stdin, maxNodeTokenLength+2))
	} else {
		tokenBytes, err = os.ReadFile(tokenFile)
	}
	if err != nil {
		return fmt.Errorf("read node token: %w", err)
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(tokenBytes), "\n"), "\r")
	if err := validateNodeToken(token); err != nil {
		return err
	}
	store, err := NewStore(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()
	node := Node{
		ID:              strings.TrimSpace(id),
		Kind:            strings.TrimSpace(kind),
		Host:            strings.TrimSpace(host),
		AllowedCertName: strings.TrimSpace(allowedCertName),
		TokenHash:       hashToken(token),
		Status:          statusActive,
	}
	if err := store.UpsertNode(node); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "registered node %s\n", node.ID)
	return err
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
	flag.StringVar(&cfg.AdminAuth, "admin-auth", authModeOIDC, "admin auth mode: oidc or none (none is for localhost dev only)")
	flag.StringVar(&cfg.AdminOIDCIssuer, "admin-oidc-issuer", "", "OIDC issuer URL (e.g. https://pocket-id.example.com)")
	flag.StringVar(&cfg.AdminOIDCClientID, "admin-oidc-client-id", "", "OIDC client ID")
	flag.StringVar(&cfg.AdminOIDCClientSecret, "admin-oidc-client-secret", "", "OIDC client secret (or set GATEHUB_ADMIN_OIDC_CLIENT_SECRET to keep it out of argv)")
	flag.StringVar(&cfg.AdminOIDCRedirectURL, "admin-oidc-redirect-url", "", "OIDC redirect URL (e.g. https://gatehub.example.com/api/auth/callback)")
	flag.StringVar(&cfg.AdminOIDCScopes, "admin-oidc-scopes", "openid,profile,email", "comma-separated OIDC scopes")
	flag.StringVar(&cfg.AdminOIDCAllowedSubjects, "admin-oidc-allowed-subjects", "", "comma-separated allowlist of subject (sub) claims; empty allows any authenticated identity")
	flag.StringVar(&cfg.AdminOIDCAllowedEmails, "admin-oidc-allowed-emails", "", "comma-separated allowlist of email claims")
	flag.StringVar(&cfg.AdminOIDCAllowedGroups, "admin-oidc-allowed-groups", "", "comma-separated allowlist of group claims")
	flag.IntVar(&cfg.AdminSessionMaxAge, "admin-session-max-age", 28800, "admin session lifetime in seconds; 0 means no expiry")
	flag.DurationVar(&cfg.SightingRetention, "sighting-retention", defaultSightingRetention, "how long to retain per-IP fingerprint sightings")
	flag.Parse()
	if cfg.SightingRetention <= 0 {
		log.Fatalf("--sighting-retention must be positive")
	}
	if cfg.AdminOIDCClientSecret == "" {
		cfg.AdminOIDCClientSecret = os.Getenv("GATEHUB_ADMIN_OIDC_CLIENT_SECRET")
	}
	switch cfg.PublicAuth {
	case "mtls", "token", "both":
	default:
		log.Fatalf("invalid --public-auth %q (want mtls, token, or both)", cfg.PublicAuth)
	}
	// Treat an empty value (e.g. an unset environment variable in the systemd
	// unit) as the secure default rather than an error, so a stale env file
	// fails closed with an actionable message instead of "invalid mode".
	if cfg.AdminAuth == "" {
		cfg.AdminAuth = authModeOIDC
	}
	switch cfg.AdminAuth {
	case authModeOIDC:
		if cfg.AdminListen != "" && (cfg.AdminOIDCIssuer == "" || cfg.AdminOIDCClientID == "" || cfg.AdminOIDCRedirectURL == "") {
			log.Fatalf("admin auth mode %q requires --admin-oidc-issuer, --admin-oidc-client-id and --admin-oidc-redirect-url (use --admin-auth none only for localhost dev)", cfg.AdminAuth)
		}
	case authModeNone:
	default:
		log.Fatalf("invalid --admin-auth %q (want oidc or none)", cfg.AdminAuth)
	}
	return cfg
}

func startSightingPruner(store *Store, retention time.Duration) {
	ticker := time.NewTicker(sightingPruneInterval)
	defer ticker.Stop()
	for range ticker.C {
		deleted, err := store.PruneSightingsBefore(time.Now().Add(-retention))
		if err != nil {
			log.Printf("prune fingerprint sightings: %v", err)
		} else if deleted > 0 {
			log.Printf("pruned %d expired fingerprint sighting(s)", deleted)
		}
		if deleted, err := store.PruneAbuseSignalsBefore(time.Now().Add(-retention)); err != nil {
			log.Printf("prune web abuse signals: %v", err)
		} else if deleted > 0 {
			log.Printf("pruned %d expired web abuse signal(s)", deleted)
		}
	}
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
	Sightings   []Sighting     `json:"sightings,omitempty"`
	Count       int            `json:"count,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	UpdatedAt   string         `json:"updated_at"`
}

type Sighting struct {
	IP       string `json:"ip"`
	Port     int    `json:"port,omitempty"`
	LastSeen string `json:"last_seen"`
}

// AbuseSignal is deliberately aggregate-only. Raw request targets are not
// accepted because access-log paths can contain credentials and identifiers.
type AbuseSignal struct {
	EventID       string `json:"event_id"`
	ObservedAt    string `json:"observed_at"`
	Host          string `json:"host"`
	Site          string `json:"site"`
	IP            string `json:"ip"`
	Trigger       string `json:"trigger"`
	Connections   int    `json:"connections"`
	Errors        int    `json:"errors"`
	Successes     int    `json:"successes"`
	WindowSeconds int    `json:"window_seconds"`
}

type WebCandidate struct {
	NodeID      string   `json:"node_id"`
	Host        string   `json:"host"`
	Fingerprint string   `json:"fingerprint"`
	Status      string   `json:"status"`
	Label       string   `json:"label,omitempty"`
	Networks    []string `json:"networks"`
	Sites       []string `json:"sites"`
	Signals     int      `json:"signals"`
	Connections int      `json:"connections"`
	Errors      int      `json:"errors"`
	Successes   int      `json:"successes"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
}

type WebSignalActivity struct {
	NodeID      string `json:"node_id"`
	Host        string `json:"host"`
	Site        string `json:"site"`
	Network     string `json:"network"`
	Trigger     string `json:"trigger"`
	Signals     int    `json:"signals"`
	Connections int    `json:"connections"`
	Errors      int    `json:"errors"`
	Successes   int    `json:"successes"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

type FingerprintGroup struct {
	Fingerprint string
	Status      string
	Label       string
	LabelsVary  bool
	LastSeen    string
	IPs         []string
	Count       int
	HostNames   []string
	MoreHosts   int
	Instances   []Fingerprint
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
		`CREATE TABLE IF NOT EXISTS fingerprint_sightings (
			node_id TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 0,
			last_seen TEXT NOT NULL,
			PRIMARY KEY (node_id, fingerprint, ip, port),
			FOREIGN KEY (node_id, fingerprint) REFERENCES fingerprints(node_id, fingerprint) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS web_abuse_signals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			event_id TEXT NOT NULL,
			observed_at TEXT NOT NULL,
			received_at TEXT NOT NULL,
			host TEXT NOT NULL,
			site TEXT NOT NULL,
			ip TEXT NOT NULL,
			trigger TEXT NOT NULL,
			connections INTEGER NOT NULL,
			errors INTEGER NOT NULL,
			successes INTEGER NOT NULL,
			window_seconds INTEGER NOT NULL,
			UNIQUE (node_id, event_id)
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
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_sightings_ip_seen ON fingerprint_sightings(ip, last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_web_abuse_signals_ip_seen ON web_abuse_signals(ip, observed_at)`,
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
		for _, sighting := range fp.Sightings {
			if _, err := tx.Exec(`
				INSERT INTO fingerprint_sightings (node_id, fingerprint, ip, port, last_seen)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(node_id, fingerprint, ip, port) DO UPDATE SET last_seen = excluded.last_seen`,
				node.ID, fp.Fingerprint, sighting.IP, sighting.Port, sighting.LastSeen); err != nil {
				return err
			}
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

// PruneSightingsBefore bounds correlation data without removing the aggregate
// fingerprint records or their manual decisions.
func (s *Store) PruneSightingsBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM fingerprint_sightings WHERE julianday(last_seen) < julianday(?)`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) UpsertAbuseSignals(node Node, signals []AbuseSignal) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	receivedAt := nowString()
	for _, signal := range signals {
		if err := validateAbuseSignal(signal); err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO web_abuse_signals (
				node_id, event_id, observed_at, received_at, host, site, ip, trigger,
				connections, errors, successes, window_seconds
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(node_id, event_id) DO NOTHING`,
			node.ID, signal.EventID, signal.ObservedAt, receivedAt, signal.Host,
			signal.Site, signal.IP, signal.Trigger, signal.Connections, signal.Errors,
			signal.Successes, signal.WindowSeconds); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PruneAbuseSignalsBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM web_abuse_signals WHERE julianday(observed_at) < julianday(?)`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// WebCandidates correlates signals only with TLS sightings on the same host
// and within window. It is report-only and never creates a policy decision.
func (s *Store) WebCandidates(since time.Time, window time.Duration) ([]WebCandidate, error) {
	rows, err := s.db.Query(`
		SELECT f.node_id, f.host, f.fingerprint, f.status, f.label,
			sig.event_id, sig.site, sig.ip, sig.observed_at,
			sig.connections, sig.errors, sig.successes
		FROM web_abuse_signals sig
		JOIN fingerprint_sightings sight ON sight.ip = sig.ip
		JOIN fingerprints f ON f.node_id = sight.node_id AND f.fingerprint = sight.fingerprint
		WHERE f.kind = 'tlsgate'
		  AND f.host = sig.host
		  AND julianday(sig.observed_at) >= julianday(?)
		  AND ABS((julianday(sig.observed_at) - julianday(sight.last_seen)) * 86400.0) <= ?
		ORDER BY sig.observed_at, sig.event_id`, since.UTC().Format(time.RFC3339Nano), window.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type aggregate struct {
		candidate WebCandidate
		events    map[string]struct{}
		networks  map[string]struct{}
		sites     map[string]struct{}
	}
	aggregates := make(map[string]*aggregate)
	for rows.Next() {
		var nodeID, host, fp, status, label, eventID, site, ip, observedAt string
		var connections, errors, successes int
		if err := rows.Scan(&nodeID, &host, &fp, &status, &label, &eventID, &site, &ip, &observedAt, &connections, &errors, &successes); err != nil {
			return nil, err
		}
		key := nodeID + "\x00" + fp
		agg := aggregates[key]
		if agg == nil {
			agg = &aggregate{
				candidate: WebCandidate{NodeID: nodeID, Host: host, Fingerprint: fp, Status: status, Label: label},
				events:    make(map[string]struct{}), networks: make(map[string]struct{}), sites: make(map[string]struct{}),
			}
			aggregates[key] = agg
		}
		if _, duplicate := agg.events[eventID]; duplicate {
			continue
		}
		agg.events[eventID] = struct{}{}
		agg.networks[sourceNetwork(ip)] = struct{}{}
		agg.sites[site] = struct{}{}
		agg.candidate.Signals++
		agg.candidate.Connections += connections
		agg.candidate.Errors += errors
		agg.candidate.Successes += successes
		if agg.candidate.FirstSeen == "" || observedAt < agg.candidate.FirstSeen {
			agg.candidate.FirstSeen = observedAt
		}
		if observedAt > agg.candidate.LastSeen {
			agg.candidate.LastSeen = observedAt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	candidates := make([]WebCandidate, 0, len(aggregates))
	for _, agg := range aggregates {
		for network := range agg.networks {
			agg.candidate.Networks = append(agg.candidate.Networks, network)
		}
		for site := range agg.sites {
			agg.candidate.Sites = append(agg.candidate.Sites, site)
		}
		sort.Strings(agg.candidate.Networks)
		sort.Strings(agg.candidate.Sites)
		candidates = append(candidates, agg.candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i].Networks) != len(candidates[j].Networks) {
			return len(candidates[i].Networks) > len(candidates[j].Networks)
		}
		return candidates[i].LastSeen > candidates[j].LastSeen
	})
	return candidates, nil
}

func sourceNetwork(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(addr, bits).Masked().String()
}

// WebSignalActivity reports accepted aggregate HTTP abuse signals without
// implying that they are safe enforcement candidates. IPs are reduced to
// source networks to match the privacy-limited candidate view.
func (s *Store) WebSignalActivity(since time.Time) ([]WebSignalActivity, error) {
	rows, err := s.db.Query(`
		SELECT node_id, host, site, ip, trigger, COUNT(*),
			SUM(connections), SUM(errors), SUM(successes),
			MIN(observed_at), MAX(observed_at)
		FROM web_abuse_signals
		WHERE julianday(observed_at) >= julianday(?)
		GROUP BY node_id, host, site, ip, trigger
		ORDER BY MAX(observed_at) DESC`, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var activity []WebSignalActivity
	for rows.Next() {
		var item WebSignalActivity
		var ip string
		if err := rows.Scan(&item.NodeID, &item.Host, &item.Site, &ip, &item.Trigger,
			&item.Signals, &item.Connections, &item.Errors, &item.Successes,
			&item.FirstSeen, &item.LastSeen); err != nil {
			return nil, err
		}
		item.Network = sourceNetwork(ip)
		activity = append(activity, item)
	}
	return activity, rows.Err()
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
	switch d.ScopeType {
	case "instance":
		if _, err := tx.Exec(`
			UPDATE fingerprints
			SET status = ?, label = CASE WHEN ? != '' THEN ? ELSE label END, updated_at = ?
			WHERE node_id = ? AND fingerprint = ?`,
			d.Status, d.Label, d.Label, now, d.ScopeID, d.Fingerprint); err != nil {
			return err
		}
	case "kind":
		if _, err := tx.Exec(`
			UPDATE fingerprints
			SET status = ?, label = CASE WHEN ? != '' THEN ? ELSE label END, updated_at = ?
			WHERE kind = ? AND fingerprint = ?`,
			d.Status, d.Label, d.Label, now, d.ScopeID, d.Fingerprint); err != nil {
			return err
		}
	case "global":
		if _, err := tx.Exec(`
			UPDATE fingerprints
			SET status = ?, label = CASE WHEN ? != '' THEN ? ELSE label END, updated_at = ?
			WHERE fingerprint = ?`,
			d.Status, d.Label, d.Label, now, d.Fingerprint); err != nil {
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
	mux.HandleFunc("POST /v1/signals/batch", a.handleSignalBatch)
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
	mux.HandleFunc("GET /api/auth/login/start", a.auth.loginStart)
	mux.HandleFunc("GET /api/auth/callback", a.auth.callback)
	mux.HandleFunc("POST /api/auth/logout", a.auth.logout)

	// Gated admin surface.
	mux.HandleFunc("GET /", a.auth.require(a.handleAdminHome))
	mux.HandleFunc("POST /nodes", a.auth.require(a.handleAdminUpsertNode))
	mux.HandleFunc("POST /nodes/status", a.auth.require(a.handleAdminNodeStatus))
	mux.HandleFunc("POST /decisions", a.auth.require(a.handleAdminDecision))
	mux.HandleFunc("GET /api/fingerprints", a.auth.require(a.handleAdminFingerprintsAPI))
	mux.HandleFunc("GET /api/web-candidates", a.auth.require(a.handleAdminWebCandidatesAPI))
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

type signalBatchRequest struct {
	InstanceID string        `json:"instance_id"`
	Signals    []AbuseSignal `json:"signals"`
}

func (a *app) handleSignalBatch(w http.ResponseWriter, r *http.Request) {
	node, ok := a.authorizeNode(w, r, r.URL.Query().Get("instance_id"))
	if !ok {
		return
	}
	if node.Kind != "log_watcher" {
		writeError(w, http.StatusForbidden, errors.New("node is not a web signal source"))
		return
	}
	var req signalBatchRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.InstanceID != "" && req.InstanceID != node.ID {
		writeError(w, http.StatusForbidden, errors.New("request instance_id does not match authorized node"))
		return
	}
	if len(req.Signals) > maxSignalsPerBatch {
		writeError(w, http.StatusBadRequest, fmt.Errorf("too many signals: %d > %d", len(req.Signals), maxSignalsPerBatch))
		return
	}
	if err := a.store.UpsertAbuseSignals(node, req.Signals); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(req.Signals)})
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
	fingerprintGroups := groupFingerprints(fps)
	candidates, err := a.store.WebCandidates(time.Now().Add(-24*time.Hour), 5*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	activity, err := a.store.WebSignalActivity(time.Now().Add(-24 * time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	data := struct {
		Nodes             []Node
		FingerprintGroups []FingerprintGroup
		WebCandidates     []WebCandidate
		WebActivity       []WebSignalActivity
		ObservationCount  int
		Statuses          []string
		AuthEnabled       bool
		CSRFToken         string
	}{nodes, fingerprintGroups, candidates, activity, len(fps), []string{decisionApproved, decisionBlocked, decisionPending}, a.auth.enabled(), a.auth.csrfToken(r)}
	if err := adminTemplate.Execute(w, data); err != nil {
		log.Printf("render admin: %v", err)
	}
}

func groupFingerprints(fps []Fingerprint) []FingerprintGroup {
	groupsByFingerprint := make(map[string]*FingerprintGroup)
	var groups []*FingerprintGroup
	for _, fp := range fps {
		group := groupsByFingerprint[fp.Fingerprint]
		if group == nil {
			group = &FingerprintGroup{
				Fingerprint: fp.Fingerprint,
				Status:      fp.Status,
				Label:       fp.Label,
			}
			groupsByFingerprint[fp.Fingerprint] = group
			groups = append(groups, group)
		}
		group.Instances = append(group.Instances, fp)
		group.Count += fp.Count
		if fp.LastSeen > group.LastSeen {
			group.LastSeen = fp.LastSeen
		}
		if groupedFingerprintStatusRank(fp.Status) < groupedFingerprintStatusRank(group.Status) {
			group.Status = fp.Status
		}
		if len(group.Instances) > 1 && group.Label != fp.Label {
			group.LabelsVary = true
			group.Label = ""
		}
	}

	result := make([]FingerprintGroup, 0, len(groups))
	for _, group := range groups {
		hostSet := make(map[string]struct{})
		ipSet := make(map[string]struct{})
		for _, fp := range group.Instances {
			hostSet[fp.Host] = struct{}{}
			for _, ip := range fp.IPs {
				ipSet[ip] = struct{}{}
			}
		}
		for host := range hostSet {
			group.HostNames = append(group.HostNames, host)
		}
		for ip := range ipSet {
			group.IPs = append(group.IPs, ip)
		}
		sort.Strings(group.HostNames)
		sort.Strings(group.IPs)
		if len(group.HostNames) > 3 {
			group.MoreHosts = len(group.HostNames) - 3
		}
		sort.SliceStable(group.Instances, func(i, j int) bool {
			if group.Instances[i].Host != group.Instances[j].Host {
				return group.Instances[i].Host < group.Instances[j].Host
			}
			return group.Instances[i].NodeID < group.Instances[j].NodeID
		})
		result = append(result, *group)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if groupedFingerprintStatusRank(result[i].Status) != groupedFingerprintStatusRank(result[j].Status) {
			return groupedFingerprintStatusRank(result[i].Status) < groupedFingerprintStatusRank(result[j].Status)
		}
		return result[i].LastSeen > result[j].LastSeen
	})
	return result
}

func groupedFingerprintStatusRank(status string) int {
	switch status {
	case decisionBlocked:
		return 0
	case decisionPending:
		return 1
	case decisionApproved:
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
	scopeType := firstNonEmpty(r.FormValue("scope_type"), "instance")
	scopeID := r.FormValue("scope_id")
	if scopeType == "global" {
		scopeID = ""
	}
	d := Decision{
		ScopeType:   scopeType,
		ScopeID:     scopeID,
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

func (a *app) handleAdminWebCandidatesAPI(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	if raw := r.URL.Query().Get("window"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > 30*time.Minute {
			writeError(w, http.StatusBadRequest, errors.New("window must be between 1ns and 30m"))
			return
		}
		window = parsed
	}
	since := time.Now().Add(-24 * time.Hour)
	if raw := r.URL.Query().Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || parsed.Before(time.Now().Add(-defaultSightingRetention)) {
			writeError(w, http.StatusBadRequest, errors.New("since must be an RFC3339 timestamp within the retention window"))
			return
		}
		since = parsed
	}
	candidates, err := a.store.WebCandidates(since, window)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": "report_only", "candidates": candidates})
}

func validateNode(n Node) error {
	if n.ID == "" || n.Kind == "" || n.Host == "" || n.AllowedCertName == "" {
		return errors.New("id, kind, host, and allowed_cert_name are required")
	}
	if n.Kind != "tlsgate" && n.Kind != "sshgate" && n.Kind != "log_watcher" {
		return fmt.Errorf("invalid kind %q", n.Kind)
	}
	if n.Status != "" && !validNodeStatus(n.Status) {
		return fmt.Errorf("invalid node status %q", n.Status)
	}
	return nil
}

func validateAbuseSignal(signal AbuseSignal) error {
	if signal.EventID == "" || len(signal.EventID) > 128 || strings.ContainsAny(signal.EventID, " \t\r\n") {
		return errors.New("event_id is required and must be a compact value of at most 128 bytes")
	}
	if _, err := time.Parse(time.RFC3339Nano, signal.ObservedAt); err != nil {
		return fmt.Errorf("invalid observed_at: %w", err)
	}
	if len(signal.Host) == 0 || len(signal.Host) > 256 || len(signal.Site) == 0 || len(signal.Site) > 256 {
		return errors.New("host and site are required and must be at most 256 bytes")
	}
	if _, err := netip.ParseAddr(signal.IP); err != nil {
		return fmt.Errorf("invalid signal IP %q", signal.IP)
	}
	if signal.Trigger == "" || len(signal.Trigger) > 64 || strings.ContainsAny(signal.Trigger, " \t\r\n/?:&=") {
		return errors.New("trigger is required and must be a compact rule identifier")
	}
	if signal.Connections <= 0 || signal.Connections > 1_000_000_000 || signal.Errors < 0 || signal.Successes < 0 || signal.Errors+signal.Successes > signal.Connections {
		return errors.New("invalid signal counters")
	}
	if signal.WindowSeconds <= 0 || signal.WindowSeconds > 86400 {
		return errors.New("window_seconds must be between 1 and 86400")
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
	if len(fp.Sightings) > maxObservationIPs {
		return fmt.Errorf("too many sightings for %s: %d > %d", fp.Fingerprint, len(fp.Sightings), maxObservationIPs)
	}
	for _, sighting := range fp.Sightings {
		if _, err := netip.ParseAddr(sighting.IP); err != nil {
			return fmt.Errorf("invalid sighting IP %q for %s", sighting.IP, fp.Fingerprint)
		}
		if sighting.Port < 0 || sighting.Port > 65535 {
			return fmt.Errorf("invalid sighting port %d for %s", sighting.Port, fp.Fingerprint)
		}
		if len(sighting.LastSeen) > 64 {
			return errors.New("sighting timestamp is too long")
		}
		if _, err := time.Parse(time.RFC3339Nano, sighting.LastSeen); err != nil {
			return fmt.Errorf("invalid sighting timestamp for %s: %w", fp.Fingerprint, err)
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
    h1 { margin: 0; font-size: 22px; letter-spacing: 0; }
    h2 { margin: 0; font-size: 17px; letter-spacing: 0; }
    main { padding: 18px 22px 36px; display: grid; gap: 16px; }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .section-head {
      padding: 12px 14px;
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
    .section-tools { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .dashboard-tools {
      position: sticky;
      top: 0;
      z-index: 20;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin: -18px -22px 0;
      padding: 8px 22px;
      background: rgba(245, 247, 248, .96);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(8px);
    }
    .section-nav { display: flex; gap: 6px; flex-wrap: wrap; }
    .section-nav a {
      padding: 4px 9px;
      border-radius: 999px;
      color: #344541;
      background: #fff;
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 680;
      text-decoration: none;
    }
    .section-nav a:hover { color: var(--teal); border-color: var(--teal); }
    .density-toggle, .collapse-toggle {
      min-height: 28px;
      padding: 4px 9px;
      border-color: var(--line-strong);
      background: #fff;
      color: var(--teal);
      font-size: 12px;
      white-space: nowrap;
    }
    .density-toggle:hover, .collapse-toggle:hover { background: #edf7f5; }
    section.is-collapsed > :not(.section-head) { display: none; }
    section.is-collapsed .section-head { border-bottom: 0; }
    .link-btn {
      display: inline-flex;
      align-items: center;
      min-height: 30px;
      padding: 5px 10px;
      border: 1px solid var(--line-strong);
      border-radius: 6px;
      color: var(--teal);
      background: #fff;
      font-size: 12px;
      font-weight: 720;
      text-decoration: none;
    }
    .link-btn:hover { background: #edf7f5; }
    table { width: 100%; border-collapse: separate; border-spacing: 0; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 10px; text-align: left; vertical-align: top; }
    th { position: sticky; top: 45px; z-index: 5; font-size: 11px; color: var(--muted); font-weight: 760; text-transform: uppercase; background: #f7f9f9; box-shadow: inset 0 -1px var(--line); }
    th[data-sort] { cursor: pointer; user-select: none; }
    th[data-sort]::after { content: " ↆ"; color: #9aa8a5; font-weight: 700; }
    th[data-dir="asc"]::after { content: " ↑"; color: var(--teal); }
    th[data-dir="desc"]::after { content: " ↓"; color: var(--teal); }
    tr:hover td { background: #f8fbfb; }
    tbody tr:nth-child(even) td { background: #fcfdfd; }
    tbody tr:nth-child(even):hover td { background: #f8fbfb; }
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
    details.host-list { min-width: 210px; }
    details.host-list > summary {
      cursor: pointer;
      list-style: none;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 5px;
    }
    details.host-list > summary::-webkit-details-marker { display: none; }
    .host-chip {
      display: inline-flex;
      padding: 2px 7px;
      border-radius: 999px;
      color: #344541;
      background: #edf3f2;
      border: 1px solid #d5e2df;
      font-size: 12px;
      font-weight: 680;
    }
    .host-more { color: var(--teal); font-size: 12px; font-weight: 760; }
    .host-instances {
      display: grid;
      gap: 9px;
      margin-top: 10px;
      min-width: 420px;
    }
    .host-instance {
      padding: 9px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #f8faf9;
    }
    .host-instance-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 7px;
    }
    .wrap { overflow-x: auto; }
    .list { display: flex; flex-wrap: wrap; gap: 4px; }
    body.compact main { gap: 10px; }
    body.compact .section-head { padding: 8px 11px; }
    body.compact th, body.compact td { padding: 6px 8px; }
    body.compact input, body.compact select, body.compact button { min-height: 28px; padding: 4px 7px; }
    body.compact form.grid { padding: 9px 11px; gap: 7px; }
    body.compact .badge { min-height: 20px; padding: 1px 6px; }
    body.compact .host-chip { padding: 1px 5px; }
    body.compact code { font-size: 11px; }
    @media (max-width: 980px) {
      header { align-items: start; flex-direction: column; }
      .brand { align-items: center; }
      .service-legend { justify-content: flex-start; }
      main { padding: 14px 10px 28px; }
      .dashboard-tools { position: static; margin: -14px -10px 0; padding: 8px 10px; align-items: flex-start; }
      th { top: 0; }
      form.grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <img class="mascot" src="/assets/porter-mascot-app.png" alt="Porter mascot">
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
    <nav class="dashboard-tools" aria-label="Dashboard controls">
      <div class="section-nav">
        <a href="#nodes">Nodes <strong>{{len .Nodes}}</strong></a>
        <a href="#web-activity">Activity <strong>{{len .WebActivity}}</strong></a>
        <a href="#web-findings">Findings <strong>{{len .WebCandidates}}</strong></a>
        <a href="#fingerprints">Fingerprints <strong>{{len .FingerprintGroups}}</strong></a>
      </div>
      <button class="density-toggle" id="density-toggle" type="button" aria-pressed="true">Comfortable view</button>
    </nav>
    <section id="nodes" data-collapsible>
      <div class="section-head">
        <h2>Nodes</h2>
        <span class="section-count">{{len .Nodes}} registered</span>
      </div>
      <form class="grid" method="post" action="/nodes">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <label>Instance ID<input name="id" placeholder="mail-tls" required></label>
        <label>Kind<select name="kind"><option>tlsgate</option><option>sshgate</option><option>log_watcher</option></select></label>
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
    <section id="web-activity" data-collapsible>
      <div class="section-head">
        <div>
          <h2>Web scanner activity</h2>
          <span class="muted">Aggregate HTTP abuse signals received from log_watcher; informational and not correlated for enforcement</span>
        </div>
        <div class="section-tools">
          <span class="section-count">{{len .WebActivity}} sources · last 24 hours · report only</span>
          <a class="link-btn" href="/#web-activity">Refresh</a>
        </div>
      </div>
      <div class="wrap">
        <table>
          <thead><tr><th data-sort="text">Last seen</th><th data-sort="text">Host</th><th data-sort="text">Site</th><th data-sort="text">Network</th><th data-sort="text">Trigger</th><th data-sort="number">Signals</th><th data-sort="number">Requests</th><th data-sort="number">Errors</th><th data-sort="text">First seen</th></tr></thead>
          <tbody>
          {{range .WebActivity}}
            <tr>
              <td data-value="{{.LastSeen}}">{{.LastSeen}}</td>
              <td data-value="{{.Host}}"><strong>{{.Host}}</strong><div><code>{{.NodeID}}</code></div></td>
              <td data-value="{{.Site}}"><span class="host-chip">{{.Site}}</span></td>
              <td data-value="{{.Network}}"><code>{{.Network}}</code></td>
              <td data-value="{{.Trigger}}">{{.Trigger}}</td>
              <td data-value="{{.Signals}}">{{.Signals}}</td>
              <td data-value="{{.Connections}}">{{.Connections}}</td>
              <td data-value="{{.Errors}}">{{.Errors}}</td>
              <td data-value="{{.FirstSeen}}">{{.FirstSeen}}</td>
            </tr>
          {{else}}
            <tr><td colspan="9" class="muted">No web abuse signals received in the last 24 hours.</td></tr>
          {{end}}
          </tbody>
        </table>
      </div>
    </section>
    <section id="web-findings" data-collapsible>
      <div class="section-head">
        <div>
          <h2>Web scanner findings</h2>
          <span class="muted">HTTP abuse signals correlated with a TLS fingerprint on the same host within five minutes</span>
        </div>
        <div class="section-tools">
          <span class="section-count">{{len .WebCandidates}} candidates · last 24 hours · report only</span>
          <a class="link-btn" href="/#web-findings">Refresh</a>
        </div>
      </div>
      <div class="wrap">
        <table>
          <thead><tr><th data-sort="text">Last seen</th><th data-sort="text">TLS fingerprint</th><th data-sort="text">Gate</th><th data-sort="status">Status</th><th data-sort="text">Sites</th><th data-sort="number">Networks</th><th data-sort="number">Signals</th><th data-sort="number">Requests</th><th data-sort="number">Errors</th><th data-sort="text">First seen</th></tr></thead>
          <tbody>
          {{range .WebCandidates}}
            <tr>
              <td data-value="{{.LastSeen}}">{{.LastSeen}}</td>
              <td data-value="{{.Fingerprint}}"><code>{{.Fingerprint}}</code>{{if .Label}}<div class="muted">{{.Label}}</div>{{end}}</td>
              <td data-value="{{.Host}}"><strong>{{.Host}}</strong><div><code>{{.NodeID}}</code></div></td>
              <td data-value="{{.Status}}"><span class="badge status-{{.Status}}">{{.Status}}</span></td>
              <td data-value="{{range .Sites}}{{.}} {{end}}"><div class="list">{{range .Sites}}<span class="host-chip">{{.}}</span>{{end}}</div></td>
              <td data-value="{{len .Networks}}"><div class="list">{{range .Networks}}<code>{{.}}</code>{{end}}</div></td>
              <td data-value="{{.Signals}}">{{.Signals}}</td>
              <td data-value="{{.Connections}}">{{.Connections}}</td>
              <td data-value="{{.Errors}}">{{.Errors}}</td>
              <td data-value="{{.FirstSeen}}">{{.FirstSeen}}</td>
            </tr>
          {{else}}
            <tr><td colspan="10" class="muted">No correlated web scanner findings in the last 24 hours. Raw abuse signals without a nearby TLS fingerprint are intentionally not shown as candidates.</td></tr>
          {{end}}
          </tbody>
        </table>
      </div>
    </section>
    <section id="fingerprints" data-collapsible>
      <div class="section-head">
        <h2>Fingerprints</h2>
        <span class="section-count">{{len .FingerprintGroups}} signatures across {{.ObservationCount}} observations</span>
      </div>
      <div class="wrap">
        <table>
          <thead><tr><th data-sort="text">Fingerprint</th><th data-sort="number">Hosts</th><th data-sort="status">Status</th><th data-sort="text">Label</th><th data-sort="text">Last Seen</th><th data-sort="number">IPs</th><th data-sort="number">Count</th><th>Decision</th></tr></thead>
          <tbody>
          {{range .FingerprintGroups}}
            <tr>
              <td data-value="{{.Fingerprint}}"><code>{{.Fingerprint}}</code></td>
              <td data-value="{{len .HostNames}}">
                <details class="host-list">
                  <summary>
                    {{range $i, $host := .HostNames}}{{if lt $i 3}}<span class="host-chip">{{$host}}</span>{{end}}{{end}}
                    {{if .MoreHosts}}<span class="host-more">+{{.MoreHosts}} more</span>{{end}}
                  </summary>
                  <div class="host-instances">
                    {{range .Instances}}
                      <div class="host-instance">
                        <div class="host-instance-head">
                          <span><strong>{{.Host}}</strong> <code>{{.NodeID}}</code> <span class="kind kind-{{.Kind}}">{{.Kind}}</span></span>
                          <span class="badge status-{{.Status}}">{{.Status}}</span>
                        </div>
                        <form class="inline" method="post" action="/decisions">
                          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                          <input type="hidden" name="scope_id" value="{{.NodeID}}">
                          <input type="hidden" name="kind" value="{{.Kind}}">
                          <input type="hidden" name="fingerprint" value="{{.Fingerprint}}">
                          <input type="hidden" name="scope_type" value="instance">
                          <select name="status" aria-label="Status for {{.Host}}">{{range $.Statuses}}<option>{{.}}</option>{{end}}</select>
                          <input name="label" value="{{.Label}}" placeholder="label" aria-label="Label for {{.Host}}">
                          <button>Apply to host</button>
                        </form>
                      </div>
                    {{end}}
                  </div>
                </details>
              </td>
              <td data-value="{{.Status}}"><span class="badge status-{{.Status}}">{{.Status}}</span></td>
              <td data-value="{{.Label}}">{{if .LabelsVary}}<span class="muted">varies by host</span>{{else if .Label}}{{.Label}}{{else}}<span class="muted">-</span>{{end}}</td>
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
              <td data-value="{{.Count}}">{{.Count}}</td>
              <td>
                <form class="inline" method="post" action="/decisions">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="fingerprint" value="{{.Fingerprint}}">
                  <select name="status">{{range $.Statuses}}<option>{{.}}</option>{{end}}</select>
                  <input type="hidden" name="scope_type" value="global">
                  <input name="label" value="{{.Label}}" placeholder="label">
                  <button>Apply to all hosts</button>
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
    const densityToggle = document.getElementById("density-toggle");
    const savedDensity = localStorage.getItem("gatehub-density") || "compact";
    document.body.classList.toggle("compact", savedDensity === "compact");
    function updateDensityButton() {
      const compact = document.body.classList.contains("compact");
      densityToggle.textContent = compact ? "Comfortable view" : "Compact view";
      densityToggle.setAttribute("aria-pressed", String(compact));
    }
    updateDensityButton();
    densityToggle.addEventListener("click", () => {
      document.body.classList.toggle("compact");
      localStorage.setItem("gatehub-density", document.body.classList.contains("compact") ? "compact" : "comfortable");
      updateDensityButton();
    });
    document.querySelectorAll("section[data-collapsible]").forEach((section) => {
      const heading = section.querySelector("h2");
      const tools = section.querySelector(".section-tools") || section.querySelector(".section-head");
      const button = document.createElement("button");
      const storageKey = "gatehub-section-" + section.id;
      button.type = "button";
      button.className = "collapse-toggle";
      button.setAttribute("aria-controls", section.id);
      function updateSection() {
        const collapsed = section.classList.contains("is-collapsed");
        button.textContent = collapsed ? "Show" : "Hide";
        button.setAttribute("aria-expanded", String(!collapsed));
        button.setAttribute("aria-label", (collapsed ? "Show " : "Hide ") + heading.textContent);
      }
      if (localStorage.getItem(storageKey) === "collapsed") section.classList.add("is-collapsed");
      button.addEventListener("click", () => {
        section.classList.toggle("is-collapsed");
        localStorage.setItem(storageKey, section.classList.contains("is-collapsed") ? "collapsed" : "expanded");
        updateSection();
      });
      tools.appendChild(button);
      updateSection();
    });
    const logoutBtn = document.getElementById("logout-btn");
    const csrfToken = document.querySelector("meta[name='csrf-token']")?.content || "";
    if (logoutBtn) {
      logoutBtn.addEventListener("click", async () => {
        logoutBtn.disabled = true;
        try { await fetch("/api/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrfToken } }); } catch (e) {}
        window.location.href = "/login";
      });
    }
    document.querySelectorAll("form.inline").forEach((form) => {
      form.addEventListener("submit", (event) => {
        const scope = form.querySelector("[name='scope_type']");
        if (scope?.value === "global" && !window.confirm("Apply this decision to every node with this fingerprint?")) {
          event.preventDefault();
        }
      });
    });
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
