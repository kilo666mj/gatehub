package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kilo666mj/gatekit/approval"
	"net/http"
)

func scopeSQL(scope *approval.Scope) any {
	if scope == nil {
		return nil
	}
	// Ranges is []string, which encoding/json always supports.
	b, _ := json.Marshal(scope.Ranges())
	return string(b)
}
func decodeScope(raw sql.NullString) (*approval.Scope, error) {
	if !raw.Valid {
		return nil, nil
	}
	var scope *approval.Scope
	if err := json.Unmarshal([]byte(raw.String), &scope); err != nil {
		return nil, err
	}
	if scope == nil {
		return nil, errors.New("non-null approval scope must contain CIDRs")
	}
	return scope, nil
}

type scopeQuerier interface{ QueryRow(string, ...any) *sql.Row }

// Only the latest applicable decision is effective, regardless of target scope.
func hasRestrictedPolicy(q scopeQuerier, node Node, fingerprint string) (bool, error) {
	var restricted bool
	err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM decisions d
 WHERE (d.scope_type='global' OR (d.scope_type='kind' AND d.scope_id=?) OR (d.scope_type='instance' AND d.scope_id=?))
 AND (?='' OR d.fingerprint=?) AND d.status='approved' AND d.approval_ranges IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM decisions later WHERE later.fingerprint=d.fingerprint
 AND (later.scope_type='global' OR (later.scope_type='kind' AND later.scope_id=?) OR (later.scope_type='instance' AND later.scope_id=?))
 AND (later.updated_at>d.updated_at OR (later.updated_at=d.updated_at AND later.id>d.id))))`, node.Kind, node.ID, fingerprint, fingerprint, node.Kind, node.ID).Scan(&restricted)
	return restricted, err
}

func (s *Store) checkNodeScopeCompatibility(n Node) error {
	var supported bool
	err := s.db.QueryRow(`SELECT supports_approval_ranges FROM nodes WHERE id=?`, n.ID).Scan(&supported)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if supported {
		return nil
	}
	restricted, err := hasRestrictedPolicy(s.db, n, "")
	if err != nil {
		return err
	}
	if restricted {
		return errors.New("node registration would apply scoped approval to an unsupported node")
	}
	return nil
}

// RecordScopeCapability learns support only from an authenticated policy request, not admin input.
func (s *Store) RecordScopeCapability(node Node, supported bool) error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	if _, err := s.db.Exec(`UPDATE nodes SET supports_approval_ranges=? WHERE id=?`, supported, node.ID); err != nil {
		return err
	}
	if !supported {
		restricted, err := hasRestrictedPolicy(s.db, node, "")
		if err != nil {
			return err
		}
		if restricted {
			return errors.New("node cannot enforce active approval_ranges; upgrade before pulling policy")
		}
	}
	return nil
}

func validateScopeTargetsTx(tx *sql.Tx, d Decision) (err error) {
	if d.Status != decisionApproved {
		return nil
	}
	rows, err := tx.Query(`SELECT id,kind,supports_approval_ranges FROM nodes WHERE ?='global' OR (?='kind' AND kind=?) OR (?='instance' AND id=?)`, d.ScopeType, d.ScopeType, d.ScopeID, d.ScopeType, d.ScopeID)
	if err != nil {
		return err
	}
	defer closeWithError(&err, "close scope target rows", rows.Close)
	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Kind, &n.SupportsApprovalRanges); err != nil {
			return err
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if d.ApprovalRanges != nil && len(nodes) == 0 {
		return errors.New("scoped approval requires registered target nodes")
	}
	for _, n := range nodes {
		if d.ApprovalRanges != nil && !n.SupportsApprovalRanges {
			return fmt.Errorf("node %q has not advertised approval_ranges support", n.ID)
		}
		if d.ApprovalRanges == nil && !d.ClearApprovalRanges {
			restricted, err := hasRestrictedPolicy(tx, n, d.Fingerprint)
			if err != nil {
				return err
			}
			if restricted {
				return errors.New("approval would remove a CIDR restriction; explicitly set clear_approval_ranges")
			}
		}
	}
	return nil
}

func (a *app) handleAdminDecisionAPI(w http.ResponseWriter, r *http.Request) {
	if !a.auth.requireCSRF(w, r) {
		return
	}
	var d Decision
	if err := readJSON(r, &d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	d.Actor = "admin"
	d.Source = "manual"
	if d.ScopeType == "global" {
		d.ScopeID = ""
	}
	if err := a.store.CreateDecision(d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// A preapproval must remain visible when its first observation creates the row.
// Observations never provide the authoritative status or scope.
func applyCurrentDecisionTx(tx *sql.Tx, node Node, fp string) error {
	var status, label string
	var ranges sql.NullString
	err := tx.QueryRow(`SELECT status,label,approval_ranges FROM decisions WHERE fingerprint=? AND
 (scope_type='global' OR (scope_type='kind' AND scope_id=?) OR (scope_type='instance' AND scope_id=?))
 ORDER BY updated_at DESC,id DESC LIMIT 1`, fp, node.Kind, node.ID).Scan(&status, &label, &ranges)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE fingerprints SET status=?,label=CASE WHEN ?!='' THEN ? ELSE label END,approval_ranges=? WHERE node_id=? AND fingerprint=?`, status, label, label, ranges, node.ID, fp)
	return err
}
