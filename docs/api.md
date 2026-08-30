# Synchronization API

Node observation, policy, signal, and web-candidate API reference.

## Sync API

Observation upload:

```http
POST /v1/observations/batch?instance_id=mail-tls
```

```json
{
  "instance_id": "mail-tls",
  "observations": [
    {
      "fingerprint": "abc123",
      "status": "blocked",
      "first_seen": "2026-07-01T10:00:00Z",
      "last_seen": "2026-07-01T10:01:00Z",
      "ips": ["203.0.113.10"],
      "ports": [993],
      "sightings": [
        {"ip": "203.0.113.10", "port": 993, "last_seen": "2026-07-01T10:01:00Z"}
      ],
      "count": 2,
      "metadata": {
        "sni": "mail.example.com",
        "ja3": "...",
        "ja4": "..."
      }
    }
  ]
}
```

Timestamped sightings preserve the IP/port pairing needed for later event
correlation. Gatehub retains them for eight days by default; configure
`--sighting-retention` to change the bounded retention window. Aggregate
fingerprint records and decisions are not removed by sighting cleanup.

Policy pull:

```http
GET /v1/policy?instance_id=mail-tls&since=2026-07-01T10:00:00Z
```

```json
{
  "cursor": "2026-07-01T10:05:00Z",
  "decisions": [
    {
      "scope_type": "instance",
      "scope_id": "mail-tls",
      "fingerprint": "abc123",
      "status": "approved",
      "label": "Alice iPhone",
      "updated_at": "2026-07-01T10:05:00Z",
      "actor": "admin"
    }
  ]
}
```

Web signal nodes registered with kind `log_watcher` may upload aggregate
scanner evidence to `POST /v1/signals/batch?instance_id=<id>`. The schema
intentionally has no raw request-target or user-agent field because access-log
values can contain credentials and personal data:

```json
{
  "instance_id": "central-logs",
  "signals": [{
    "event_id": "01example",
    "observed_at": "2026-08-21T15:00:00Z",
    "host": "web-1",
    "site": "example",
    "ip": "203.0.113.10",
    "trigger": "suspicious_uri",
    "connections": 20,
    "errors": 18,
    "successes": 2,
    "window_seconds": 120
  }]
}
```

The authenticated admin endpoint `GET /api/web-candidates` correlates signals
with TLS sightings from the same host within five minutes and returns
report-only candidates grouped by gate instance and fingerprint. When the
shadow policy is enabled, each candidate also includes `shadow_status`,
`shadow_reasons`, the measured `error_ratio`, cross-site/node evidence, and a
proposed expiry. `would_block` is simulation output only: this endpoint never
creates a decision and shadow results are never returned to gate nodes.

An existing manual `approved` decision protects the matching fingerprint from
shadow automation; an existing manual `blocked` decision is reported as
`already_blocked`. Configure scoring with `--web-shadow-enabled`,
`--web-shadow-min-networks`, `--web-shadow-min-signals`,
`--web-shadow-min-error-ratio`, `--web-shadow-require-multi-scope`, and
`--web-shadow-proposed-ttl`. Optional `window` (maximum `30m`) and RFC3339 `since`
