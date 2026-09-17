# Operations and recovery

Health checks, logs, backups, upgrades, policy safety, and common failure modes.

## Health and logs

Each enabled listener exposes `GET /healthz`. Check the same surface that the
caller uses:

```sh
curl --fail http://127.0.0.1:8081/healthz
curl --fail --cacert ./server-ca.crt \
  --cert ./node.crt --key ./node.key \
  https://gatehub.example.com/healthz
```

The second form applies when the public listener requires mTLS. For token-only
deployments, omit the client certificate options. A successful health response
shows that the HTTP process and database are available; verify a real policy
pull from a registered test node before considering node authentication and
authorization healthy.

With the included systemd unit:

```sh
systemctl status gatehub
journalctl -u gatehub --since today
```

Repeated observation or policy errors usually mean the node ID, bearer token,
certificate name, or public authentication mode disagrees with the node record.
Gatehub never accepts one authenticated node claiming another node's instance
ID.

## Database and backups

Gatehub stores nodes, hashed bearer tokens, OIDC sessions, observations,
decisions, audit records, and reports in one SQLite database. SQLite runs in
WAL mode, so keep the live database on a local filesystem. Do not place it on
NFS or copy only the main database file while Gatehub is running.

Use SQLite's online backup command for a consistent snapshot:

```sh
sudo install -d -m 0700 /var/backups/gatehub
sudo sqlite3 /var/lib/gatehub/gatehub.sqlite \
  ".backup '/var/backups/gatehub/gatehub-$(date +%Y%m%dT%H%M%SZ).sqlite'"
```

Protect and rotate snapshots like credentials. Periodically restore a snapshot
to a temporary path and run an integrity check:

```sh
sqlite3 /path/to/restored-gatehub.sqlite 'PRAGMA integrity_check;'
```

Restoring production state is an offline operation: stop Gatehub, preserve the
current database plus its `-wal` and `-shm` companions for rollback, install the
verified snapshot with the service user's ownership, and start the service.
Confirm admin login, registered nodes, policy pulls, and `/healthz` afterward.

## Upgrades and rollback

Before an upgrade:

1. Create and verify a database snapshot.
2. Record the current binary version or package digest.
3. Build and test the replacement from the intended source revision.
4. Deploy the binary and restart Gatehub.
5. Check both health endpoints, administrator login, one observation upload,
   and one policy pull.

Database migrations are applied when Gatehub opens the database. Rollback is
therefore the previous binary plus the pre-upgrade snapshot when an older
binary cannot read the upgraded schema. Do not restore a database while either
listener is running.

## Retention and automated decisions

`--sighting-retention` bounds detailed fingerprint sightings and web abuse
signals; the default is eight days. Aggregate fingerprint rows, decisions,
nodes, sessions, SMTP reports, and audit records are not removed by that
cleanup.

Web scanner scoring and enforcement are separately gated:

- `--web-shadow-enabled` calculates candidates without changing policy.
- `--web-enforcement-mode=canary` limits automated blocks to the explicit
  canary node list.
- `--web-enforcement-mode=enforce` permits every eligible TLSGate node.
- `--web-enforcement-mode=disabled` is the kill switch and publishes pending
  decisions to clear effective automated blocks.

Start in shadow mode, review candidates over a representative period, then use
canary mode before wider enforcement. Manual approvals protect matching
fingerprints from automation.

## Troubleshooting

- **Admin listener refuses to start:** OIDC mode requires issuer, client ID,
  and redirect URL. Use `--admin-auth none` only on loopback for development.
- **OIDC login loops or callback fails:** the configured redirect URL must
  exactly match the provider registration and the browser-visible HTTPS URL.
- **Public listener refuses to start:** `mtls` and `both` require a server
  certificate, key, and client CA. Token-only mode may run behind a trusted TLS
  terminator, but the origin path must still be protected.
- **Node receives `401`:** verify its token or client certificate chain.
- **Node receives `403`:** verify that its certificate name and reported
  `instance_id` match the registered node and that the node is active.
- **Database is locked or slow:** confirm the live database is on local disk,
  the service user owns its directory, and no external process is holding a
  long write transaction.
- **A gate retains an automated block:** set enforcement to `disabled`, keep
  Gatehub running long enough for the gate to pull the explicit pending
  decision, and inspect the gate's control-plane logs.
- **Trusted ranges stop updating:** check every configured HTTPS reflector or
  DNS name. Gatehub retains a source only through the configured grace period
  after its last successful refresh.

## Removal

Disable automated enforcement first and allow gates to receive the clearing
policy. Then remove Gatehub configuration from each gate, stop and disable the
service, archive or destroy the credential-bearing database according to the
retention policy, and remove public synchronization routes. Removing Gatehub
does not remove local gate databases or backend authentication.
