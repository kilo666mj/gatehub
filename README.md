# gatehub

<p align="center">
  <img src="assets/porter-mascot-concept.png" alt="Porter mascot" width="260">
</p>

> **Written with AI.** This project was developed with the help of an AI
> assistant (OpenAI's GPT-5, via Codex). The code has been reviewed and tested,
> but treat it accordingly: read it before you run it.

Shared control plane for `tlsgate` and `sshgate` fingerprint approvals.

The service has two HTTP surfaces:

- Admin listener: internal UI/API for registering nodes and approving,
  blocking, or labeling fingerprints. Gated by WebAuthn (passkey) login with
  server-side sessions.
- Public listener: mTLS-only sync API for gate instances. It exposes only
  node sync paths.

## Admin Authentication

The admin surface requires a WebAuthn passkey by default (`--admin-auth
webauthn`). Because WebAuthn only works in a secure context, serve the admin UI
over `https://` (a reverse proxy) or reach it as `http://127.0.0.1` / `localhost`
over an SSH tunnel. The relying-party ID and origin must match that hostname:

```sh
go run . --db ./gatehub.sqlite \
  --admin-listen 127.0.0.1:8081 \
  --admin-webauthn-rpid gatehub.example.com \
  --admin-webauthn-origin https://gatehub.example.com
```

The first browser to reach `/login` with no credential enrolled can register a
passkey; once one exists, further enrollment requires an authenticated session.
Credentials and sessions live in the same SQLite database. Session lifetime is
`--admin-session-max-age` seconds (default 8h; `0` disables expiry).

For localhost-only development you can disable auth with `--admin-auth none`.
The process refuses to start a WebAuthn admin listener without an RP ID and
origin, so a misconfiguration cannot silently expose the approval API.

Client certificates are used as node identity. A node must be registered in
`gatehub` before it can sync, and its configured `allowed_cert_name`
must match the client certificate Common Name, DNS SAN, or URI SAN.

## Run Admin Only

```sh
go run . --db ./gatehub.sqlite --admin-listen 127.0.0.1:8081 --admin-auth none
```

Open `http://127.0.0.1:8081` from an internal network or over a tunnel.
`--admin-auth none` disables passkey auth and is for localhost development only;
see [Admin Authentication](#admin-authentication) for the production setup.

## Run Public mTLS Sync

```sh
go run . \
  --db ./gatehub.sqlite \
  --admin-listen 127.0.0.1:8081 \
  --public-listen 127.0.0.1:8443 \
  --public-cert /path/to/server.crt \
  --public-key /path/to/server.key \
  --client-ca /path/to/client-ca.crt \
  --client-crl /path/to/client-ca.crl.pem
```

Expose only these public paths through the internet-facing reverse proxy:

- `POST /v1/observations/batch`
- `GET /v1/policy`
- `GET /healthz`

Do not proxy the admin listener publicly.

## Node Registration

Create a node in the admin UI:

```text
Instance ID: mail-tls
Kind: tlsgate
Host: mail-gateway
Allowed cert name: mail-gateway
```

The public API will then accept requests for `instance_id=mail-tls` only
when the mTLS client certificate identifies as `mail-gateway`.

## Ansible Deployment

The included playbook deploys `gatehub` to the hosts in `ansible/inventory`.
Replace the sample inventory with your deployment host before running it:

```sh
cd ansible
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

Default listeners:

- Admin UI/API: `0.0.0.0:8081`
- Public mTLS sync API: `127.0.0.1:9443`

Place or override the server certificate, server key, and client CA paths before
starting the service. The defaults are:

```text
/etc/gatehub/server.crt
/etc/gatehub/server.key
/etc/gatehub/client-ca.crt
```

By default the playbook generates a self-signed server certificate if
`server.crt`/`server.key` are missing. To copy a local client CA certificate to
the target during deploy, pass:

```sh
ansible-playbook playbook.yml -e gatehub_client_ca_src=/path/to/client-ca.crt
```

If you put `127.0.0.1:9443` behind a normal HTTP reverse proxy or tunnel, make
sure client certificate identity still reaches `gatehub`. Standard HTTP
termination at the proxy will not pass the node mTLS certificate through to the
origin process.

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
