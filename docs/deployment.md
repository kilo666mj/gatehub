# Deployment and authentication

OIDC administration, node identity, listener topology, and Ansible deployment.

## Admin Authentication

The admin surface authenticates through **OpenID Connect** by default
(`--admin-auth oidc`), acting as a relying party against your provider (e.g.
Pocket ID). Register an OIDC client on the provider whose redirect URL points at
this app's `/api/auth/callback`, then run:

```sh
go run . --db ./gatehub.sqlite \
  --admin-listen 127.0.0.1:8081 \
  --admin-oidc-issuer https://pocket-id.example.com \
  --admin-oidc-client-id gatehub \
  --admin-oidc-redirect-url https://gatehub.example.com/api/auth/callback \
  --admin-oidc-allowed-emails you@example.com
# client secret via env (kept out of argv):
export GATEHUB_ADMIN_OIDC_CLIENT_SECRET=...
```

Serve the admin UI over `https://` (a reverse proxy) or reach it as
`http://127.0.0.1` / `localhost` over an SSH tunnel; the redirect URL must match
the hostname the browser uses. `/login` shows a single "Sign in with Pocket ID"
button that starts the authorization-code + PKCE flow. On return, the verified
identity is checked against the optional `--admin-oidc-allowed-{subjects,emails,groups}`
allowlists before a session is issued. Sessions live in the same SQLite database;
lifetime is `--admin-session-max-age` seconds (default 8h; `0` disables expiry).
The OIDC relying-party flow is provided by
[`github.com/kilo666mj/oidcrp`](https://github.com/kilo666mj/oidcrp).

For localhost-only development you can disable auth with `--admin-auth none`.
The process refuses to start an OIDC admin listener without an issuer, client ID,
and redirect URL, so a misconfiguration cannot silently expose the approval API.

Client certificates are used as node identity. A node must be registered in
`gatehub` before it can sync, and its configured `allowed_cert_name`
must match the client certificate Common Name, DNS SAN, or URI SAN.

## Run Admin Only

```sh
go run . --db ./gatehub.sqlite --admin-listen 127.0.0.1:8081 --admin-auth none
```

Open `http://127.0.0.1:8081` from an internal network or over a tunnel.
`--admin-auth none` disables OIDC auth and is for localhost development only;
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
- `POST /v1/signals/batch`
- `GET /v1/policy`
- `GET /healthz`

Do not proxy the admin listener publicly.

## Node Registration

Nodes can be registered through the authenticated admin UI or locally with the
administrative CLI. The CLI reads tokens from a file or standard input so they
do not appear in process arguments or shell history:

```sh
gatehub register-node --db /var/lib/gatehub/gatehub.sqlite \
  --id logs-central --kind log_watcher --host logwc \
  --allowed-cert-name logs-central --token-file /run/secrets/log-watcher-token
```

Use `--token-file -` to read one newline-terminated token from standard input.
The token is hashed before storage and is never printed.

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

