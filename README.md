# gatehub

<p align="center">
  <img src="assets/porter-mascot-concept-v2.png" alt="Porter mascot" width="360">
</p>

> **Written with AI.** This project was developed with the help of an AI
> assistant (OpenAI's GPT-5, via Codex). The code has been reviewed and tested,
> but treat it accordingly: read it before you run it.

Gatehub is the shared control plane for
[TLSGate](https://github.com/kilo666mj/tlsgate) and
[SSHGate](https://github.com/kilo666mj/sshgate) fingerprint observations and
approval decisions.

It exposes two separate HTTP surfaces:

- An internal admin UI/API for registering nodes and approving, blocking, or
  labeling fingerprints.
- A narrowly scoped synchronization API for gate instances, authenticated with
  node credentials or mTLS.

Do not expose the admin listener as the public synchronization surface.

## Quick start

Run an unauthenticated, loopback-only development instance:

```sh
go run . \
  --db ./gatehub.sqlite \
  --admin-listen 127.0.0.1:8081 \
  --admin-auth none
```

Open `http://127.0.0.1:8081`.

Production administration uses OpenID Connect. Register
`https://gatehub.example.com/api/auth/callback` with the identity provider,
then configure the issuer, client ID, redirect URL, and optional subject, email,
or group allowlists. Gatehub refuses to start an OIDC admin listener with an
incomplete configuration.

Nodes must be registered before they can synchronize. Their configured
certificate identity or bearer token is bound to the instance ID they report.

## Deployment

The included Ansible playbook installs Gatehub and its systemd service:

```sh
cd ansible
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml
```

The normal topology keeps the admin listener behind an internal HTTPS reverse
proxy while exposing only these synchronization paths:

```text
POST /v1/observations/batch
POST /v1/signals/batch
GET  /v1/policy
GET  /healthz
```

If TLS terminates at a proxy, ensure the selected node-authentication mechanism
still reaches Gatehub. A conventional HTTP reverse proxy does not forward the
original client certificate automatically.

See [deployment and authentication](docs/deployment.md) for OIDC, node
registration, certificates, listener configuration, and Ansible variables.

## API

Gate instances upload fingerprint observations and pull approval policy.
Signal-producing nodes can submit privacy-bounded aggregate scanner evidence;
the admin API correlates those signals with recent TLS sightings. An optional
shadow policy explains which candidates would receive a short-lived block under
configured network, signal, error-ratio, and cross-site/node thresholds, but it
never creates or distributes decisions automatically. Manual approvals act as
protection overrides.

See the [synchronization API reference](docs/api.md) for request and response
examples, retention behavior, and the web-candidate endpoint.

## Development

```sh
go build ./...
go test ./...
```

Gatehub uses SQLite for durable state. Treat the live database and its
credential-bearing contents as sensitive operational data.

## Documentation

- [Deployment and authentication](docs/deployment.md)
- [Synchronization API](docs/api.md)
- [TLSGate](https://github.com/kilo666mj/tlsgate)
- [SSHGate](https://github.com/kilo666mj/sshgate)
- [OIDC relying-party helper](https://github.com/kilo666mj/oidcrp)

## License

MIT. See [LICENSE](LICENSE).
