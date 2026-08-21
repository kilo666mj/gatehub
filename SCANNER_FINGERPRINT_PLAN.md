# Web Scanner Fingerprint Correlation Plan

## Goal

Use centrally collected nginx access logs and passive TLS ClientHello
observations to identify high-confidence scanner fingerprints, then distribute
short-lived blocks to the TLS gateways already protecting each ingress.

This is a noise-reduction mechanism, not authentication. JA3 and JA4 values
are shared by many clients and are spoofable, so automated decisions must be
conservative, reversible, and subordinate to manual policy.

## Architecture

```text
nginx hosts --syslog--> log_watcher --abuse signals--> Gatehub
       ^                                             /       \
       |                                  observations       decisions
       +----------- nginx <--PROXY v2-- tlsgate <-----------+
```

### log_watcher

`log_watcher` remains the single central log consumer. A separate internal
web-traffic detector will process nginx access events before the existing
operational-alert rules. It will:

- unwrap the syslog envelope while retaining source host and virtual host;
- parse the nginx access record and original client address;
- maintain namespaced counters and fixed windows in the existing KeyDB;
- recognize suspicious paths and high error rates;
- send structured abuse signals to Gatehub through a bounded asynchronous
  queue with durable retry;
- continue operating when Gatehub is unavailable.

The detector does not make fingerprint decisions and does not need to poll
Gatehub.

### tlsgate and Gatekit

`tlsgate` remains the per-ingress data plane. It will:

- optionally send PROXY protocol v2 to a backend that explicitly expects it;
- pass the original ClientHello through byte-for-byte after the PROXY header;
- record JA4, source address, port, SNI, and observation time;
- sync observations and poll decisions through Gatehub as it does today;
- enforce manual and automated fingerprint decisions.

The observation protocol must carry a recent timestamp per fingerprint/IP
sighting. Overall fingerprint timestamps and an un-timestamped IP set are not
precise enough for safe correlation behind NAT or after IP reassignment.

### Gatehub

Gatehub is the policy authority and correlator. It will:

- authenticate and persist web-abuse signals;
- join a signal to TLS sightings by source IP and a short time window;
- aggregate distinct source networks rather than raw requests;
- produce report-only candidates before enforcement is enabled;
- create expiring, provenance-bearing automated blocks;
- ensure manual approvals and protected fingerprints outrank automation;
- expose evidence and decisions for audit and manual override.

## Initial policy

The first version will default to report-only. Thresholds will be configurable,
with conservative defaults along these lines:

- use JA4 for correlation;
- require a TLS sighting within five minutes of the HTTP abuse signal;
- count distinct IPv4 `/24` and IPv6 `/64` networks;
- require evidence across multiple networks and preferably multiple sites;
- require a high suspicious/error ratio;
- never automatically block a manually approved or protected fingerprint;
- expire an automated block after 6-24 hours unless renewed by new evidence.

Raw connection or request counts alone must never trigger a fingerprint block.

## Delivery phases

1. Add opt-in backend PROXY protocol v2 support to tlsgate, with byte-level
   tests, documentation, and Ansible configuration.
2. Extend Gatekit/Gatehub observations with per-IP sighting timestamps while
   preserving compatibility with existing nodes.
3. Add the isolated web-traffic detector to log_watcher and feed it the
   centralized nginx access stream.
4. Add authenticated abuse-signal ingestion and retention to Gatehub.
5. Implement correlation and candidate reporting with no automatic blocks.
6. Observe candidates, tune thresholds, and add audit/UI visibility.
7. Enable expiring automated decisions explicitly.
8. Retire web_watcher where its local IP blocking and analytics are no longer
   needed; retain it where those functions remain useful.

## Rollout and safety

- Every new feature is disabled by default.
- A backend must be configured for PROXY protocol before tlsgate enables it.
- Use a canary HTTPS ingress before broad deployment.
- Gatehub outages must not interrupt existing traffic or erase local policy.
- Signal queues and database tables must be bounded by age and size.
- Do not store request query strings, credentials, or other unnecessary
  sensitive data in evidence.
- Deployment remains a separate reviewed step after code and tests are ready.
