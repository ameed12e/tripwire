# Security policy

## Supported versions

Only the latest release receives security fixes during the 0.x series.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
**"Report a vulnerability"** (Security Advisories) on this repository.
Include affected version, impact and reproduction steps. We aim to acknowledge
within 72 hours and to ship a fix or mitigation within 30 days.

## Security model (summary)

- **Secrets**: the Fernet key, the HMAC signing key and channel credentials come
  from environment variables (or a `0600` `.env` in the data directory). They
  are never written to the YAML config or logs.
- **At rest**: incident reports are Fernet-encrypted (AES-128-CBC + HMAC-SHA256)
  in SQLite. Plaintext columns are limited to id, timestamp, kind, severity and
  decoy id.
- **Beacon tokens** are `decoy_id || HMAC(signing_key, decoy_id)[:64 bits]`.
  Forged or random tokens are answered with the same pixel and create no
  incident. Requests are rate-limited per IP.
- **Report links** are HMAC-signed and expire (default 72 h).
- **Decoys are inert**: there are no macros, scripts or executable content. Beacons
  only reference a URL.

## Out of scope

- An attacker who already has root/admin on the monitored device can disable
  the agent. Tripwire is a detection aid, not a prevention control.
- Viewers that block remote content will not trigger beacons.
