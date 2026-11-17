# Tripwire

Defensive tripwires and honeytokens for **devices you own**. Plant convincing
decoys (fake credentials, "confidential" documents). The moment someone reads,
changes, deletes or opens one, you get a short alert on your phone with a link
to the full report.

> ## ⚖️ Ethics and legal notice
>
> Tripwire is a **defensive** tool. Deploy it **only on systems you own or are
> explicitly authorized in writing to monitor**. Monitoring other people's
> devices or accounts without consent may be illegal (computer misuse,
> wiretapping and privacy laws such as the CFAA, GDPR and local equivalents).
> Beacon hits record the IP address and user agent of whoever opened a
> decoy. Treat that data as personal data: keep it encrypted (Tripwire does by
> default), retain it only as long as needed, and handle it lawfully.
>
> By design Tripwire does **not**: self-propagate, install persistence, hide
> from the device owner, or run any code on a third party's device. Beacons
> are passive remote-resource references (an image or link), never macros,
> scripts or exploits.

## How it works

```
 decoy files ──(watchdog)──► filesystem collector ─┐
 external collectors (Go/Rust, JSON lines) ────────┤
                                                   ▼
 beacon docs ──(HTTP GET /t/<token>)──► server ──► engine ──► SQLite (Fernet-encrypted)
                                                   │
                                                   └──► Telegram · e-mail · webhook
                                                        "🟠 Decoy accessed … Report: https://…/r/<id>?sig=…"
```

* **Filesystem collector**: event-driven (inotify / FSEvents / ReadDirectoryChangesW
  via `watchdog`). On Linux, plain *reads* are detected. On every OS, modify,
  move and delete are detected. An optional low-frequency atime check covers reads
  on macOS/Windows where the filesystem updates access times.
* **Beacon decoys**: HTML, DOCX, PDF and `.url` files that reference a unique,
  HMAC-signed URL on your server. Opening one in a viewer that loads remote
  content triggers an alert. Many viewers block remote content by default, so
  treat beacons as a bonus signal on top of the filesystem collector.
* **Alerts** are phone-sized: a title, a one-line summary, host, time and a
  **signed, expiring link** to the full JSON report.
* **Storage**: SQLite. The full incident report (paths, IPs, user agents) is
  encrypted with Fernet, so only minimal metadata is stored in plaintext.

## Quick start

```bash
pip install .                         # Python 3.11+
tripwire init --public-url https://tripwire.example.com
tripwire plant --list                 # see decoy templates
tripwire plant passwords ~/Documents --label "Documents password list"
tripwire plant beacon-docx ~/Desktop  # needs `tripwire serve` reachable at public URL
export TRIPWIRE_TELEGRAM_TOKEN=123:abc TRIPWIRE_TELEGRAM_CHAT_ID=987654
# enable the telegram alert in ~/.config/tripwire/config.yaml, then:
tripwire watch                        # run the agent
tripwire status                       # decoys + counts
tripwire incidents                    # list incidents, --show <id> for a full report
tripwire plant --remove-all           # clean up every decoy you planted
```

`tripwire init` writes the config to `~/.config/tripwire/config.yaml` (or
`$TRIPWIRE_CONFIG`). It also writes `TRIPWIRE_FERNET_KEY` and `TRIPWIRE_SIGNING_KEY`
to `~/.local/share/tripwire/.env` with mode `600`. Real environment variables
override that file. **Back up the Fernet key**: without it, stored incidents
cannot be decrypted.

### Running the beacon server

```bash
cp .env.example .env    # fill in keys (same signing key as the agent that planted beacons)
docker compose up -d    # listens on 127.0.0.1:8080; put a TLS reverse proxy in front
```

The server must share `TRIPWIRE_SIGNING_KEY` with the machine that planted
the beacons, because tokens are verified by HMAC. Labels are shown when the
server also shares the database. Otherwise alerts show the decoy id.
Set `server.trust_forwarded_for: true` only behind a proxy you control.

## Configuration

See [`config.example.yaml`](config.example.yaml). Any value can reference an
environment variable as `${VAR}` or `${VAR:-default}`. Secrets belong in env
vars, never in the YAML file.

| Alert channel | Key options |
|---|---|
| `telegram` | `bot_token`, `chat_id`, `silent` |
| `email` | `smtp_host`, `smtp_port`, `security` (`starttls`/`ssl`/`none`), `username`, `password`, `sender`, `recipients` |
| `webhook` | `url`, `headers`, `secret` (HMAC-SHA256 `X-Tripwire-Signature`), `include_report` |

## Extending

Collectors and alert channels are plugins (Python entry points or any
executable that speaks a JSON-lines contract). See [docs/PLUGINS.md](docs/PLUGINS.md)
and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

## Roadmap (phase 2)

Android agent via Termux, OpenCanary-style fake network services, web dashboard.

## License

MIT, see [LICENSE](LICENSE).
