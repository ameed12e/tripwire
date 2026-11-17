# Architecture

```
src/tripwire/
├── cli.py              Typer commands; builds plugins from config and runs the engine
├── core/
│   ├── config.py       pydantic models, YAML loading, ${ENV} expansion, secret lookup
│   ├── events.py       Event (raw observation) and Incident (persisted event)
│   ├── engine.py       queue → dedupe → storage → alert fan-out
│   ├── plugin.py       PluginOptions / PluginContext / Plugin base
│   ├── registry.py     built-in + entry-point plugin discovery
│   └── logging.py      structlog configuration
├── collectors/         filesystem (watchdog), subprocess (JSON-lines contract)
├── decoys/             inert file templates, beacon templates, planter + manifest
├── alerts/             telegram, email, webhook; AlertMessage formatter
├── server/             FastAPI beacon endpoint, signed report links, rate limiting
└── storage/            SQLite (WAL) + Fernet encryption
```

## Event flow

1. A collector (thread or coroutine) calls `Engine.emit(event)`. This is thread-safe:
   it hands off to the event loop with `call_soon_threadsafe`.
2. A single worker coroutine pulls events from a bounded queue.
3. **Dedupe**: identical events (`kind` + decoy/path [+ client IP]) within
   `engine.dedupe_window_seconds` are dropped, so one file open by an editor
   does not produce 10 alerts.
4. The incident is encrypted and written to SQLite (in a worker thread).
5. An `AlertMessage` with a signed report URL is sent to all channels
   concurrently. Each channel has a 20 s timeout and failures are isolated.

## Beacon flow

1. `tripwire plant beacon-docx ~/Desktop` generates `decoy_id`, builds
   `https://<public_url>/t/<decoy_id><hmac>.png`, embeds it as an external
   image, registers the label in the DB and records the decoy in the manifest.
2. Someone opens the document and the viewer fetches the image.
3. The server verifies the HMAC, emits a `beacon_hit` event (IP, user agent,
   referer, accept-language) and always returns a 1×1 GIF.

## Resource usage

- The filesystem collector is event-driven. The asyncio loop sleeps in hour-long
  intervals unless the optional atime check is enabled.
- No threads spin. SQLite writes happen only per incident.
- Expected idle CPU is effectively 0% (well under the 1% budget).

## Manifest

`<data_dir>/manifest.json` lists every planted decoy (id, template, path,
label, sha256). It is the single source of truth for `status`, the filesystem
collector and `plant --remove`. Removal only deletes a file whose content is
unchanged since planting, unless `--force` is given.
