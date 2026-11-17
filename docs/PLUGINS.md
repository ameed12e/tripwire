# Plugins

Tripwire has two plugin kinds: **collectors** (produce events) and **alert
channels** (deliver incidents). Both are configured the same way:

```yaml
collectors:
  - type: <plugin name>      # registry key
    name: <instance name>    # optional, defaults to type
    enabled: true
    options: { ... }         # validated by the plugin's pydantic Options model
```

## 1. Python plugins (entry points)

Create a package that depends on `tripwire` and declares entry points:

```toml
[project.entry-points."tripwire.collectors"]
usb = "tripwire_usb:UsbCollector"

[project.entry-points."tripwire.alerts"]
ntfy = "tripwire_ntfy:NtfyChannel"
```

### Collector

```python
import asyncio
from tripwire.collectors.base import Collector, Emit
from tripwire.core.events import Event, EventKind, Severity
from tripwire.core.plugin import PluginOptions


class UsbOptions(PluginOptions):
    poll_seconds: float = 30


class UsbCollector(Collector[UsbOptions]):
    Options = UsbOptions

    async def run(self, emit: Emit) -> None:
        while True:  # must sleep/await, never busy-loop
            await asyncio.sleep(self.options.poll_seconds)
            ...
            emit(
                Event(
                    kind=EventKind.CUSTOM,
                    source=self.name,
                    summary="USB storage inserted",
                    severity=Severity.MEDIUM,
                )
            )

    async def stop(self) -> None: ...
```

`emit` is thread-safe, so it can be called from library callback threads.

### Alert channel

```python
from tripwire.alerts.base import AlertChannel, AlertError, AlertMessage
from tripwire.core.plugin import PluginOptions


class NtfyOptions(PluginOptions):
    topic_url: str


class NtfyChannel(AlertChannel[NtfyOptions]):
    Options = NtfyOptions

    async def send(self, message: AlertMessage) -> None:
        # message.title / message.body are short, phone-friendly text;
        # message.report_url is the signed link; message.incident has everything.
        ...  # raise AlertError on failure
```

You can also register classes at runtime: `tripwire.core.registry.alerts.register("ntfy", NtfyChannel)`.

## 2. Any-language collectors (subprocess + JSON lines)

The built-in `subprocess` collector runs an executable (without a shell) and
reads **one JSON object per line** from its stdout. This is the supported way
to write collectors in Go, Rust, C, shell, etc.

```yaml
collectors:
  - type: subprocess
    name: rust-usb
    options:
      command: ["/usr/local/bin/tripwire-usb", "--json"]
      env: { RUST_LOG: info }
      restart: true             # restart with exponential backoff if it exits
      max_backoff_seconds: 300
```

### Contract v1

Each stdout line is a JSON object, at most 64 KiB, UTF-8:

| field      | type            | required | notes |
|------------|-----------------|----------|-------|
| `v`        | int             | no (=1)  | contract version; other values are rejected |
| `type`     | string          | no       | `"heartbeat"` lines are ignored |
| `summary`  | string          | **yes**  | one line, human readable |
| `kind`     | string          | no       | one of `file_accessed`, `file_modified`, `file_deleted`, `file_moved`, `file_created`, `beacon_hit`, `custom` (unknown → `custom`) |
| `severity` | string          | no       | `low`, `medium` (default), `high`, `critical` |
| `path`     | string \| null  | no       | affected path, if any |
| `decoy_id` | string \| null  | no       | manifest decoy id, if known |
| `details`  | object          | no       | free-form, stored encrypted in the report |

Example:

```json
{"v":1,"kind":"custom","severity":"high","summary":"Decoy SMB share accessed","details":{"client":"10.0.0.7"}}
```

Rules:

- Invalid lines are logged and skipped. They never crash the agent.
- stderr is forwarded to Tripwire's log (truncated to 500 characters per line).
- On shutdown the process receives SIGTERM (Windows: `TerminateProcess`), then
  SIGKILL after 5 s.
- Collectors must stay lightweight: block on OS events rather than polling tightly.
- The same hard constraints apply as for the core project: no persistence
  tricks, no hiding, no code execution on third-party devices.

### Minimal Go example

```go
package main

import ("encoding/json"; "os"; "time")

func main() {
    enc := json.NewEncoder(os.Stdout)
    for {
        enc.Encode(map[string]any{"type": "heartbeat"})
        time.Sleep(60 * time.Second)
    }
}
```
