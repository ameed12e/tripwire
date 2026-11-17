"""HMAC helpers for beacon tokens and signed report links.

Beacon tokens are self-authenticating: ``<decoy_id><sig>`` where ``sig`` is a
truncated HMAC of the decoy id. The server can verify a token without a shared
database, and random scanners hitting ``/t/<garbage>`` never create incidents.

Report links carry an expiry and an HMAC, so knowing an incident id alone is not
enough to read its report.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlencode

DECOY_ID_HEX = 16
TOKEN_SIG_HEX = 16
_TOKEN_RE = re.compile(rf"^[0-9a-f]{{{DECOY_ID_HEX + TOKEN_SIG_HEX}}}$")


def _mac(key: str, message: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def new_decoy_id() -> str:
    return secrets.token_hex(DECOY_ID_HEX // 2)


def make_beacon_token(key: str, decoy_id: str) -> str:
    return decoy_id + _mac(key, f"beacon:{decoy_id}")[:TOKEN_SIG_HEX]


def verify_beacon_token(key: str, token: str) -> str | None:
    """Return the decoy id if the token is authentic, else ``None``."""
    token = token.lower()
    if not _TOKEN_RE.match(token):
        return None
    decoy_id, sig = token[:DECOY_ID_HEX], token[DECOY_ID_HEX:]
    expected = _mac(key, f"beacon:{decoy_id}")[:TOKEN_SIG_HEX]
    return decoy_id if hmac.compare_digest(sig, expected) else None


def beacon_url(public_url: str, key: str, decoy_id: str, suffix: str = "") -> str:
    """Public URL that a beacon decoy fetches. ``suffix`` (e.g. ``.png``) is cosmetic."""
    return f"{public_url.rstrip('/')}/t/{make_beacon_token(key, decoy_id)}{suffix}"


def sign_report(key: str, incident_id: str, expires_at: int) -> str:
    return _mac(key, f"report:{incident_id}:{expires_at}")


def report_url(public_url: str, key: str, incident_id: str, ttl_hours: int) -> str:
    expires_at = int(time.time()) + ttl_hours * 3600
    query = urlencode({"exp": expires_at, "sig": sign_report(key, incident_id, expires_at)})
    return f"{public_url.rstrip('/')}/r/{incident_id}?{query}"


def verify_report(key: str, incident_id: str, expires_at: int, sig: str) -> bool:
    if expires_at < int(time.time()):
        return False
    return hmac.compare_digest(sign_report(key, incident_id, expires_at), sig)


class RateLimiter:
    """Sliding-window limiter keyed by client IP (in memory, thread-safe)."""

    def __init__(self, max_hits: int, window_seconds: float = 60.0) -> None:
        self.max_hits = max_hits
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.max_hits:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory under scanning
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True
