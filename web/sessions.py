"""In-memory browser sessions for the dashboard (ADR-0001)."""
import secrets
import threading
import time
from typing import Callable

DEFAULT_TTL_SECONDS = 12 * 60 * 60


class SessionStore:
    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._expiry: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self) -> str:
        """Issue a new random session token."""
        token = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._expiry = {t: exp for t, exp in self._expiry.items() if exp > now}
            self._expiry[token] = now + self._ttl
        return token

    def is_valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            expiry = self._expiry.get(token)
        return expiry is not None and self._clock() < expiry

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._expiry.pop(token, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._expiry)
