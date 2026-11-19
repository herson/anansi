"""Web directory discovery: a rate-limited, opt-in path scanner (ADR-0012)."""
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

import requests

from domain.findings import PathFinding

DEFAULT_RATE = 10            # requests per second
MAX_RATE = 50
MAX_RETRY_AFTER = 60         # seconds; a server can't stall the scan for longer per pause
MAX_TRIES = 3                # per path while the server keeps answering 429/503
MAX_CONSECUTIVE_ERRORS = 3   # connection errors in a row before the scan stops
MAX_BODY_BYTES = 1024 * 1024
TIMEOUT = 10                 # seconds
USER_AGENT = "Anansi directory scanner (+https://github.com/herson/anansi)"

_THROTTLED = (429, 503)
_CHUNK = 65536

# Written for Anansi, so its license is the project's.
DEFAULT_WORDLIST = (
    "admin/", "administrator/", "admin.php", "login", "login.php", "signin", "logout", "register",
    "dashboard/", "panel/", "cpanel/", "manager/", "console/", "portal/", "user/", "users/",
    "account/", "profile/", "api/", "api/v1/", "api/v2/", "graphql", "swagger/", "swagger.json",
    "openapi.json", "docs/", "redoc", "health", "healthz", "status", "metrics", "server-status",
    "server-info", "info.php", "phpinfo.php", "test/", "test.php", "dev/", "staging/", "beta/",
    "old/", "new/", "backup/", "backups/", "backup.zip", "backup.tar.gz", "site.zip", "db.sql",
    "dump.sql", "database.sql", "config/", "config.php", "config.json", "config.yml", "settings.py",
    "web.config", ".env", ".env.bak", ".git/", ".git/HEAD", ".gitignore", ".svn/", ".hg/",
    ".DS_Store", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "security.txt", ".well-known/security.txt", "readme.html", "README.md", "CHANGELOG.md",
    "LICENSE", "composer.json", "package.json", "Dockerfile", "docker-compose.yml", "uploads/",
    "upload/", "files/", "static/", "assets/", "images/", "media/", "tmp/", "temp/", "logs/",
    "log/", "error_log", "debug/", "cgi-bin/", "scripts/", "includes/", "vendor/", "node_modules/",
    "wp-admin/", "wp-login.php", "wp-content/", "xmlrpc.php", "phpmyadmin/", "adminer.php",
    "jenkins/", "actuator/", "actuator/health", "console", "shell", "webdav/",
)


@dataclass
class DirectoryReport:
    url: str
    found: list[PathFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Answer:
    status: int
    length: int
    location: str


class DirectoryScanner:
    """Requests each wordlist path under one URL and reports those that differ from a missing page.

    Raises ValueError for settings outside the limits ADR-0012 sets.
    """

    def __init__(self, base_url: str, wordlist: Iterable[str] | None = None, rate: object = DEFAULT_RATE,
                 verify_tls: object = True, session: requests.Session | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 random_path: Callable[[], str] = lambda: secrets.token_hex(16)) -> None:
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 < rate <= MAX_RATE:
            raise ValueError(f"dirs_rate must be a number above 0 and at most {MAX_RATE}, not {rate!r}")
        if not isinstance(verify_tls, bool):
            raise ValueError(f"dirs_verify_tls must be true or false, not {verify_tls!r}")
        self.base_url = base_url.rstrip("/") + "/"
        self.wordlist = list(DEFAULT_WORDLIST if wordlist is None else wordlist)
        self.delay = 1 / rate
        self.verify_tls = verify_tls
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._sleep = sleep
        self._random_path = random_path
        self._requested = False
        self._errors_in_a_row = 0

    def scan(self) -> DirectoryReport:
        report = DirectoryReport(self.base_url)
        baseline = []
        for _ in range(2):
            answer = self._fetch(self._random_path(), report)
            if answer is not None:
                baseline.append(answer)
        for path in self._paths():
            if self._errors_in_a_row >= MAX_CONSECUTIVE_ERRORS:
                report.errors.append(f"stopped after {MAX_CONSECUTIVE_ERRORS} connection errors in a row")
                break
            answer = self._fetch(path, report)
            if answer is not None and answer.status != 404 and not _looks_missing(answer, baseline):
                report.found.append(PathFinding(self.base_url + path, answer.status, answer.length,
                                                answer.location))
        return report

    def _paths(self) -> Iterable[str]:
        for entry in self.wordlist:
            path = entry.strip().lstrip("/")
            if not path or path.startswith("#"):
                continue
            if ".." in path.split("/"):
                logging.warning("Skipping wordlist entry %r: it climbs above the URL given", entry)
                continue
            yield path

    def _fetch(self, path: str, report: DirectoryReport) -> _Answer | None:
        url = self.base_url + path
        for _ in range(MAX_TRIES):
            self._wait()
            try:
                response = self.session.get(url, allow_redirects=False, timeout=TIMEOUT,
                                            verify=self.verify_tls, stream=True)
            except requests.RequestException as e:
                self._errors_in_a_row += 1
                report.errors.append(f"{url}: {e}")
                return None
            self._errors_in_a_row = 0
            try:
                retry_after = _retry_after(response)
                if retry_after is None:
                    return _Answer(response.status_code, _body_length(response),
                                   response.headers.get("Location", ""))
            finally:
                response.close()
            self._sleep(retry_after)
        report.errors.append(f"{url}: still throttled after {MAX_TRIES} tries, skipped")
        return None

    def _wait(self) -> None:
        if self._requested:
            self._sleep(self.delay)
        self._requested = True


def _retry_after(response: requests.Response) -> float | None:
    """Seconds to pause before retrying, or None if the server isn't asking for a pause."""
    if response.status_code not in _THROTTLED:
        return None
    value = response.headers.get("Retry-After", "")
    if not value.strip().isdigit():
        return None
    return min(int(value), MAX_RETRY_AFTER)


def _body_length(response: requests.Response) -> int:
    length = 0
    for chunk in response.iter_content(_CHUNK):
        length += len(chunk)
        if length >= MAX_BODY_BYTES:
            return MAX_BODY_BYTES
    return length


def _looks_missing(answer: _Answer, baseline: list[_Answer]) -> bool:
    """True if answer matches the server's reply for a path that cannot exist (a soft 404)."""
    return any(answer.status == missing.status and
               abs(answer.length - missing.length) <= max(16, missing.length // 20)
               for missing in baseline)
