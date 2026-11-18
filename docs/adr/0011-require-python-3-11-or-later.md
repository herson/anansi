# ADR-0011: Require Python 3.11 or later

## Status

Accepted

## Date

2026-11-18

## Context

[ADR-0010](0010-pin-dependencies-with-a-hashed-universal-lockfile-compiled-by-uv.md) locks dependencies for every Python version CI tests: 3.10, 3.11 and 3.12. Where a package needs an older version on 3.10, the lock pins both, with an environment marker for each.

On 2026-11-18, the first CI run of PR #6 failed on Python 3.10. pip-audit found 44 known vulnerabilities in the 3.10 pins:

| Package | 3.10 pin | Fixed in | Fixed version needs |
|---|---|---|---|
| pillow (through fpdf2, for `--pdf`) | 12.3.0 | 13.0.0 | Python ≥ 3.11 |
| dnspython (for `--dns`) | 2.8.0 | 2.9.0, 2.9.2 | Python ≥ 3.11 |

The 3.11 and 3.12 pins are already the fixed versions and pass the audit. On 3.10 no fixed release can be installed, so re-locking does not help.

Python 3.10 reached end of life in October 2026, so it gets no security fixes either. The Docker image already uses 3.12.

## Decision Drivers

- No installation should ship a dependency with known vulnerabilities.
- pip-audit in CI must stay a blocking check, not one with exceptions.
- Dependencies are dropping 3.10, so more 3.10 pins will fall behind.
- Support no Python version that its maintainers no longer support.

## Options Considered

### Option 1: Keep 3.10 and skip these advisories on 3.10

- **Good:** Users on 3.10 can still install.
- **Bad:**
  - 3.10 installs ship pillow and dnspython with known vulnerabilities, and `--pdf` and `--dns` parse untrusted input with them.
  - Every new advisory affecting a package that has dropped 3.10 means another exception. The audit stops meaning "no known vulnerabilities".

### Option 2: Require Python 3.11 or later

- **Good:**
  - Every install gets the fixed versions, and pip-audit stays blocking with no exceptions.
  - The lock loses its separate 3.10 pins, so it is smaller and easier to read.
- **Bad:** Users on 3.10 must upgrade Python. 3.10 is end of life, and the Docker image is unaffected.

## Decision

We will use **Option 2**: Python 3.11 is the minimum supported version.

This replaces only the lock range in ADR-0010 (`--python-version 3.10` becomes `3.11`). ADR-0010's decision to lock with uv stands. Option 1 would leave a security tool shipping libraries with known vulnerabilities, for a Python version that no longer gets security fixes.

Implementation, after this ADR is accepted:

- `scripts/lock-requirements.sh`: set `PYTHON_MIN="3.11"`, then re-lock.
- CI matrix: 3.11, 3.12.
- `mypy.ini`: `python_version = 3.11`.
- README: badge and requirements say 3.11+, and CI is described as running on 3.11 and 3.12.
- `tests/infra/test_packaging.py`: remove the 3.10 workaround for `packages_distributions()`, and read packages the way 3.11+ does.
- A contract test that the lock script, the CI matrix and mypy all name the same minimum version, so they cannot drift apart.

## Consequences

### Positive

- No known-vulnerable pins in any supported install.
- One set of pins for every supported version, where packages allow it.

### Negative / Trade-offs

- Breaking change for users on 3.10. CHANGELOG lists it under "Changed (breaking)".

### Risks

- When 3.11 reaches end of life (October 2027), the same failure will come back. The minimum then moves with a new ADR, and the contract test makes it one change in each of three places.

## Links

- Partly supersedes [ADR-0010](0010-pin-dependencies-with-a-hashed-universal-lockfile-compiled-by-uv.md) (the 3.10 lock range only)
- PR #6, CI run 44383741741
- [Python release status](https://devguide.python.org/versions/)
