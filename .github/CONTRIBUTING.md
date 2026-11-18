# Contributing to Anansi

First off, thank you for considering contributing to Anansi! It's people like you that make Anansi such a great tool.

## 1. Where to start?
- **Found a bug?** Open a [Bug Report](https://github.com/herson/anansi/issues/new?template=bug_report.md).
- **Have a feature idea?** Open a [Feature Request](https://github.com/herson/anansi/issues/new?template=feature_request.md).
- **Want to code?** Check out the [open issues](https://github.com/herson/anansi/issues).

## 2. Fork & Clone
1. Fork the repo on GitHub.
2. Clone it locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/anansi.git
   cd anansi
   ```
3. Create a branch:
   ```bash
   git checkout -b my-new-feature
   ```

## 3. Development Environment
Anansi needs Python 3.11 or later. We recommend using a virtual environment.

```bash
# Create venv
python3 -m venv venv
source venv/bin/activate

# Install the locked runtime and development dependencies
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
```

### Changing dependencies
The `requirements*.txt` files are hashed lockfiles generated from the `requirements*.in` files ([ADR-0010](../docs/adr/0010-pin-dependencies-with-a-hashed-universal-lockfile-compiled-by-uv.md)). Edit the `.in` file, never the `.txt`, then re-lock with [uv](https://docs.astral.sh/uv/) and commit both files:

```bash
scripts/lock-requirements.sh                          # after editing a .in file
scripts/lock-requirements.sh --upgrade-package NAME   # update one package, e.g. for a security fix
scripts/lock-requirements.sh --upgrade                # update everything
```

CI fails if a lockfile doesn't match its `.in` file.

## 4. Run Tests
We use `unittest`. Please ensure all tests pass before submitting.

```bash
python -m unittest discover -s tests -t .
```

## 5. Submit a Pull Request
1. Push your branch to GitHub.
2. Open a Pull Request (PR) against the `main` branch.
3. Fill out the PR template checklist.
4. Wait for the CI checks to pass.

## 6. Code Style
- Follow **PEP 8**.
- Add docstrings to your functions/classes.
- Be respectful and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

Happy Hacking! 🕸️
