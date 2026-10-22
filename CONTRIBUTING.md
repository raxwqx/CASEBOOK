# Contributing

Thanks for helping make CASEBOOK more reliable. Small, test-backed changes are preferred over broad rewrites.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m compileall -q src tests
python -m unittest discover -s tests -v
```

## Pull request checklist

- Add or update tests for changed behavior.
- Keep runtime dependencies in the standard library unless a strong reason is documented.
- Preserve existing evidence; never silently overwrite source files or reports.
- Treat filenames, archive entries, JSON, and report text as untrusted input.
- Add limits and clear error messages for resource-sensitive input paths.
- Update `README.md`, `CHANGELOG.md`, or `docs/` when behavior changes.
- Use only synthetic or public-domain fixtures. Never commit live incident data, personal data, secrets, or captured credentials.
- Explain the threat model and remaining limitations in the pull request.

## Code principles

- Explicit beats implicit: report the source, hash, and interpretation separately.
- Fail closed on unsafe archive inputs.
- No network calls, automatic execution of evidence, or hidden telemetry.
- Integrity checks should report issues; they should not silently repair forensic records.
