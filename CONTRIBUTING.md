# Contributing

Thanks for helping improve vncsnatch.

## Development setup
- Build: `make`
- Clean-room tests: `make test-cleanroom`

## Workflow
- Keep changes focused and small.
- Add tests for new behavior where practical.
- Run `make` and `make test-cleanroom` before submitting.

## Code style
- Follow existing C style (brace placement, naming, and spacing).
- Prefer clear, defensive error handling.
- Keep output quiet by default; add `-v` hooks for verbose logs.

## Security and ethics
- Do not add features that bypass authorization or violate laws.
- Avoid hardcoded secrets or targets.

## Reporting issues
- Include OS, build output, and command line used.
- Provide a minimal repro case when possible.
