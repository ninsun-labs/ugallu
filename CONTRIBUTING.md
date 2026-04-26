# Contributing to ugallu

Thanks for your interest. `ugallu` is in pre-alpha; the architecture is in flux and contributions are welcome but coordination via issues is preferred for non-trivial changes.

## Sign-off (DCO)

All commits **must** be signed off:

```bash
git commit -s -m "your message"
```

This certifies you have the right to submit the contribution under Apache-2.0 (Developer Certificate of Origin). CI enforces this on every PR.

## License

By contributing, you agree your contributions are licensed under the Apache License, Version 2.0.

## Code style

- Go: `gofumpt` + `goimports` + `golangci-lint` strict config
- Comments and identifiers in English; technical, concise
- Conventional Commits format for commit messages: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- No emojis in code, comments, or commit messages
- Documentation lives in `docs/`

## Workflow

1. Open an issue for non-trivial changes (architecture, new operators, breaking changes)
2. Fork, branch from `main`, name branches like `feat/<short>` or `fix/<short>`
3. Implement, sign off all commits
4. Pass CI: build + test + lint + DCO
5. Open PR, link the issue, wait for review

## Tests

- Unit tests live next to source (`*_test.go`)
- Integration in `<module>/test/integration/`
- E2E in `tests/e2e/`
- Use `testcontainers-go` for OpenBao, MinIO/SeaweedFS, Rekor in CI
- Coverage targets enforced per module in CI

## Generated code

Generated files (`zz_generated.deepcopy.go`, proto, CRD YAML) are committed. Run `task generate` after changing types or proto.

## Reporting bugs

Use GitHub Issues with the bug template. For security issues, see [SECURITY.md](SECURITY.md).
