# ANBridge

- All project files and temporary build/test outputs belong under `/root/anbridge`.
- Use the Go standard library; add a dependency only when a concrete requirement justifies it.
- Do not change host Nginx configuration or install/start system services during development.
- Run tests with `TMPDIR`, `GOCACHE`, and `GOMODCACHE` inside the project.
- Treat uploaded PEM and API payloads as untrusted. Never accept shell commands, paths,
  Nginx configuration fragments, or probe destinations from an HTTP request.
- Do not log tokens, private keys, or request bodies.
- A deployment succeeds only after a fresh TLS connection observes the expected certificate.
- Preserve the last working configuration. Cover failures, recovery, tenant isolation, and
  real Nginx behavior with tests before claiming those paths work.
