# vulnerable example

Intentionally insecure sample used for fixtures and end-to-end tests.

- `app.js`: `eval` on request input (Semgrep SAST)
- `package-lock.json`: old `lodash` and `express` (Trivy SCA via the Syft SBOM)
- `config.js`: **not committed**. `scripts/make-example.sh` creates it with random,
  fake AWS and GitHub-style credentials, so no secret-shaped strings live in git.
