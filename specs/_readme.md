# Hardened Plane specs

Base: upstream v1.4.3 commit `37a15d99231042b3ff5a4401fed479fdbec9effe`. The operator authorized review, source/dependency fixes and restricted tests on the qualified Debian host; VPS deployment is deferred. Upstream applications are web/admin/space/live and Django API/Celery, with PostgreSQL/cache/broker/S3/proxy dependencies.

| Spec | Owning sources | Read when |
|---|---|---|
| [Maintenance](upstream-maintenance.md) | Git, `PATCHES.md`, provenance | Updating upstream or assessing fork differences |
| [Security](security-policy.md) | Middleware/tasks, dependencies, hardening tools | Changing security behavior, trust, dependency or finding disposition |
| [Testing](testing.md) | Hardening runner, application tests, verification | Running checks, operating restricted tests or assessing evidence |

[Design](../design/security-hardening.md) owns desired work; [verification](../records/verification.json) owns actual results; [research](../research/current-vulnerabilities.md) owns the attributed project snapshot.

JavaScript dependencies use the root package.json workspace/catalog and bun.lock; the original pnpm inputs are retained under vendored/upstream as static reference. All workspace build/type gates and scoped backend/live/worker qualification pass. See testing and verification for exact artifact identities and the remaining browser/storage/transport/restore/image/deployment limits.
