# Maintained hardened fork

- Read `specs/_readme.md` and relevant owning specs before changes. Current contracts belong in specs, desired behavior in design, results in `records/verification.json`, upstream differences in `PATCHES.md`. No handoff/milestone notes.
- Work in this normal checkout on `hardened`; `upstream` is makeplane/plane and `origin` is RaresKeY/plane-hardened. Intake incoming source/dependencies/tools before execution. No PR or review publication unless requested.
- The operator authorized source/dependency hardening and restricted tests on the qualified Debian host. VPS deployment, production-data use, host package/authentication changes and unrelated workload changes are deferred.
- The review environment remains inert. Candidate execution uses the owning rootless restricted launcher: no host home/credentials/SSH or engine sockets, privilege escalation or public ports; default-deny egress; bounded resources and exact task-owned cleanup.
- Never invoke Node/npm/npx/pnpm/yarn or package executors. Prefer Deno; use Bun only for repository compatibility, frozen dependencies and reviewed lifecycle scripts. The original commands below are upstream reference, superseded by these rules.
- Preserve upstream license/copyright; provenance belongs in `vendored/THIRD_PARTY_NOTICES.md`. Test changed and related paths with positive controls. Report failures/skips, scanner freshness/coverage and maintenance risks; no broad ignores or absolute-security claims.
- Finish qualification with image cleanup: retain the current qualified candidate and an explicitly required rollback only; remove superseded backend images and discarded builder stages by exact ID after checking ongoing runs and deployment references. Reusing a tag and setting ephemeral labels do not remove older images. Preserve manifests, logs and security evidence.
- Builds hold the shared Podman retention lock and label intermediates ephemeral. Cleanup takes its exclusive lock, rechecks container/build-container references and protected image ancestry, and uses non-forced exact removals. Preserve shared bases and unrelated workloads; never use blanket image/system/volume pruning or reset. Record removals, reclaimed space and retained exceptions in the existing verification record. See `specs/testing.md`.

# Upstream development guide (reference)

## Commands

- `pnpm dev` - Start all dev servers (web:3000, admin:3001)
- `pnpm build` - Build all packages and apps
- `pnpm check` - Run all checks (format, lint, types)
- `pnpm check:lint` - OxLint across all packages
- `pnpm check:types` - TypeScript type checking
- `pnpm fix` - Auto-fix format and lint issues
- `pnpm turbo run <command> --filter=<package>` - Target specific package/app
- `pnpm --filter=@plane/ui storybook` - Start Storybook on port 6006

## Code Style

- **Imports**: Use `workspace:*` for internal packages, `catalog:` for external deps
- **TypeScript**: Strict mode enabled, all files must be typed
- **Formatting**: oxfmt, run `pnpm fix:format`
- **Linting**: OxLint with shared `.oxlintrc.json` config
- **Naming**: camelCase for variables/functions, PascalCase for components/types
- **Error Handling**: Use try-catch with proper error types, log errors appropriately
- **State Management**: MobX stores in `packages/shared-state`, reactive patterns
- **Testing**: All features require unit tests, use existing test framework per package
- **Components**: Build in `@plane/ui` with Storybook for isolated development

## Backend tests (Docker)

The Django/pytest suite for `apps/api` runs in an isolated stack defined by `docker-compose-test.yml` at the repo root.

Prereq (once): `./setup.sh` — generates `apps/api/.env` from `.env.example`.

- Full suite: `docker compose -f docker-compose-test.yml up --build --abort-on-container-exit --exit-code-from api-tests`
- Subset: `docker compose -f docker-compose-test.yml run --rm api-tests pytest -m unit`
- Teardown: `docker compose -f docker-compose-test.yml down -v`

See `apps/api/tests/RUNNING_TESTS.md` for the full walkthrough and troubleshooting; see `apps/api/tests/TESTING_GUIDE.md` for test conventions and fixtures.
