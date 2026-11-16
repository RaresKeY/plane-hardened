# Testing and restricted runtime

## Human input

Review, patch and repeatedly test a maintained Plane fork, including changed and related paths, in restricted containers on the qualified Debian host. The review environment stays inert. VPS deployment and production-data testing are deferred.

## Supported boundary

`hardening/run_restricted.py` transfers the normal checkout's tracked/unignored files, rejects private environment files and unreviewed symlinks, verifies source hashes on both hosts, and mounts an immutable per-run snapshot. Application lanes require an exact built image ID. Rootless Podman uses non-root UID1000, no capabilities or privilege escalation, a readonly root, bounded CPU/memory/PIDs/time, no public ports and no home/authentication/SSH/engine mounts. Offline lanes use `network=none`; database/server/worker lanes use a separately inspected internal network, synthetic credentials and temporary storage. Exact task-owned cleanup preserves unrelated workloads.

`hardening/build_backend.py` builds offline from pinned Python3.12.16-slim-trixie, hash-locked binary wheels, a reproducibly patched urllib3 wheel and the verified Debian zlib security package. No candidate package source builds, lifecycle downloads or automatic production migrations run. The qualification lane installs its own hash-pinned tool/test environment, checks dependency consistency, applies real PostgreSQL migrations and executes focused/upstream tests. The supported runtime does not contain pip/ensurepip, lxml/libxml2/libxslt or SSH executables.

## Implemented suite

| Purpose | Actual tools / owning entrypoints | Boundary |
|---|---|---|
| API/contracts/properties | pytest9.2, pytest-django4.14, Hypothesis6.170.15; `qualify.py` and API tests | Real PostgreSQL15.20 migrations; full-API lanes run the upstream-backport contract gate before the complete suite; cache controls use Valkey7.2.15; unit tasks otherwise use memory transport |
| Production HTTP | `runtime_smoke.py`, native HTTP clients | Actual image entrypoint/auth/workspace isolation/issue sanitization/parser rejection/log privacy; signed database sessions, provider-token omission, intake permissions and real shared-cache retention/invalidation |
| Worker/audit integration | `worker_smoke.py` | Actual API, JSON Valkey broker, prefork Celery worker and PostgreSQL; real producer/worker/database controls pass; does not cover RabbitMQ |
| TLS/trust | OpenSSL,54 public certificate/chain controls,22 native Bun transport controls | Effective backend OS/directory/certifi/botocore/gRPC stores; custom transports/JS image integration remain separate gates |
| HTTP/compression | Native CPython/urllib3 framing controls, reproducible wheel checks, bounded Python/Bun codec checks, exact zlib backport and bounded gz* failure controls | No claim that basic codec tests reproduce every cited CVE |
| SAST/lint | Bandit1.9.4, Ruff0.17.5, Trivy0.76.2 embedded misconfiguration/secret checks |74 low raw Bandit results require exact source-byte/line dispositions; raw exits retained; legacy deployment recipes still have open configuration findings |
| SBOM/SCA | Syft1.57.1, Grype0.121.3, OSV querybatch | Actual image archive plus separate Python/JS closures; package matches require applicability review |
| JavaScript | Bun1.4.4 direct pinned CLI entrypoints, `js_cli.py`, focused Bun tests | Frozen lock, no hooks/macros/Node/npm/pnpm/yarn/package executors; all workspace builds/types,65upstream tests and actual live HTTP/realtime controls pass |
| Intake | ClamAV1.5.4/db28179 (2026-11-10), trusted stdlib static scanner, manual entrypoint/archive/native-header review | Five-day signature lag at initial qualification, six days at backport intake; no absence-of-malware, independent binary rebuild or completed publisher-attestation claim |

## Current results

The current image `3aa5f9a6b1fb4bad4c9a25ad1accd34de1e99fd0c71e16d62b6bcb16b3c05b5c` applied every migration and passed779 full API tests,29 targeted backport tests,263 focused checks,54 trust checks and86 transport/compression/helper checks in run `plane-qualification-59a86f0d68ab`. The29 backport tests and263 focused checks overlap the full suite; do not sum them as distinct coverage. All recorded test groups have zero failures/errors/skips. The initial backport run was interrupted after8 fixture failures/137passes: unique factory usernames fixed the release's blank-username collision, and AST-preserving formatting fixed one test lint error. Those failed results remain recorded.

Actual-image production HTTP run `plane-qualification-3293b54f91c9` passes9 groups of checks, including signed session-cookie authentication, connected-account token omission, intake creator/admin/member behavior and real Valkey cache preservation/invalidation. Existing HTML/log/privacy/parser/CORS controls still pass. The image's732 API build inputs match the checkout;The historical comparison checked5358 non-Markdown/non-record source/configuration files against the final API-run snapshot; launcher routing and lock comments changed during the later privacy cleanup. A prior real API→Valkey broker→prefork Celery→PostgreSQL run remains evidence for the unchanged audit-worker closure; worker and JavaScript execution were not repeated for these backend-only backports. `records/verification.json` owns exact source/artifact identities and historical results.

All JavaScript workspace builds and type checks pass under Bun, including web/admin/space/live. The frozen lock's1580 npm package/version queries returned two matches: the two retained packages with tested source/emitted-entrypoint patches. Prototype controls reproduced the issue before patching and pass after patching (37 cases in each mode).44 shared logger/error/image-policy controls pass;4 real PDF render controls preserve valid JPEGs, honor noAssets and reject raw URL/file sources without trap requests. The complete JavaScript launcher passes32live and33codemod upstream tests through actual Vitest/Bun,48focused tests,37patched prototype controls,22TLS controls and the real HTTP/PDF/two-client realtime/auth-failure/log-privacy test. Complete browser/storage/runtime-image qualification remains open.

The latest native scan uses Grype database v6.1.10 built2026-11-15T06:19:39Z. The signed Debian zlib update removed the available distro-fix matches. The current image has209 raw matches across96 advisory IDs, no Critical matches,59 High matches. These are not209 demonstrated Plane vulnerabilities, and this is not a clean finding gate. The earlier Debian12 image had356 matches including3 Critical package entries; the intermediate Debian13 image had212. Preserve raw reports and distinguish distro backports, conditional utilities/APIs, wrong-range records and unresolved findings. `scan_backend.py` verifies the qualified database archive, imports a private cache, mounts it readonly for scanning and saves native inventory/Syft/CycloneDX/Grype evidence. Import expands/indexes the SQLite database, so pin the reviewed archive, not the resulting cache bytes.

## Reproduce on this workstation

The existing external-intake receipts and dedicated session SSH agent are prerequisites. Operator routing is deliberately absent from Git. Export `PLANE_QUALIFICATION_HOST` (a reviewed SSH alias or user@hostname) and `PLANE_QUALIFICATION_ROOT` (the absolute qualification directory on that host) in the local session. JavaScript runs also require `PLANE_QUALIFICATION_INTAKE_ROOT`, the reviewed remote intake parent; dependency directories must be direct `plane-js-*` children. Missing or unsafe settings fail before remote activity. Host-key checking, batch authentication, manifest identities and container restrictions remain mandatory.

Set `PLANE_WHEELS`, `PLANE_ZLIB_DEB`, `PLANE_JS_DEPENDENCIES` and `PLANE_JS_MANIFEST` to already-screened inputs. Keep actual machine names, home paths and profiles outside version control. These commands acquire no dependencies and perform no deployment:

```sh
python3 hardening/build_backend.py \
  --wheels "$PLANE_WHEELS" \
  --manifest vendored/python-production-inputs.json \
  --zlib-deb "$PLANE_ZLIB_DEB"
python3 hardening/run_restricted.py integration --backend-image 3aa5f9a6b1fb4bad4c9a25ad1accd34de1e99fd0c71e16d62b6bcb16b3c05b5c
python3 hardening/run_restricted.py server --backend-image 3aa5f9a6b1fb4bad4c9a25ad1accd34de1e99fd0c71e16d62b6bcb16b3c05b5c
python3 hardening/run_restricted.py worker --backend-image 3aa5f9a6b1fb4bad4c9a25ad1accd34de1e99fd0c71e16d62b6bcb16b3c05b5c
python3 hardening/scan_backend.py 3aa5f9a6b1fb4bad4c9a25ad1accd34de1e99fd0c71e16d62b6bcb16b3c05b5c
```

A rebuild may have a different image ID; use its actual output and bind new evidence to it. `js_cli.py build` / `js_cli.py types` are container-only entrypoints: they reject root/capabilities/missing no-new-privileges and Git checkouts. `run_javascript.py` now stages and verifies a fresh Git-listed snapshot, copies only the screened dependency directories with exact file/link identities, checks unchanged source after every phase, inspects effective isolation before execution and owns the internal Valkey lifecycle. Its complete run is `plane-js-dd09dd066885`; earlier recipes/failures remain retained. The current intake manifest is deliberately hash-pinned: a new closure requires intake/review and an identity update. Do not execute these modules on the workstation or in the inert review environment.

```sh
python3 hardening/run_javascript.py all \
  --dependencies "$PLANE_JS_DEPENDENCIES" \
  --manifest "$PLANE_JS_MANIFEST" \
  --image 3aa5f9a6b1fb4bad4c9a25ad1accd34de1e99fd0c71e16d62b6bcb16b3c05b5c
```

The already-qualified binary wheel inventories are committed under `vendored/python-*-inputs*.json`; local urllib3 rebuild provenance and licenses are retained. Standalone scanner/runtime release identities are in `vendored/tool-inputs.json`. The scripts intentionally do not download, install host packages or refresh databases. Original intake receipts and tool stores remain external to the repository.

`hardening/test_operator_config.py` covers routing, unsafe host/path inputs, explicit intake boundaries, CLI failure behavior and self-contained remote programs using standard-library unittest. Execute it in a restricted container with these launcher modules mounted readonly, using `python -m unittest -v test_operator_config` from the mounted hardening directory. Privacy cleanup changes launcher routing and lock comments; the earlier whole-snapshot equality is historical. Application source and dependency payloads remain byte-for-byte or comment-insensitively unchanged, respectively; see the scoped cleanup record.

## Remaining limits

Fresh full production-backup restore, complete S3 storage/recovery, RabbitMQ/beat, browser user journeys, final JS runtime images and production rollout remain unqualified. ZAP/Schemathesis/Semgrep were not installed or run; established-tool coverage is the suite above. Scanner data and native/library reachability need continuing review. Dependency deprecations, optional tooling/type issues and failed historical fixture runs are retained; passing builds do not substitute for running the application. No VPS package update, service replacement, reboot, CSP enforcement, credential rotation or Plane item mutation is part of this fork qualification.
