# Testing and restricted runtime

## Human input

Review, patch and repeatedly test a maintained Plane fork, including changed and related paths, in restricted containers on the qualified Debian host. The review environment stays inert. VPS deployment and production-data testing are deferred.

## Supported boundary

`hardening/run_restricted.py` transfers the normal checkout's tracked/unignored files, rejects private environment files and unreviewed symlinks, verifies source hashes on both hosts, and mounts an immutable per-run snapshot. Application lanes require an exact built image ID. Rootless Podman uses non-root UID1000, no capabilities or privilege escalation, a readonly root, bounded CPU/memory/PIDs/time, no public ports and no home/authentication/SSH/engine mounts. Offline lanes use `network=none`; database/server/worker lanes use a separately inspected internal network, synthetic credentials and temporary storage. Exact task-owned cleanup preserves unrelated workloads.

`hardening/build_backend.py` builds offline from pinned Python3.12.16-slim-trixie, hash-locked binary wheels, a reproducibly patched urllib3 wheel and the verified Debian zlib security package. No candidate package source builds, lifecycle downloads or automatic production migrations run. The qualification lane installs its own hash-pinned tool/test environment, checks dependency consistency, applies real PostgreSQL migrations and executes focused/upstream tests. The supported runtime does not contain pip/ensurepip, lxml/libxml2/libxslt or SSH executables.

## Implemented suite

| Purpose | Actual tools / owning entrypoints | Boundary |
|---|---|---|
| API/contracts/properties | pytest9.2, pytest-django4.14, Hypothesis6.170.15; `qualify.py` and API tests | Real PostgreSQL15.20 migrations; selected cache controls use Valkey7.2.15; unit tasks otherwise use memory transport |
| Production HTTP | `runtime_smoke.py`, native HTTP clients | Actual image entrypoint/auth/workspace isolation/issue sanitization/parser rejection/log privacy |
| Worker/audit integration | `worker_smoke.py` | Actual API, JSON Valkey broker, prefork Celery worker and PostgreSQL; real producer/worker/database controls pass; does not cover RabbitMQ |
| TLS/trust | OpenSSL,54 public certificate/chain controls,22 native Bun transport controls | Effective backend OS/directory/certifi/botocore/gRPC stores; custom transports/JS image integration remain separate gates |
| HTTP/compression | Native CPython/urllib3 framing controls, reproducible wheel checks, bounded Python/Bun codec checks, exact zlib backport and bounded gz* failure controls | No claim that basic codec tests reproduce every cited CVE |
| SAST/lint | Bandit1.9.4, Ruff0.17.5, Trivy0.76.2 embedded misconfiguration/secret checks |74 low raw Bandit results require exact source-byte/line dispositions; raw exits retained; legacy deployment recipes still have open configuration findings |
| SBOM/SCA | Syft1.57.1, Grype0.121.3, OSV querybatch | Actual image archive plus separate Python/JS closures; package matches require applicability review |
| JavaScript | Bun1.4.4 direct pinned CLI entrypoints, `js_cli.py`, focused Bun tests | Frozen lock, no hooks/macros/Node/npm/pnpm/yarn/package executors; all workspace builds/types,65upstream tests and actual live HTTP/realtime controls pass |
| Intake | ClamAV1.5.4/db28179 (2026-11-10), trusted stdlib static scanner, manual entrypoint/archive/native-header review | Five-day signature lag; no absence-of-malware, independent binary rebuild or completed publisher-attestation claim |

## Current results

The exact image `cb9d00572e28472032dc984a543902339ad82661e56859786791ec4e7b56ba70` applied every migration and passed750 full API tests,263 overlapping focused checks,54 trust checks and86 transport/compression/helper checks in run `plane-qualification-b534d988b034`. Do not sum overlapping subsets as distinct coverage. The final-image production HTTP run also passes, including deny-by-default CORS and a fresh-process valid-origin control. A real API→Valkey broker→prefork Celery→PostgreSQL run passes on the preceding image; final source changes only the CORS default and leaves its worker/native closure unchanged. `records/verification.json` owns results, failures and source/artifact identities.

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
python3 hardening/run_restricted.py integration --backend-image cb9d00572e28472032dc984a543902339ad82661e56859786791ec4e7b56ba70
python3 hardening/run_restricted.py server --backend-image cb9d00572e28472032dc984a543902339ad82661e56859786791ec4e7b56ba70
python3 hardening/run_restricted.py worker --backend-image cb9d00572e28472032dc984a543902339ad82661e56859786791ec4e7b56ba70
python3 hardening/scan_backend.py cb9d00572e28472032dc984a543902339ad82661e56859786791ec4e7b56ba70
```

A rebuild may have a different image ID; use its actual output and bind new evidence to it. `js_cli.py build` / `js_cli.py types` are container-only entrypoints: they reject root/capabilities/missing no-new-privileges and Git checkouts. `run_javascript.py` now stages and verifies a fresh Git-listed snapshot, copies only the screened dependency directories with exact file/link identities, checks unchanged source after every phase, inspects effective isolation before execution and owns the internal Valkey lifecycle. Its complete run is `plane-js-dd09dd066885`; earlier recipes/failures remain retained. The current intake manifest is deliberately hash-pinned: a new closure requires intake/review and an identity update. Do not execute these modules on the workstation or in the inert review environment.

```sh
python3 hardening/run_javascript.py all \
  --dependencies "$PLANE_JS_DEPENDENCIES" \
  --manifest "$PLANE_JS_MANIFEST" \
  --image cb9d00572e28472032dc984a543902339ad82661e56859786791ec4e7b56ba70
```

The already-qualified binary wheel inventories are committed under `vendored/python-*-inputs*.json`; local urllib3 rebuild provenance and licenses are retained. Standalone scanner/runtime release identities are in `vendored/tool-inputs.json`. The scripts intentionally do not download, install host packages or refresh databases. Original intake receipts and tool stores remain external to the repository.
## Remaining limits

Fresh full production-backup restore, complete S3 storage/recovery, RabbitMQ/beat, browser user journeys, final JS runtime images and production rollout remain unqualified. ZAP/Schemathesis/Semgrep were not installed or run; established-tool coverage is the suite above. Scanner data and native/library reachability need continuing review. Dependency deprecations, optional tooling/type issues and failed historical fixture runs are retained; passing builds do not substitute for running the application. No VPS package update, service replacement, reboot, CSP enforcement, credential rotation or Plane item mutation is part of this fork qualification.
