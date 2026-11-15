# Hardened fork design

## Human input

On 15 November the operator authorized this maintained fork, relevant dependency/tool acquisition, exhaustive scoped review/patch/test cycles and extensive cross-cutting tests in restricted containers on the qualified Debian host. Document upstream differences, rationale, evidence and future risks. Document qualification results and remaining infrastructure work. No VPS deployment; continued work/deployment is a later decision.

## AI Inferred sequence

Establish source/provenance and inventory; qualify tools/runtime inputs and close archive scan gaps; patch all log producers/sinks and independent trust selectors; remediate reachable dependency defects with frozen inputs; run focused/upstream/full-stack tests; investigate manual/scanner leads and repeat affected checks. Keep precise tool/database/runtime identities and explicit residual limits. No broad ignore or absolute-security claim.

The proposed suite combines pytest/pytest-django/Hypothesis, lint/SAST, SBOM/dependency/image scans, HTTP/DAST and native TLS/compression checks. Tools require provenance/license/compatibility review. Use Bun only where Deno cannot support the workspace; lifecycle scripts stay disabled unless individually reviewed.

## Evidence

The previous audit found DRF 3.17.2, retained body/query activity logging, independent pip/botocore trust regressions and other matches. Fresh review also found the general request logger using `get_full_path()` and arbitrary user-agent data. Existing keyed-token/header tests do not close those separate paths. Backend full API/migration/HTTP/native gates, real broker/worker persistence and full Bun build/type/upstream/focused/live gates now pass within their recorded profiles. Native conditions remain reviewed and visible; complete browser/S3/RabbitMQ/beat/restore/finalJSimages/deployment remain outside passed coverage.
