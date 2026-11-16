# Security policy

## Human input

Inventory recent relevant eMudhra/SSH/compression and application vulnerabilities; review, patch and extensively test changes and related paths using established tools. VPS deployment is deferred.

## Contracts

Bind every conclusion to source/artifact identities, dependency closure, tool/runtime versions, advisory database date and test boundary. Distinguish version matches, reachable defects, mitigations/not-affected paths and incomplete checks. Suppressions require precise scope, rationale and review/expiry; no blanket package-family ignore.

Credentials, query strings, arbitrary headers, bodies and user agents must not enter general or asynchronous activity logs. Preserve upstream keyed HMAC correlation and normal HTTP behavior, cover producers/consumers/failures, and do not read streaming bodies merely to log them.

External API intake updates require an active project membership and the work item's creator, project-admin or active workspace-admin authority, preserving existing guest field restrictions. Connected-account list/detail responses omit stored access, refresh and ID tokens without deleting provider credentials needed server side. For label create/update/delete, state create/default/delete and workspace leave, role checks precede cache invalidation; denied permissions must leave both stored objects and shared cache contents untouched. Valid actions must still work and invalidate their caches. These are scoped upstream backports, not a claim that every application endpoint has been audited.

CA policy compares public keys including cross-signed forms across actual effective system and independent stores. Native negative tests require positive controls; timeouts alone are inconclusive. Scheduled issuance cutoffs differ from compromised-key distrust. No TLS bypass.

Qualify candidate artifacts before their intended execution path. Bound malformed-input tests by time/memory; use task fixtures only, never public exploit targets. SSH applicability inventory does not authorize changing host authentication.

## Observed implementation and AI Inferred

The5267-file imported source matched the pinned upstream tree. ClamAV and static/manual review covered source, materialized stock-image archives, dependency payloads and qualified runtime/tool inputs; neither scanner results nor header inspection prove malware absence. The maintained Debian13 backend with three upstream security backports passes779 full API tests and the native/compression/trust gates; current raw image matches remain under review. All Bun workspace builds/types, upstream tests and actual live HTTP/PDF/realtime controls pass on their recorded unchanged-source profile; they were not repeated for the backend-only backports. Browser/storage/final-JS-image qualification remains open. Threats include anonymous/authenticated requests, cross-project access, remote assets, logged or queued secrets and supply chain. Container isolation limits impact without proving trustworthiness.

The hardened profile denies arbitrary credentialed CORS origins when no list is configured; actual-image denied/allowed-origin controls pass. Backend and shared JavaScript HTTP logs keep recognized methods, static route patterns, status/timing/outcome and necessary correlation only. The audit worker rejects old schema records, strips queued fields independently and retains the existing keyed HMAC identifier. Live error wrappers do not serialize external messages, response bodies or URLs; PDF retry/controller failures omit causes. These changes do not remove historical database/log/backup content or fix plaintext API-token storage/scopes.

PDF rendering accepts only bounded JPEG data prepared for an authorized asset UUID, never document URL/file/object sources. Image download origins come from operator-only `PDF_ASSET_ORIGINS` (empty denies downloads), require exact HTTP(S) origin matches, omit credentials, reject redirects, abort at8seconds and bound downloaded/output bytes and decoded pixels. An explicitly allowed internal storage origin is a trusted service boundary; this is not a DNS-rebinding defense for attacker-controlled origins. External/inline document images and unresolved assets are omitted.64 images/10000 visited nodes/depth100 bound extraction; the renderer and other document/native formats still require broader resource review.

Strict response-framing patches cover pinned CPython3.12.16 and urllib3: hexadecimal-only chunk sizes, CRLF boundaries, a64KiB urllib3 trailer cap and no hostile chunk text in transport errors. The private wheel version is2.8.0+plane.2; its public runtime compatibility string remains2.8.0 for Requests, while distribution metadata, `_version.__plane_revision__` and `plane_patch.json` carry exact fork identity. Source-hash mismatch fails the patch build. This is a maintained backport, not an upstream release or an assigned new urllib3 CVE.

## Dated trust policy

`hardening/trust/policy.json` currently contains20 SPKI identities: eight compromised ECDSA intermediate keys, six November revoked RSA TLS intermediates, five eMudhra root keys and the AAA Certificate Services root key. AAA is a cross-sign issuer, not a demonstrated compromised key. Its removal is a deliberately broad root-only defense for clients that cannot consume intermediate revocations; it can also break unrelated valid chains through that root. Whole-G1 removal is a conservative fork choice stricter than browser SCTNotAfter transitions and may break legitimate existing G1 endpoints. It does not assert that all root keys were demonstrated compromised. Two RSA code-signing intermediate byte fixtures are unavailable; exact certificate fingerprints are recorded and their RootCSG2 issuer is blocked. The built backend filters and checks OS/directory/certifi/botocore/gRPC stores and removes pip/ensurepip. Public chain tests and22 native Bun TLS controls pass. Final JS service integration and every alternate custom transport remain unqualified. Never infer effective trust from merely having this file or passing the standalone tests.
