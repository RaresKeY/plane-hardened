# Upstream maintenance

## Human input

Maintain a hardened fork with clear differences/rationale, extensive cross-cutting tests and future maintenance risks. Restricted qualified Debian host testing only; the operator decides whether to continue/deploy after the report.

## Observed implementation

The normal checkout is `plane-hardened`, branch `hardened`, based on upstream v1.4.3 commit `37a15d99231042b3ff5a4401fed479fdbec9effe`. `upstream` fetches `https://github.com/makeplane/plane.git`; `origin` is `https://github.com/RaresKeY/plane-hardened.git`. The GitHub fork was created on 15 November. On 16 November the operator authorized updating the fork and pushing the hardened branch. `hardened` is the fork's default branch; `preview` mirrors upstream development separately. Original license/copyright files remain.

The 16 November upstream check found master/latest release still at the pinned v1.4.3 base. The fork's `preview` advanced four commits to `258e03cbcf4db5cdb8c2708b8fa64391927c4e5e` after inert intake and delta review. This development update is reference-only: no execution, dependency activation or merge into `hardened` was performed. It includes intake-update authorization, connected-account token omission and permission-before-cache-invalidation fixes; their applicability/backport to the release-based hardened branch remains unqualified. Do not mistake syncing `preview` for incorporating these changes into the tested release branch.

GitHub Actions are disabled for this fork. Upstream push workflows can build/publish images and acquire unreviewed tool/dependency inputs; the restricted local qualification remains the verification evidence. Enabling or replacing CI needs a separate review of its execution and publication behavior.

`PATCHES.md` distinguishes proposed, implemented and verified changes, their rationale and test/maintenance obligations. Incoming tags/artifacts require intake and exact identity before integration; never automatically pull a moving upstream branch. Do not commit generated outputs, credentials or private data.

## Verification and AI Inferred

Imported source files matched the prior static-review manifest and Git reported no initial difference from the pinned upstream tree. The bounded backend and Bun source/dependency qualification gates pass; records bind exact inputs, corrected failures and residual limits. Source publication does not authorize VPS deployment, image publication, PRs or advisory publication. Prefer a small reviewable patch set and supported dependency lines; alternate-runtime compatibility, archived MinIO, schemas and scanning tools create fork-owned maintenance obligations.
