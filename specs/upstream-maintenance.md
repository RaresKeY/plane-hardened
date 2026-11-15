# Upstream maintenance

## Human input

Maintain a hardened fork with clear differences/rationale, extensive cross-cutting tests and future maintenance risks. Restricted qualified Debian host testing only; the operator decides whether to continue/deploy after the report.

## Observed implementation

The normal checkout is `plane-hardened`, branch `hardened`, based on upstream v1.4.3 commit `37a15d99231042b3ff5a4401fed479fdbec9effe`. `upstream` fetches `https://github.com/makeplane/plane.git`; `origin` is `https://github.com/RaresKeY/plane-hardened.git`. The GitHub fork was created on 15 November; hardened changes have not yet been pushed. Original license/copyright files remain.

`PATCHES.md` distinguishes proposed, implemented and verified changes, their rationale and test/maintenance obligations. Incoming tags/artifacts require intake and exact identity before integration; never automatically pull a moving upstream branch. Do not commit generated outputs, credentials or private data.

## Verification and AI Inferred

Imported source files matched the prior static-review manifest and Git reported no initial difference from the pinned upstream tree. The bounded backend and Bun source/dependency qualification gates pass; records bind exact inputs, corrected failures and residual limits. The complete hardened fork remains local pending the operator's publication/continuation decision. Prefer a small reviewable patch set and supported dependency lines; alternate-runtime compatibility, archived MinIO, schemas and scanning tools create fork-owned maintenance obligations.
