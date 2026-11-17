# Upstream maintenance

## Human input

Maintain a hardened fork with clear differences/rationale, extensive cross-cutting tests and future maintenance risks. Restricted qualified Debian host testing only; the operator decides whether to continue/deploy after the report.

## Observed implementation

The normal checkout is `plane-hardened`, branch `hardened`, based on upstream v1.4.3 commit `37a15d99231042b3ff5a4401fed479fdbec9effe`. `upstream` fetches `https://github.com/makeplane/plane.git`; `origin` is `https://github.com/RaresKeY/plane-hardened.git`. The GitHub fork was created on 15 November. On 16 November the operator authorized updating the fork and pushing the hardened branch. `hardened` is the fork's default branch; `preview` mirrors upstream development separately. Original license/copyright files remain.

The 16 November upstream check found master/latest release still at the pinned v1.4.3 base. The fork's `preview` advanced four commits to `258e03cbcf4db5cdb8c2708b8fa64391927c4e5e` after inert intake and delta review. That development head is 196 commits ahead of the release base. The operator then authorized incorporating the security updates, testing and a normal push. Three selected backend fixes are backported on `hardened`: intake-update authorization (`69b1f23990d4b9ee293acb7020ba08d094abb0f2`), connected-account token omission (`72efad14a7e7d91d927c63c9f086a3f0d3fd96b6`) and permission-before-cache-invalidation (`258e03cbcf4db5cdb8c2708b8fa64391927c4e5e`). Unrelated development changes and dependency migrations are not merged.

Backport adaptations add the release's missing `WorkspaceMember` import and explicitly import its existing Celery test fixture. The release test factory now assigns unique usernames so fixtures with multiple users satisfy the model's unique index. State-view decorators are reordered manually because upstream surrounding state behavior differs. Additional contract cases cover membership/role boundaries, affected mutations and valid behavior. Source/dependency hardening is retained; dependencies are unchanged. The original whole-preview reference-only intake decision remains in force outside these specifically reviewed patches and the existing qualified dependency closure. Current verification records determine which resulting sources/images actually passed.

GitHub Actions are disabled for this fork. Upstream push workflows can build/publish images and acquire unreviewed tool/dependency inputs; the restricted local qualification remains the verification evidence. Enabling or replacing CI needs a separate review of its execution and publication behavior.

`PATCHES.md` distinguishes proposed, implemented and verified changes, their rationale and test/maintenance obligations. Incoming tags/artifacts require intake and exact identity before integration; never automatically pull a moving upstream branch. Do not commit generated outputs, credentials or private data.

Publication privacy cleanup rewrites all three fork-owned commits to remove operator host aliases, workstation usernames and home paths. Qualification launchers require explicit local routing; lock changes affect comments only. Verification records retain historical test identities and distinguish the later routing checks from application qualification. Rewriting branch history cannot erase copies, forks or GitHub cached commits. The hardened release still does not merge the development branch: backporting selected patches does not change upstream commit ancestry or GitHub's behind count.

## Verification and AI Inferred

Imported source files matched the prior static-review manifest and Git reported no initial difference from the pinned upstream tree. The bounded backend and Bun source/dependency qualification gates pass; records bind exact inputs, corrected failures and residual limits. Source publication does not authorize VPS deployment, image publication, PRs or advisory publication. Prefer a small reviewable patch set and supported dependency lines; alternate-runtime compatibility, archived MinIO, schemas and scanning tools create fork-owned maintenance obligations.

The local fourth review centralizes shared-table session/token/legacy asset source/target authorization and validates bulk source reassociation as well as destinations. Keep that resolver synchronized with upstream entity enums, page/global/enterprise permissions, ownership and editor staging. The161 regression cases include valid public-image and staged-upload flows; future upstream equivalents should replace fork logic after qualification rather than adding competing guards. No dependency or schema migration is introduced.
