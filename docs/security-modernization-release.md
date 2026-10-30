# Security modernization candidate — deployment gate closed

This is a coordinated source candidate, not an approved production rollout. `security-baseline.json` pins every shared library; no application may substitute a floating Common.Security checkout or overwrite shared running binaries. Build in an isolated output directory and deploy a complete application bundle independently.

## Build and evidence

Run `python3 ../Common/Common.Security/scripts/verify-source-baseline.py security-baseline.json --common-root ../Common` before building. Run the existing application tests and the coordinated security workflow. Failed, skipped, missing or empty results block release. The workflow uses disposable PostgreSQL 16 and cannot replace live provider or operational acceptance.

## Data and identity preparation

1. Capture the currently deployed application package, protected configuration, database backup, key rings, plugin versions and credential-store references. Verify a restore into an isolated environment before any production write.
2. Review an owner-only approved account manifest. Preserve each existing account ID and login alias. Resolve immutable AD domain/user GUIDs or Entra tenant/object IDs through an authorized directory administrator. Email and usernames do not authorize bindings. No production identity import has been executed by this change.
3. Rehearse the additive common schema and approved imports on a representative restored database. Verify account counts, existing business references, role assignments and security audit. New staff/operators must remain Pending Access until explicitly approved.
4. Keep at least two approved administrators. Test login, disabling, linking/unlinking, role removal and session revocation before enabling broader access. All pre-cutover human cookies require a fresh login to acquire a verified account/version binding.

## Rollout and recovery

Stage the complete candidate alongside the last known-good package. Keep each application's database and deployment independent. Run its acceptance matrix, verify protected configuration and backups, then cut over only that application. No deployment is authorized by a successful shared-library build alone.

On a stop condition, stop the affected rollout and return traffic to the previous package. Preserve new business records and the additive security tables/audit. Do not restore a stale pre-cutover database after new writes; reconcile identity changes forward or recover current business writes into a restored copy before an explicitly approved restore. Do not drop old identity history or business tables. Re-run smoke and security checks after recovery.

## Required operational acceptance

All three services must share the SAME protected `SuiteSecurity:AccountStorePath`, while retaining separate ASP.NET cookie names/key protection and app-owned role definitions. `SuiteSecurity:AccountRoles:<immutable-account-id>` grants roles explicitly; usernames and directory authentication do not imply an administrative role. Configure Entra tenant/client IDs and the client secret through the existing Common.Secrets provider. Protect the suite handoff signing key; tickets are audience-bound, expire in 45 seconds and are one-use.

Emergency recovery is offline OS-authorized maintenance through the pinned `Common.Security.Tools`. Enroll a dedicated LocalDatabase staff account using an owner-only manifest/password file and `COMMON_SECURITY_CONNECTION` pointing to the protected shared account database. Explicitly grant that account ID the app-owned Administrator role. Activate `SuiteSecurity:Mode=LocalDatabase` only for the controlled recovery window; there is no automatic fallback from AD. Use `recover-local` only for that already enrolled local account; it invalidates existing sessions. Test the recovered login in each intended service, rotate any exposed proof, restore the normal mode and retain the account audit. The shared recovery regression verifies identity preservation, role preservation, old password/session rejection and one-use reset behavior.

Verify registered applications remain visible, service health and diagnostics arrive, OpenBao access works, and revoked/rotated machine credentials fail. Installation, instance, runtime and correlation identifiers remain correlation data. Configuration persists explicit machine scopes; unauthorized credentials cannot mutate identity-conflict state. Operations revalidates telemetry credentials on every request and fails closed when the authority is unavailable; client retry/outbox behavior remains responsible for later delivery. Diagnostic machine scopes default to View and Run and cannot grant Repair/Critical authority. Live authority outage/recovery and registration smoke checks remain required.
