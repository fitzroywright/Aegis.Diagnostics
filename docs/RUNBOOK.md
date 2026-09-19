# Aegis.Diagnostics Operational Runbook

## Purpose
Aegis.Diagnostics aggregates application-owned diagnostic evidence and provides the System Diagnostics operator console.

## Dependencies
Aegis.Configuration discovery, Common.Diagnostics, Common.Secrets for machine credentials, configured target endpoints, and local diagnostic run storage.

## Startup
Load configuration, initialize Common.Secrets, refresh Configuration discovery, start application health monitoring, and expose the diagnostics API/UI.

## Health Verification
/health describes Aegis.Diagnostics itself. Target application failures are evidence observed by Diagnostics and must not automatically make Diagnostics unhealthy.

## Normal State
Configuration discovery is current, run-store is writable, target evidence is fresh, and no central secret/configuration failure blocks authorized diagnostic requests.

## Evidence Rules
HTTP 200 alone is not Healthy. Missing, malformed, stale, timed-out or unreachable target telemetry is Unknown unless stronger evidence exists.

## Recovery
Restore the failed discovery/credential/target dependency and verify fresh evidence after recovery. Do not infer recovery from a repair action alone.

## Backup / Restore
Back up persistent engineering diagnostic history where required by operations policy. Restore should preserve correlation identifiers and timestamps.

## Deployment / Rollback
Preserve configuration, machine credential references and persistent run history.

## Escalation
Escalate discovery failure, machine-authentication failure, run-store failure, or persistent inability to obtain trustworthy target evidence.

## Log Locations
Use service logs and stored engineering diagnostic runs. Never log secret values, machine credentials or application authentication tokens.
