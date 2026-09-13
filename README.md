# Aegis.Diagnostics

`Aegis.Diagnostics` is the code/product identity. Its operator-facing UI is branded **System Diagnostics**.

`Common.Diagnostics` remains the reusable engine and wire-contract library. Aegis.Diagnostics owns aggregation, cross-application history, correlation, operator workflow and the responsive System Diagnostics console.

## Ownership boundary

- **System Configuration / Aegis.Configuration:** what an application says it requires and whether it reports that requirement configured.
- **System Diagnostics / Aegis.Diagnostics:** whether the running application and its dependencies are actually working.
- Applications are authoritative for their own diagnostic results.
- Secrets are never displayed or returned as diagnostic evidence.
- Configuration completeness is not a diagnostic health test.

## Stable identity

Targets use the same `ApplicationId`, `SiteId`, `InstanceId` and version identity used by Aegis.Configuration. Current target identities include `RequestPortal`, `Aegis.Studio`, `Aegis.Cafeteria.Services` and `Aegis.SensorNetwork.ControlPlane`.

## Starfleet Engineering Protocol lifecycle

The internal engineering protocol name is retained, while the UI uses generic System Diagnostics branding and a generic diagnostics logo.

- Level 5 — Scan: fast baseline health and heartbeat.
- Level 4 — Analysis: deeper dependency, data-flow and error evidence.
- Level 3 — Verification: verify a suspected fault or recovery.
- Level 2 — Repair: authorized controlled repair stage.
- Level 1 — Critical Intervention: high-trust emergency intervention.

Levels are cumulative according to Common.Diagnostics policy. Level 2 and Level 1 require an engineering reason and remain gated intervention stages.

## Uniform application protocol

Every monitored independently deployed application should expose `GET /health`, `POST /api/engineering/diagnostics/run`, `GET /api/engineering/diagnostics/runs`, `GET /api/engineering/diagnostics/runs/{runId}`, and `POST /api/engineering/diagnostics/runs/{runId}/resolve` where resolution is supported.

Level 5 uses `/health`. Deeper levels use `Common.Diagnostics.EngineeringDiagnosticRunRequest` and `EngineeringDiagnosticRun`. System Diagnostics does not infer configuration state or Common.* adoption; application diagnostic results report their own component health.

## Machine authentication

The default machine header is `X-Aegis-Diagnostics-Key`. Credentials are supplied through process environment variables or the configured secrets provider and are never committed to appsettings. The browser console stores its entered operator key only in `sessionStorage`; server-side comparisons use fixed-time comparison.

## Configuration integration

Aegis.Diagnostics registers its own configuration contract with Aegis.Configuration when `AegisConfiguration:BaseUrl` and the registration credential are available. Publication is best-effort and Diagnostics remains operational if Configuration is unavailable.

## Validation

Before release, build and test Common.Diagnostics first, then Aegis.Diagnostics and each consuming application. End-to-end validation must prove machine authentication, history, target identity, Level 5 health, deeper application-owned diagnostics, no secret leakage, and continued application operation when either central UI is unavailable.
