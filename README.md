# Aegis.Diagnostics

Top-level Engineering Diagnostics application for the current scope:

- RequestPortal
- Aegis.Studio
- Aegis.Cafeteria
- Common.* through the diagnostics reported by those applications

`Common.Diagnostics` remains the reusable engine and DTO contract. `Aegis.Diagnostics` owns orchestration, cross-application run history and the operator console.

## Diagnostic levels

- Level 5 — Quick Diagnostics
- Level 4 — Component Diagnostics
- Level 3 — System Diagnostics
- Level 2 — Integration Diagnostics
- Level 1 — Full System Diagnostics

Levels are cumulative. Level 1 is the deepest run.

## Uniform application protocol

Every monitored application exposes:

- `GET /health`
- `POST /api/engineering/diagnostics/run`
- `GET /api/engineering/diagnostics/runs`
- `GET /api/engineering/diagnostics/runs/{runId}`
- `POST /api/engineering/diagnostics/runs/{runId}/resolve`

Level 5 uses `/health`. Levels 4 through 1 use the exact `Common.Diagnostics.EngineeringDiagnosticRunRequest` and `EngineeringDiagnosticRun` wire contract. Aegis.Diagnostics does not infer Common.* adoption; the application diagnostic results report their own real component health and adoption gaps.

## Orchestration responsibilities

Aegis.Diagnostics owns the centralized application-layer concerns that were originally explored in Aegis.Engineering:

- target/application registration and discovery;
- remote-safe diagnostic initiation;
- consolidated cross-application audit history;
- operator escalation and resolution workflows;
- diagnostic playbook selection and presentation;
- correlation of related runs across applications;
- notification fan-out to Slack, Teams, email, or other configured providers.

These concerns deliberately remain outside `Common.Diagnostics`. See `docs/ORCHESTRATION-MODEL.md` for the ownership and safety boundary.

The retired `Aegis.Engineering` repository is not a runtime dependency.

## Machine authentication

The shared header is:

`X-Aegis-Diagnostics-Key`

Secrets are supplied through process environment variables, never `appsettings.json`:

- `AEGIS_DIAGNOSTICS_KEY` — protects this console/API
- `REQUESTPORTAL_DIAGNOSTICS_KEY` — RequestPortal machine endpoint
- `STUDIO_DIAGNOSTICS_KEY` — Aegis.Studio machine endpoint
- `CAFETERIA_DIAGNOSTICS_KEY` — Aegis.Cafeteria machine endpoint

The browser console keeps its entered console key only in `sessionStorage` and sends it on API requests. Server-side comparisons use fixed-time comparison.

## Local layout

```text
D:\Projects\
  Aegis.Diagnostics\
  Aegis.Cafeteria\
  Aegis.Studio\
  RequestPortal\
  Common\
    Common.Diagnostics\
    Common.Security\
    Common.Secrets\
    Common.Messaging\
    Common.Storage\
```

## Run

```powershell
dotnet restore
dotnet run
```

Set the target URLs in `Diagnostics:Targets` and provision the four environment variables before production use.
