# Aegis.Diagnostics

Top-level Engineering Diagnostics application for the current Aegis application scope:

- RequestPortal
- Aegis.Studio
- Aegis.Cafeteria
- Common.* platform components through Common.Diagnostics

`Common.Diagnostics` remains the reusable diagnostics engine. `Aegis.Diagnostics` owns the operator UI, orchestration, run history and cross-application view.

## Diagnostic levels

- Level 5 — Quick Diagnostics
- Level 4 — Component Diagnostics
- Level 3 — System Diagnostics
- Level 2 — Integration Diagnostics
- Level 1 — Full System Diagnostics

Levels are cumulative. Level 1 is the deepest run and includes Levels 1 through 5.

## Local layout

Expected sibling layout:

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

Update `Diagnostics:Targets` in `appsettings.json` for the actual internal URLs.

## API protection

Set `Diagnostics:RequireApiKey=true` and provide `Diagnostics:ApiKey` in production. API calls then require `X-Diagnostics-Key`. This can later be replaced by Common.Security authentication without changing the diagnostics engine.
