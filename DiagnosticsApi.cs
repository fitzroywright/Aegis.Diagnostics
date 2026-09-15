using Aegis.Diagnostics;
using Common.Diagnostics;

internal static class DiagnosticsApi
{
    internal static void MapDiagnosticsApi(this WebApplication app, DiagnosticsOptions options)
    {
        app.MapGet("/health", (ConfigurationDiscoveryCatalog discovery) => Results.Ok(new
        {
            status = discovery.IsStale ? "Degraded" : "Healthy",
            health = discovery.IsStale ? OperationalHealth.Degraded.ToString() : OperationalHealth.Healthy.ToString(),
            applicationId = options.ApplicationId,
            application = options.ApplicationName,
            siteId = options.SiteId,
            instanceId = options.InstanceId ?? Environment.MachineName,
            discoveredTargets = discovery.Targets.Count,
            discoveryLastSuccessfulUtc = discovery.LastSuccessfulRefreshUtc,
            discoveryStale = discovery.IsStale,
            utc = DateTimeOffset.UtcNow
        }));

        app.MapGet("/api/engineering/diagnostics/targets", (HttpContext c, ConfigurationDiscoveryCatalog discovery) =>
            View(c) ? Results.Ok(new
            {
                source = "Aegis.Configuration",
                lastSuccessfulRefreshUtc = discovery.LastSuccessfulRefreshUtc,
                stale = discovery.IsStale,
                error = discovery.LastError,
                targets = discovery.Targets
            }) : Results.Forbid());

        app.MapGet("/api/engineering/diagnostics/capabilities", (HttpContext c, RemoteDiagnosticCatalog catalog) => View(c) ? Results.Ok(catalog.GetCapabilities()) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/telemetry", GetTelemetryAsync);
        app.MapGet("/api/engineering/diagnostics/playbooks", (HttpContext c, DiagnosticPlaybookCatalog catalog) => View(c) ? Results.Ok(catalog.GetAll()) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/incidents", GetIncidentsAsync);
        app.MapGet("/api/engineering/diagnostics/runs", GetRunsAsync);
        app.MapGet("/api/engineering/diagnostics/runs/{runId:guid}", GetRunAsync);
        app.MapPost("/api/engineering/diagnostics/run", RunDiagnosticsAsync);
        app.MapPost("/api/engineering/diagnostics/runs/{runId:guid}/resolve", ResolveRunAsync);
    }

    static bool Has(HttpContext c,string p)=>c.Items.TryGetValue("SuiteIdentity",out object? v)&&v is SuiteIdentity i&&i.Permissions.Contains(p,StringComparer.OrdinalIgnoreCase);
    static bool View(HttpContext c)=>Has(c,"Diagnostics.View");

    private static async Task<IResult> GetTelemetryAsync(HttpContext context, CancellationToken ct)
    {
        if (!View(context)) return Results.Forbid();
        return Results.Ok(await OperationalTelemetryCollector.CaptureAsync(ct));
    }

    private static async Task<IResult> GetIncidentsAsync(int? minutes,IEngineeringDiagnosticRunStore store,IncidentCorrelationService correlation,HttpContext context,CancellationToken ct){if(!View(context))return Results.Forbid();var runs=await store.GetRecentAsync(500,ct);TimeSpan window=TimeSpan.FromMinutes(Math.Clamp(minutes??15,1,1440));return Results.Ok(correlation.Correlate(runs,window));}
    private static async Task<IResult> GetRunsAsync(int? take,IEngineeringDiagnosticRunStore store,HttpContext context,CancellationToken ct)=>!View(context)?Results.Forbid():Results.Ok(await store.GetRecentAsync(Math.Clamp(take??25,1,100),ct));
    private static async Task<IResult> GetRunAsync(Guid runId,IEngineeringDiagnosticRunStore store,HttpContext context,CancellationToken ct){if(!View(context))return Results.Forbid();var run=await store.GetAsync(runId,ct);return run is null?Results.NotFound():Results.Ok(run);}
    private static async Task<IResult> RunDiagnosticsAsync(EngineeringDiagnosticRunRequest request,DiagnosticOrchestrationService orchestration,HttpContext context,CancellationToken ct){if(!Has(context,"Diagnostics.Run"))return Results.Forbid();try{return Results.Ok(await orchestration.RunAsync(request,OperatorName(context),ct));}catch(ArgumentException ex){return Results.BadRequest(new{error=ex.Message});}}
    private static async Task<IResult> ResolveRunAsync(Guid runId,EngineeringDiagnosticResolutionRequest request,IEngineeringDiagnosticRunStore store,HttpContext context,CancellationToken ct){if(!Has(context,"Diagnostics.Repair"))return Results.Forbid();if(string.IsNullOrWhiteSpace(request.Resolution))return Results.BadRequest(new{error="Resolution is required."});var resolved=await store.ResolveAsync(runId,OperatorName(context),request.Resolution.Trim(),ct);return resolved is null?Results.NotFound():Results.Ok(resolved);}
    private static string OperatorName(HttpContext context)=>context.Items.TryGetValue("SuiteIdentity",out object? v)&&v is SuiteIdentity i?i.UserName:context.User.Identity?.Name??context.Connection.RemoteIpAddress?.ToString()??"operator";
}
