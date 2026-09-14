using Aegis.Diagnostics;
using Common.Diagnostics;

internal static class DiagnosticsApi
{
    internal static void MapDiagnosticsApi(this WebApplication app, DiagnosticsOptions options)
    {
        app.MapGet("/health", () => Results.Ok(new
        {
            status = "Healthy",
            health = OperationalHealth.Healthy.ToString(),
            applicationId = options.ApplicationId,
            application = options.ApplicationName,
            siteId = options.SiteId,
            instanceId = options.InstanceId ?? Environment.MachineName,
            targets = options.Targets.Count,
            utc = DateTimeOffset.UtcNow
        }));

        app.MapGet("/api/engineering/diagnostics/targets", () => Results.Ok(options.Targets.Select(t => new
        {
            t.ApplicationId, t.Name, t.SiteId, t.InstanceId, t.ApplicationType,
            t.BaseUrl, t.HealthPath, t.DiagnosticsRunPath, t.DiagnosticsRunsPath,
            t.RequireMachineCredential
        })));

        app.MapGet("/api/engineering/diagnostics/capabilities",
            (RemoteDiagnosticCatalog catalog) => Results.Ok(catalog.GetCapabilities()));

        app.MapGet("/api/engineering/diagnostics/playbooks",
            (DiagnosticPlaybookCatalog catalog) => Results.Ok(catalog.GetAll()));

        app.MapGet("/api/engineering/diagnostics/incidents", GetIncidentsAsync);
        app.MapGet("/api/engineering/diagnostics/runs", GetRunsAsync);
        app.MapGet("/api/engineering/diagnostics/runs/{runId:guid}", GetRunAsync);
        app.MapPost("/api/engineering/diagnostics/run", RunDiagnosticsAsync);
        app.MapPost("/api/engineering/diagnostics/runs/{runId:guid}/resolve", ResolveRunAsync);
    }

    private static async Task<IResult> GetIncidentsAsync(
        int? minutes,
        IEngineeringDiagnosticRunStore store,
        IncidentCorrelationService correlation,
        CancellationToken ct)
    {
        var runs = await store.GetRecentAsync(500, ct);
        TimeSpan window = TimeSpan.FromMinutes(Math.Clamp(minutes ?? 15, 1, 1440));
        return Results.Ok(correlation.Correlate(runs, window));
    }

    private static async Task<IResult> GetRunsAsync(
        int? take,
        IEngineeringDiagnosticRunStore store,
        CancellationToken ct) =>
        Results.Ok(await store.GetRecentAsync(Math.Clamp(take ?? 25, 1, 100), ct));

    private static async Task<IResult> GetRunAsync(
        Guid runId,
        IEngineeringDiagnosticRunStore store,
        CancellationToken ct)
    {
        var run = await store.GetAsync(runId, ct);
        return run is null ? Results.NotFound() : Results.Ok(run);
    }

    private static async Task<IResult> RunDiagnosticsAsync(
        EngineeringDiagnosticRunRequest request,
        DiagnosticOrchestrationService orchestration,
        HttpContext context,
        CancellationToken ct)
    {
        try
        {
            string by = OperatorName(context);
            return Results.Ok(await orchestration.RunAsync(request, by, ct));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> ResolveRunAsync(
        Guid runId,
        EngineeringDiagnosticResolutionRequest request,
        IEngineeringDiagnosticRunStore store,
        HttpContext context,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Resolution))
            return Results.BadRequest(new { error = "Resolution is required." });

        var resolved = await store.ResolveAsync(runId, OperatorName(context), request.Resolution.Trim(), ct);
        return resolved is null ? Results.NotFound() : Results.Ok(resolved);
    }

    private static string OperatorName(HttpContext context) =>
        context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator";
}
