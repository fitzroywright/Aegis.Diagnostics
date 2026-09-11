using Aegis.Diagnostics;
using Common.Diagnostics;
using System.Security.Cryptography;
using System.Text;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
DiagnosticsOptions diagnosticsOptions = builder.Configuration.GetSection("Diagnostics").Get<DiagnosticsOptions>() ?? new DiagnosticsOptions();
builder.Services.AddSingleton(diagnosticsOptions);
builder.Services.AddHttpClient("diagnostics-targets", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddCommonDiagnostics();
builder.Services.AddDiagnosticsMessaging(builder.Configuration);
builder.Services.AddSingleton<RemoteDiagnosticCatalog>();
builder.Services.AddSingleton<DiagnosticPlaybookCatalog>();
builder.Services.AddSingleton<IncidentCorrelationService>();
builder.Services.AddSingleton<IIncidentNotificationPublisher, CommonMessagingIncidentNotificationPublisher>();
builder.Services.AddSingleton<DiagnosticOrchestrationService>();

WebApplication app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.Use(async (context, next) =>
{
    if (!diagnosticsOptions.RequireApiKey || !context.Request.Path.StartsWithSegments("/api"))
    {
        await next();
        return;
    }

    string? expected = Environment.GetEnvironmentVariable(diagnosticsOptions.ApiKeyEnvironmentVariable);
    bool authorized = !string.IsNullOrWhiteSpace(expected)
        && context.Request.Headers.TryGetValue(diagnosticsOptions.ApiKeyHeader, out var supplied)
        && FixedTimeEquals(expected, supplied.ToString());

    if (!authorized)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Unauthorized");
        return;
    }

    await next();
});

app.MapGet("/health", () => Results.Ok(new
{
    status = "Healthy",
    application = diagnosticsOptions.ApplicationName,
    targets = diagnosticsOptions.Targets.Count,
    utc = DateTimeOffset.UtcNow
}));

app.MapGet("/api/engineering/diagnostics/targets", () => Results.Ok(diagnosticsOptions.Targets.Select(target => new
{
    target.Name,
    target.ApplicationType,
    target.BaseUrl,
    target.HealthPath,
    target.DiagnosticsRunPath,
    target.DiagnosticsRunsPath,
    target.RequireMachineCredential
})));

app.MapGet("/api/engineering/diagnostics/capabilities", (RemoteDiagnosticCatalog catalog) => Results.Ok(catalog.GetCapabilities()));

app.MapGet("/api/engineering/diagnostics/playbooks", (DiagnosticPlaybookCatalog playbooks) => Results.Ok(playbooks.GetAll()));

app.MapGet("/api/engineering/diagnostics/incidents", async (int? minutes, IEngineeringDiagnosticRunStore store, IncidentCorrelationService correlation, CancellationToken cancellationToken) =>
{
    int requestedMinutes = Math.Clamp(minutes ?? 15, 1, 1440);
    IReadOnlyList<EngineeringDiagnosticRun> runs = await store.GetRecentAsync(500, cancellationToken);
    return Results.Ok(correlation.Correlate(runs, TimeSpan.FromMinutes(requestedMinutes)));
});

app.MapGet("/api/engineering/diagnostics/runs", async (int? take, IEngineeringDiagnosticRunStore store, CancellationToken cancellationToken) =>
{
    int requested = Math.Clamp(take ?? 25, 1, 100);
    return Results.Ok(await store.GetRecentAsync(requested, cancellationToken));
});

app.MapGet("/api/engineering/diagnostics/runs/{runId:guid}", async (Guid runId, IEngineeringDiagnosticRunStore store, CancellationToken cancellationToken) =>
{
    EngineeringDiagnosticRun? run = await store.GetAsync(runId, cancellationToken);
    return run is null ? Results.NotFound() : Results.Ok(run);
});

app.MapPost("/api/engineering/diagnostics/run", async (EngineeringDiagnosticRunRequest request, DiagnosticOrchestrationService orchestration, HttpContext context, CancellationToken cancellationToken) =>
{
    try
    {
        string requestedBy = context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator";
        OrchestratedDiagnosticResult result = await orchestration.RunAsync(request, requestedBy, cancellationToken);
        return Results.Ok(result);
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapPost("/api/engineering/diagnostics/runs/{runId:guid}/resolve", async (Guid runId, EngineeringDiagnosticResolutionRequest request, IEngineeringDiagnosticRunStore store, HttpContext context, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Resolution))
    {
        return Results.BadRequest(new { error = "Resolution is required." });
    }

    string resolvedBy = context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator";
    EngineeringDiagnosticRun? resolved = await store.ResolveAsync(runId, resolvedBy, request.Resolution.Trim(), cancellationToken);
    return resolved is null ? Results.NotFound() : Results.Ok(resolved);
});

app.Run();

static bool FixedTimeEquals(string expected, string supplied)
{
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
    byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    return expectedBytes.Length == suppliedBytes.Length
        && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes);
}
