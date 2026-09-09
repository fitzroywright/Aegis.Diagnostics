using Aegis.Diagnostics;
using Common.Diagnostics;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
DiagnosticsOptions diagnosticsOptions = builder.Configuration.GetSection("Diagnostics").Get<DiagnosticsOptions>() ?? new DiagnosticsOptions();
builder.Services.AddSingleton(diagnosticsOptions);
builder.Services.AddHttpClient("diagnostics-targets", client => client.Timeout = TimeSpan.FromSeconds(8));
builder.Services.AddCommonDiagnostics();
builder.Services.AddSingleton<RemoteDiagnosticCatalog>();

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

    if (!context.Request.Headers.TryGetValue("X-Diagnostics-Key", out var supplied) ||
        string.IsNullOrWhiteSpace(diagnosticsOptions.ApiKey) ||
        !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(supplied.ToString()),
            System.Text.Encoding.UTF8.GetBytes(diagnosticsOptions.ApiKey)))
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
    CommonComponents = target.CommonComponents,
    ProbeCount = target.Probes.Count(probe => probe.Enabled)
})));

app.MapGet("/api/engineering/diagnostics/capabilities", (RemoteDiagnosticCatalog catalog) => Results.Ok(catalog.GetCapabilities()));

app.MapGet("/api/engineering/diagnostics/runs", async (int? take, IEngineeringDiagnosticRunStore store, CancellationToken cancellationToken) =>
{
    int requested = Math.Clamp(take ?? 25, 1, 100);
    return Results.Ok(await store.GetRecentAsync(requested, cancellationToken));
});

app.MapPost("/api/engineering/diagnostics/run", async (EngineeringDiagnosticRunRequest request, EngineeringDiagnosticEngine engine, RemoteDiagnosticCatalog catalog, HttpContext context, CancellationToken cancellationToken) =>
{
    string requestedBy = context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator";
    EngineeringDiagnosticRun run = await engine.RunAsync(
        request.Level,
        diagnosticsOptions.ApplicationName,
        diagnosticsOptions.EnvironmentName,
        requestedBy,
        request.Reason,
        catalog.Build(),
        cancellationToken);
    return Results.Ok(run);
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
