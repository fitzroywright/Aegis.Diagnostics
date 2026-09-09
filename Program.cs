using Aegis.Diagnostics;
using Common.Diagnostics;
using System.Security.Cryptography;
using System.Text;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
DiagnosticsOptions diagnosticsOptions = builder.Configuration.GetSection("Diagnostics").Get<DiagnosticsOptions>() ?? new DiagnosticsOptions();
builder.Services.AddSingleton(diagnosticsOptions);
builder.Services.AddHttpClient("diagnostics-targets", client => client.Timeout = TimeSpan.FromSeconds(30));
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

app.MapPost("/api/engineering/diagnostics/run", async (EngineeringDiagnosticRunRequest request, EngineeringDiagnosticEngine engine, RemoteDiagnosticCatalog catalog, HttpContext context, CancellationToken cancellationToken) =>
{
    string requestedBy = context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator";
    EngineeringDiagnosticRun run = await engine.RunAsync(
        request.Level,
        diagnosticsOptions.ApplicationName,
        diagnosticsOptions.EnvironmentName,
        requestedBy,
        request.Reason,
        catalog.Build(request.Level, request.Reason),
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

static bool FixedTimeEquals(string expected, string supplied)
{
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
    byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    return expectedBytes.Length == suppliedBytes.Length
        && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes);
}
