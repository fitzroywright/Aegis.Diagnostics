using Aegis.Diagnostics;
using Common.Diagnostics;
using Common.Secrets;
using System.Security.Cryptography;
using System.Text;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
DiagnosticsOptions diagnosticsOptions = builder.Configuration.GetSection("Diagnostics").Get<DiagnosticsOptions>() ?? new DiagnosticsOptions();
builder.Services.AddSingleton(diagnosticsOptions);
builder.Services.AddHttpClient("diagnostics-targets", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddCommonDiagnostics();
if (builder.Configuration.GetSection("CommonSecrets").Exists())
{
    builder.Services.AddCommonSecrets(builder.Configuration);
    builder.Services.AddCommonSecretsDiagnostics();
    builder.Services.AddHostedService<ConfigurationContractPublisher>();
}
builder.Services.AddDiagnosticsMessaging(builder.Configuration);
builder.Services.AddSingleton<RemoteDiagnosticCatalog>();
builder.Services.AddSingleton<DiagnosticPlaybookCatalog>();
builder.Services.AddSingleton<IncidentCorrelationService>();
builder.Services.AddSingleton<IIncidentNotificationPublisher, CommonMessagingIncidentNotificationPublisher>();
builder.Services.AddSingleton<DiagnosticOrchestrationService>();
WebApplication app = builder.Build();
app.UseDefaultFiles(); app.UseStaticFiles();
app.Use(async (context, next) => { if (!diagnosticsOptions.RequireApiKey || !context.Request.Path.StartsWithSegments("/api")) { await next(); return; } string? expected = Environment.GetEnvironmentVariable(diagnosticsOptions.ApiKeyEnvironmentVariable); bool authorized = !string.IsNullOrWhiteSpace(expected) && context.Request.Headers.TryGetValue(diagnosticsOptions.ApiKeyHeader, out var supplied) && FixedTimeEquals(expected, supplied.ToString()); if (!authorized) { context.Response.StatusCode = 401; await context.Response.WriteAsync("Unauthorized"); return; } await next(); });
app.MapGet("/health", () => Results.Ok(new { status = "Healthy", health = OperationalHealth.Healthy.ToString(), applicationId = diagnosticsOptions.ApplicationId, application = diagnosticsOptions.ApplicationName, siteId = diagnosticsOptions.SiteId, instanceId = diagnosticsOptions.InstanceId ?? Environment.MachineName, targets = diagnosticsOptions.Targets.Count, utc = DateTimeOffset.UtcNow }));
app.MapGet("/api/engineering/diagnostics/targets", () => Results.Ok(diagnosticsOptions.Targets.Select(t => new { t.ApplicationId, t.Name, t.SiteId, t.InstanceId, t.ApplicationType, t.BaseUrl, t.HealthPath, t.DiagnosticsRunPath, t.DiagnosticsRunsPath, t.RequireMachineCredential })));
app.MapGet("/api/engineering/diagnostics/capabilities", (RemoteDiagnosticCatalog c) => Results.Ok(c.GetCapabilities()));
app.MapGet("/api/engineering/diagnostics/playbooks", (DiagnosticPlaybookCatalog p) => Results.Ok(p.GetAll()));
app.MapGet("/api/engineering/diagnostics/incidents", async (int? minutes, IEngineeringDiagnosticRunStore store, IncidentCorrelationService correlation, CancellationToken ct) => Results.Ok(correlation.Correlate(await store.GetRecentAsync(500, ct), TimeSpan.FromMinutes(Math.Clamp(minutes ?? 15, 1, 1440)))));
app.MapGet("/api/engineering/diagnostics/runs", async (int? take, IEngineeringDiagnosticRunStore store, CancellationToken ct) => Results.Ok(await store.GetRecentAsync(Math.Clamp(take ?? 25, 1, 100), ct)));
app.MapGet("/api/engineering/diagnostics/runs/{runId:guid}", async (Guid runId, IEngineeringDiagnosticRunStore store, CancellationToken ct) => { var run = await store.GetAsync(runId, ct); return run is null ? Results.NotFound() : Results.Ok(run); });
app.MapPost("/api/engineering/diagnostics/run", async (EngineeringDiagnosticRunRequest request, DiagnosticOrchestrationService orchestration, HttpContext context, CancellationToken ct) => { try { string by = context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator"; return Results.Ok(await orchestration.RunAsync(request, by, ct)); } catch (ArgumentException ex) { return Results.BadRequest(new { error = ex.Message }); } });
app.MapPost("/api/engineering/diagnostics/runs/{runId:guid}/resolve", async (Guid runId, EngineeringDiagnosticResolutionRequest request, IEngineeringDiagnosticRunStore store, HttpContext context, CancellationToken ct) => { if (string.IsNullOrWhiteSpace(request.Resolution)) return Results.BadRequest(new { error = "Resolution is required." }); string by = context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "operator"; var resolved = await store.ResolveAsync(runId, by, request.Resolution.Trim(), ct); return resolved is null ? Results.NotFound() : Results.Ok(resolved); });
app.Run();
static bool FixedTimeEquals(string expected, string supplied) { byte[] a=Encoding.UTF8.GetBytes(expected),b=Encoding.UTF8.GetBytes(supplied); return a.Length==b.Length && CryptographicOperations.FixedTimeEquals(a,b); }
