using Aegis.Diagnostics;
using Common.Diagnostics;

internal static class DiagnosticsApi
{
    internal static void MapDiagnosticsApi(this WebApplication app, DiagnosticsOptions options)
    {
        app.MapAegisHealth(
            options.ApplicationId,
            (services, _) =>
            {
                ConfigurationDiscoveryCatalog discovery = services.GetRequiredService<ConfigurationDiscoveryCatalog>();
                ApplicationHealthStateStore health = services.GetRequiredService<ApplicationHealthStateStore>();
                IReadOnlyList<ApplicationHealthObservation> observations = health.GetAll();

                // Diagnostics health describes Diagnostics itself, not the health of the applications it observes.
                // A monitored application being unhealthy is evidence that Diagnostics is doing its job, not that
                // Diagnostics should be restarted or rolled back. Target health remains available from /status.
                AegisHealthAssessment assessment = discovery.IsStale
                    ? AegisHealthAssessment.Degraded($"Diagnostics is operational but Configuration discovery is stale. Discovered {discovery.Targets.Count}; observed {observations.Count}.")
                    : AegisHealthAssessment.Healthy($"Diagnostics discovery is current. Discovered {discovery.Targets.Count}; observed {observations.Count}.");

                return Task.FromResult(assessment);
            },
            instanceId: options.InstanceId);

        // Preserve the existing array response shape for the current Diagnostics UI. Inventory metadata
        // is exposed by /capabilities and health, while the target identities themselves come from Configuration.
        app.MapGet("/api/engineering/diagnostics/targets", (HttpContext c, IDiagnosticTargetCatalog discovery) =>
            View(c) ? Results.Ok(discovery.Targets) : Results.Forbid());

        app.MapGet("/api/engineering/diagnostics/status", (HttpContext c, ApplicationHealthStateStore health) =>
            View(c) ? Results.Ok(new { source = "Aegis.Diagnostics", observations = health.GetAll() }) : Results.Forbid());

        app.MapGet("/api/engineering/diagnostics/v2/observations", (string? applicationId, HttpContext c, DiagnosticContractV2StateStore store) =>
            View(c) ? Results.Ok(store.GetObservations(applicationId)) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/v2/flows", (string? applicationId, HttpContext c, DiagnosticContractV2StateStore store) =>
            View(c) ? Results.Ok(store.GetFlows(applicationId)) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/v2/synchronization", (string? applicationId, HttpContext c, DiagnosticContractV2StateStore store) =>
            View(c) ? Results.Ok(store.GetSynchronization(applicationId)) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/v2/queues", (string? applicationId, HttpContext c, DiagnosticContractV2StateStore store) =>
            View(c) ? Results.Ok(store.GetQueues(applicationId)) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/v2/decisions", (string? applicationId, HttpContext c, DiagnosticContractV2StateStore store) =>
            View(c) ? Results.Ok(store.GetDecisions(applicationId)) : Results.Forbid());

        app.MapPost("/api/engineering/diagnostics/v2/observations", (DiagnosticObservation item, HttpContext c, DiagnosticContractV2StateStore store) =>
        {
            if (!Has(c, "Diagnostics.Run")) return Results.Forbid();
            store.Set(item);
            return Results.Accepted();
        });
        app.MapPost("/api/engineering/diagnostics/v2/flows", (DiagnosticFlowInstance item, HttpContext c, DiagnosticContractV2StateStore store) =>
        {
            if (!Has(c, "Diagnostics.Run")) return Results.Forbid();
            store.Set(item);
            return Results.Accepted();
        });
        app.MapPost("/api/engineering/diagnostics/v2/synchronization", (SynchronizationDiagnostic item, HttpContext c, DiagnosticContractV2StateStore store) =>
        {
            if (!Has(c, "Diagnostics.Run")) return Results.Forbid();
            store.Set(item);
            return Results.Accepted();
        });
        app.MapPost("/api/engineering/diagnostics/v2/queues", (QueueDiagnostic item, HttpContext c, DiagnosticContractV2StateStore store) =>
        {
            if (!Has(c, "Diagnostics.Run")) return Results.Forbid();
            store.Set(item);
            return Results.Accepted();
        });
        app.MapPost("/api/engineering/diagnostics/v2/decisions", (DecisionDiagnostic item, HttpContext c, DiagnosticContractV2StateStore store) =>
        {
            if (!Has(c, "Diagnostics.Run")) return Results.Forbid();
            store.Set(item);
            return Results.Accepted();
        });

        app.MapGet("/api/engineering/diagnostics/capabilities", (HttpContext c, RemoteDiagnosticCatalog catalog) => View(c) ? Results.Ok(catalog.GetCapabilities()) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/telemetry", GetTelemetryAsync);
        app.MapGet("/api/engineering/diagnostics/playbooks", (HttpContext c, DiagnosticPlaybookCatalog catalog) => View(c) ? Results.Ok(catalog.GetAll()) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/incidents", GetIncidentsAsync);
        app.MapGet("/api/engineering/diagnostics/runs", GetRunsAsync);
        app.MapGet("/api/engineering/diagnostics/runs/{runId:guid}", GetRunAsync);
        app.MapPost("/api/engineering/diagnostics/run", RunDiagnosticsAsync);
        app.MapPost("/api/engineering/diagnostics/runs/{runId:guid}/resolve", ResolveRunAsync);
        app.MapGet("/api/engineering/diagnostics/activity", ProxyOperationsActivityAsync);
        app.MapGet("/api/engineering/diagnostics/logs", ProxyOperationsLogsAsync);
    }

    static bool Machine(HttpContext c)=>c.Items.TryGetValue("DiagnosticsMachineAuthorized",out object? value)&&value is true;
    static bool Has(HttpContext c,string p)=>
        (c.Items.TryGetValue("SuiteIdentity",out object? v)&&v is SuiteIdentity i&&i.Permissions.Contains(p,StringComparer.OrdinalIgnoreCase)) ||
        (Machine(c) && p is "Diagnostics.View" or "Diagnostics.Run");
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

    private static Task<IResult> ProxyOperationsActivityAsync(
        HttpContext context,
        IHttpClientFactory factory,
        IConfiguration configuration,
        CancellationToken ct) =>
        ProxyOperationsAsync(
            context,
            factory,
            configuration,
            "/api/operations/activity",
            ct);

    private static Task<IResult> ProxyOperationsLogsAsync(
        HttpContext context,
        IHttpClientFactory factory,
        IConfiguration configuration,
        CancellationToken ct) =>
        ProxyOperationsAsync(
            context,
            factory,
            configuration,
            "/api/operations/logs",
            ct);

    private static async Task<IResult> ProxyOperationsAsync(
        HttpContext context,
        IHttpClientFactory factory,
        IConfiguration configuration,
        string path,
        CancellationToken ct)
    {
        if (!View(context)) return Results.Forbid();

        string operationsUrl = AegisControlPlaneEndpoints.ResolveInternal(
            configuration,
            AegisControlPlaneService.Operations);

        if (!Uri.TryCreate(operationsUrl, UriKind.Absolute, out Uri? baseUri))
            return Results.Problem(
                "Diagnostics cannot read the suite activity stream because the resolved Operations endpoint is invalid.",
                statusCode: StatusCodes.Status503ServiceUnavailable);

        var target = new Uri(
            baseUri,
            path + context.Request.QueryString.Value);

        try
        {
            string credentialFile = configuration["Aegis:Registration:CredentialFile"]?.Trim()
                ?? "/var/lib/aegis/diagnostics/registration.key";
            if (!File.Exists(credentialFile))
                return Results.Problem(
                    "Diagnostics cannot authenticate to Operations because its control-plane registration credential is missing.",
                    statusCode: StatusCodes.Status503ServiceUnavailable);

            string credential = (await File.ReadAllTextAsync(credentialFile, ct).ConfigureAwait(false)).Trim();
            if (string.IsNullOrWhiteSpace(credential))
                return Results.Problem(
                    "Diagnostics cannot authenticate to Operations because its control-plane registration credential is empty.",
                    statusCode: StatusCodes.Status503ServiceUnavailable);

            string instanceId =
                configuration["Diagnostics:InstanceId"]?.Trim() ??
                configuration["Service:Identity"]?.Trim() ??
                Environment.MachineName;

            using var request = new HttpRequestMessage(HttpMethod.Get, target);
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", credential);
            request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", "Aegis.Diagnostics");
            request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", instanceId);

            HttpClient client = factory.CreateClient("operations-activity");
            using HttpResponseMessage response =
                await client.SendAsync(request, ct).ConfigureAwait(false);

            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return Results.Content(
                body,
                response.Content.Headers.ContentType?.ToString() ?? "application/json",
                statusCode: (int)response.StatusCode);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return Results.Problem(
                "Diagnostics could not reach the Operations activity stream.",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static string OperatorName(HttpContext context)=>context.Items.TryGetValue("SuiteIdentity",out object? v)&&v is SuiteIdentity i?i.UserName:Machine(context)?"Aegis.Diagnostics Machine":context.User.Identity?.Name??context.Connection.RemoteIpAddress?.ToString()??"operator";
}
