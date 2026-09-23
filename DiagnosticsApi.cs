using Aegis.Diagnostics;
using Common.Diagnostics;
using Common.Registration;

internal sealed record EngineerNoteRequest(string? Text);
internal sealed record EngineerNoteDispositionRequest(string? Action, string? Reason);
internal sealed record EngineerNote(
    Guid Id,
    DateTimeOffset CreatedAtUtc,
    string Engineer,
    string Text,
    string Status = "Active",
    DateTimeOffset? DispositionAtUtc = null,
    string? DispositionBy = null,
    string? DispositionReason = null,
    string? AudioFileName = null,
    string? AudioContentType = null,
    long? AudioBytes = null);

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

        app.MapGet("/api/engineering/diagnostics/levelx/targets", (HttpContext c, IDiagnosticTargetCatalog discovery) =>
        {
            if (!View(c)) return Results.Forbid();
            return Results.Ok(new
            {
                targetTypes = new[]
                {
                    new { value = "ControlPlane", label = "Control Plane" },
                    new { value = "ControlPlaneComponent", label = "Control Plane Component" },
                    new { value = "CommonComponent", label = "Common Component" },
                    new { value = "RegisteredApplication", label = "Registered Application" }
                },
                controlPlane = new[]
                {
                    new { targetId = ControlPlaneDiagnosticTargets.EntireControlPlane, label = "Entire Control Plane" },
                    new { targetId = ControlPlaneDiagnosticTargets.Operations, label = "Operations" },
                    new { targetId = ControlPlaneDiagnosticTargets.Configuration, label = "Configuration" },
                    new { targetId = ControlPlaneDiagnosticTargets.Diagnostics, label = "Diagnostics" },
                    new { targetId = ControlPlaneDiagnosticTargets.Registration, label = "Registration" }
                },
                commonComponents = CommonDiagnosticTargets.Components
                    .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .Select(x => new { targetId = x, label = x })
                    .ToArray(),
                applications = discovery.Targets.Select(target => new
                {
                    target.ApplicationId,
                    target.InstanceId,
                    target.Name,
                    target.SiteId,
                    target.BaseUrl,
                    target.SupportedLevels
                }).ToArray()
            });
        });

        app.MapGet("/api/engineering/diagnostics/explain", async (
            string applicationId,
            string? instanceId,
            HttpContext c,
            LevelXStateExplainService explain,
            CancellationToken ct) =>
        {
            if (!View(c)) return Results.Forbid();
            try
            {
                LevelXStateExplanation? result = await explain.ExplainAsync(applicationId, instanceId, ct);
                return result is null ? Results.NotFound() : Results.Ok(result);
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        });

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

        app.MapGet("/api/engineering/diagnostics/levelx/catalogue", (HttpContext c, CommonComponentDiagnosticCatalog commonComponents) =>
        {
            if (!View(c)) return Results.Forbid();
            return Results.Ok(new
            {
                tests = commonComponents.Catalogue
                    .OrderBy(x => x.Component, StringComparer.OrdinalIgnoreCase)
                    .ThenByDescending(x => (int)x.IntroducedAtLevel)
                    .ThenBy(x => x.TestId, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                summary = commonComponents.Catalogue
                    .GroupBy(x => new { x.Component, x.IntroducedAtLevel })
                    .Select(g => new { g.Key.Component, level = (int)g.Key.IntroducedAtLevel, count = g.Count() })
                    .OrderBy(x => x.Component)
                    .ThenByDescending(x => x.level)
                    .ToArray(),
                levels = new[]
            {
                new
                {
                    level = 5,
                    name = "Routine",
                    status = "IMPLEMENTED",
                    capabilities = new[]
                    {
                        "Target selection",
                        "Control Plane/component/application targeting",
                        "Health probing",
                        "Registration/telemetry freshness explanation",
                        "State derivation mismatch detection",
                        "Run history and evidence"
                    }
                },
                new
                {
                    level = 4,
                    name = "Integration",
                    status = "PARTIALLY IMPLEMENTED",
                    capabilities = new[]
                    {
                        "Remote diagnostics orchestration",
                        "Cross-application target filtering",
                        "Control Plane component selection",
                        "Existing integration diagnostics from registered applications"
                    }
                },
                new
                {
                    level = 3,
                    name = "Functional",
                    status = "PARTIALLY IMPLEMENTED",
                    capabilities = new[]
                    {
                        "Remote functional diagnostics where applications advertise support",
                        "Target-aware orchestration",
                        "Registration lifecycle automation framework not yet complete"
                    }
                },
                new
                {
                    level = 2,
                    name = "Failure / Recovery",
                    status = "PARTIALLY IMPLEMENTED",
                    capabilities = new[]
                    {
                        "Explicit disruption acknowledgement",
                        "Engineering reason gate",
                        "Isolated failure/recovery probe execution not yet complete"
                    }
                },
                new
                {
                    level = 1,
                    name = "Exhaustive",
                    status = "PARTIALLY IMPLEMENTED",
                    capabilities = new[]
                    {
                        "Explicit disruption acknowledgement",
                        "Exhaustive-level orchestration contract",
                        "14-test isolated Registration certification runner not yet complete"
                    }
                }
            }
            });
        });

        app.MapGet("/api/engineering/diagnostics/capabilities", (HttpContext c, RemoteDiagnosticCatalog catalog) => View(c) ? Results.Ok(catalog.GetCapabilities()) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/telemetry", GetTelemetryAsync);
        app.MapGet("/api/engineering/diagnostics/playbooks", (HttpContext c, DiagnosticPlaybookCatalog catalog) => View(c) ? Results.Ok(catalog.GetAll()) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/incidents", GetIncidentsAsync);
        app.MapGet("/api/engineering/diagnostics/operational-incidents", (bool? includeResolved, HttpContext context, OperationalIncidentStore store) =>
            View(context) ? Results.Ok(store.GetAll(includeResolved ?? true)) : Results.Forbid());
        app.MapGet("/api/engineering/diagnostics/runs", GetRunsAsync);
        app.MapGet("/api/engineering/diagnostics/runs/{runId:guid}", GetRunAsync);
        app.MapPost("/api/engineering/diagnostics/run", RunDiagnosticsAsync);
        app.MapPost("/api/engineering/diagnostics/runs/{runId:guid}/resolve", ResolveRunAsync);
        app.MapGet("/api/engineering/diagnostics/activity", ProxyOperationsActivityAsync);
        app.MapGet("/api/engineering/diagnostics/logs", ProxyOperationsLogsAsync);
        app.MapGet("/api/engineering/diagnostics/flows", ProxyOperationsFlowsAsync);
        app.MapPost("/api/engineering/diagnostics/engineer-log", async (
            HttpContext context,
            IConfiguration configuration,
            CancellationToken ct) =>
        {
            if (!Has(context, "Diagnostics.Run")) return Results.Forbid();
            if (!context.Request.HasFormContentType) return Results.BadRequest(new { error = "Multipart form data is required." });

            IFormCollection form = await context.Request.ReadFormAsync(ct);
            IFormFile? audio = form.Files.GetFile("audio");
            if (audio is null || audio.Length == 0) return Results.BadRequest(new { error = "Audio recording is required." });

            EngineerNote note = await SaveEngineerNoteAsync(context, configuration, "[Audio note]", audio, ct);
            return Results.Ok(note);
        });

        app.MapGet("/api/engineering/diagnostics/engineer-notes", async (
            HttpContext context,
            IConfiguration configuration,
            CancellationToken ct) =>
        {
            if (!View(context)) return Results.Forbid();

            string root = configuration["Diagnostics:EngineerLogPath"]?.Trim()
                ?? Path.Combine(AppContext.BaseDirectory, "data", "engineer-logs");
            Directory.CreateDirectory(root);
            string path = Path.Combine(root, "engineer-notes.json");

            if (!File.Exists(path))
                return Results.Ok(Array.Empty<object>());

            await using FileStream stream = File.OpenRead(path);
            EngineerNote[]? notes = await System.Text.Json.JsonSerializer.DeserializeAsync<EngineerNote[]>(stream, cancellationToken: ct);
            IEnumerable<object> visible = (notes ?? [])
                .OrderByDescending(x => x.CreatedAtUtc)
                .Select(x => new
                {
                    x.Id,
                    x.CreatedAtUtc,
                    x.Engineer,
                    Text = string.Equals(x.Status, "Redacted", StringComparison.OrdinalIgnoreCase)
                        ? "[REDACTED]"
                        : string.Equals(x.Status, "Voided", StringComparison.OrdinalIgnoreCase)
                            ? "[VOIDED] " + x.Text
                            : x.Text,
                    x.Status,
                    x.DispositionAtUtc,
                    x.DispositionBy,
                    x.DispositionReason,
                    hasAudio = !string.IsNullOrWhiteSpace(x.AudioFileName),
                    x.AudioContentType,
                    x.AudioBytes
                });
            return Results.Ok(visible);
        });

        app.MapPost("/api/engineering/diagnostics/engineer-notes", async (
            HttpContext context,
            IConfiguration configuration,
            CancellationToken ct) =>
        {
            if (!Has(context, "Diagnostics.Run")) return Results.Forbid();

            string text;
            IFormFile? audio = null;
            if (context.Request.HasFormContentType)
            {
                IFormCollection form = await context.Request.ReadFormAsync(ct);
                text = form["text"].ToString().Trim();
                audio = form.Files.GetFile("audio");
            }
            else
            {
                EngineerNoteRequest? request = await context.Request.ReadFromJsonAsync<EngineerNoteRequest>(cancellationToken: ct);
                text = request?.Text?.Trim() ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(text) && (audio is null || audio.Length == 0))
                return Results.BadRequest(new { error = "Note text or audio is required." });
            if (text.Length > 4000)
                return Results.BadRequest(new { error = "Note text exceeds the 4000 character limit." });

            EngineerNote note = await SaveEngineerNoteAsync(context, configuration, text, audio, ct);
            return Results.Ok(note);
        });

        app.MapGet("/api/engineering/diagnostics/engineer-notes/{noteId:guid}/audio", async (
            HttpContext context,
            Guid noteId,
            IConfiguration configuration,
            CancellationToken ct) =>
        {
            if (!View(context)) return Results.Forbid();

            string root = configuration["Diagnostics:EngineerLogPath"]?.Trim()
                ?? Path.Combine(AppContext.BaseDirectory, "data", "engineer-logs");
            string notesPath = Path.Combine(root, "engineer-notes.json");
            if (!File.Exists(notesPath)) return Results.NotFound();

            EngineerNote[]? notes;
            await using (FileStream read = File.OpenRead(notesPath))
                notes = await System.Text.Json.JsonSerializer.DeserializeAsync<EngineerNote[]>(read, cancellationToken: ct);

            EngineerNote? note = (notes ?? []).FirstOrDefault(x => x.Id == noteId);
            if (note is null || string.IsNullOrWhiteSpace(note.AudioFileName)) return Results.NotFound();

            string audioPath = Path.Combine(root, note.AudioFileName);
            if (!File.Exists(audioPath)) return Results.NotFound();
            return Results.File(audioPath, note.AudioContentType ?? "audio/webm", enableRangeProcessing: true);
        });

        app.MapPost("/api/engineering/diagnostics/engineer-notes/{noteId:guid}/disposition", async (
            HttpContext context,
            Guid noteId,
            IConfiguration configuration,
            CancellationToken ct) =>
        {
            if (!Has(context, "Security.Manage")) return Results.Forbid();

            EngineerNoteDispositionRequest? request =
                await context.Request.ReadFromJsonAsync<EngineerNoteDispositionRequest>(cancellationToken: ct);

            string action = request?.Action?.Trim() ?? string.Empty;
            string reason = request?.Reason?.Trim() ?? string.Empty;

            if (action is not ("void" or "redact"))
                return Results.BadRequest(new { error = "Action must be 'void' or 'redact'." });
            if (string.IsNullOrWhiteSpace(reason))
                return Results.BadRequest(new { error = "A reason is required." });
            if (reason.Length > 1000)
                return Results.BadRequest(new { error = "Reason exceeds the 1000 character limit." });

            string root = configuration["Diagnostics:EngineerLogPath"]?.Trim()
                ?? Path.Combine(AppContext.BaseDirectory, "data", "engineer-logs");
            Directory.CreateDirectory(root);
            string path = Path.Combine(root, "engineer-notes.json");

            if (!File.Exists(path))
                return Results.NotFound(new { error = "Engineering note store does not exist." });

            EngineerNote[]? existing;
            await using (FileStream read = File.OpenRead(path))
                existing = await System.Text.Json.JsonSerializer.DeserializeAsync<EngineerNote[]>(read, cancellationToken: ct);

            var notes = (existing ?? []).ToList();
            int index = notes.FindIndex(x => x.Id == noteId);
            if (index < 0)
                return Results.NotFound(new { error = "Engineering note not found." });

            EngineerNote current = notes[index];
            if (!string.Equals(current.Status, "Active", StringComparison.OrdinalIgnoreCase))
                return Results.Conflict(new { error = $"Note is already {current.Status}." });

            string status = action == "redact" ? "Redacted" : "Voided";
            EngineerNote updated = current with
            {
                Status = status,
                DispositionAtUtc = DateTimeOffset.UtcNow,
                DispositionBy = OperatorName(context),
                DispositionReason = reason
            };
            notes[index] = updated;

            string temp = path + ".tmp";
            await using (FileStream write = File.Create(temp))
                await System.Text.Json.JsonSerializer.SerializeAsync(write, notes, cancellationToken: ct);
            File.Move(temp, path, true);

            return Results.Ok(new
            {
                updated.Id,
                updated.Status,
                updated.DispositionAtUtc,
                updated.DispositionBy,
                updated.DispositionReason
            });
        });
    }

    private static async Task<EngineerNote> SaveEngineerNoteAsync(
        HttpContext context,
        IConfiguration configuration,
        string text,
        IFormFile? audio,
        CancellationToken ct)
    {
        if (audio is not null && audio.Length > 25 * 1024 * 1024)
            throw new BadHttpRequestException("Recording exceeds the 25 MB limit.");

        string root = configuration["Diagnostics:EngineerLogPath"]?.Trim()
            ?? Path.Combine(AppContext.BaseDirectory, "data", "engineer-logs");
        Directory.CreateDirectory(root);
        string notesPath = Path.Combine(root, "engineer-notes.json");

        var notes = new List<EngineerNote>();
        if (File.Exists(notesPath))
        {
            await using FileStream read = File.OpenRead(notesPath);
            EngineerNote[]? existing = await System.Text.Json.JsonSerializer.DeserializeAsync<EngineerNote[]>(read, cancellationToken: ct);
            if (existing is not null) notes.AddRange(existing);
        }

        string? audioFileName = null;
        string? audioContentType = null;
        long? audioBytes = null;
        if (audio is not null && audio.Length > 0)
        {
            string operatorName = OperatorName(context);
            string safeOperator = string.Concat(operatorName.Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '_'));
            string extension = audio.ContentType.Contains("ogg", StringComparison.OrdinalIgnoreCase) ? ".ogg"
                : audio.ContentType.Contains("wav", StringComparison.OrdinalIgnoreCase) ? ".wav"
                : ".webm";
            audioFileName = $"{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}-{safeOperator}-{Guid.NewGuid():N}{extension}";
            audioContentType = string.IsNullOrWhiteSpace(audio.ContentType) ? "audio/webm" : audio.ContentType;
            audioBytes = audio.Length;
            await using FileStream stream = File.Create(Path.Combine(root, audioFileName));
            await audio.CopyToAsync(stream, ct);
        }

        var note = new EngineerNote(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            OperatorName(context),
            text,
            AudioFileName: audioFileName,
            AudioContentType: audioContentType,
            AudioBytes: audioBytes);

        notes.Add(note);
        string temp = notesPath + ".tmp";
        await using (FileStream write = File.Create(temp))
            await System.Text.Json.JsonSerializer.SerializeAsync(write, notes, cancellationToken: ct);
        File.Move(temp, notesPath, true);
        return note;
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

    private static Task<IResult> ProxyOperationsFlowsAsync(
        HttpContext context,
        IHttpClientFactory factory,
        IConfiguration configuration,
        CancellationToken ct) =>
        ProxyOperationsAsync(
            context,
            factory,
            configuration,
            "/api/operations/activity/flows",
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
