namespace Aegis.Diagnostics;

using Common.Diagnostics;
using Common.Secrets;
using System.Diagnostics;
using System.Net.Http.Json;

public sealed class RemoteDiagnosticCatalog
{
    private readonly IHttpClientFactory httpClientFactory;
    private readonly DiagnosticsOptions options;
    private readonly IDiagnosticTargetCatalog discovery;
    private readonly IConfiguration configuration;
    private readonly IDiagnosticLevelStateExplainService stateExplain;
    private readonly CommonComponentDiagnosticCatalog commonComponents;
    private readonly CommonIsolatedCertificationCatalog isolatedCertifications;

    public RemoteDiagnosticCatalog(
        IHttpClientFactory httpClientFactory,
        DiagnosticsOptions options,
        IDiagnosticTargetCatalog discovery,
        IConfiguration configuration,
        IDiagnosticLevelStateExplainService stateExplain,
        CommonComponentDiagnosticCatalog commonComponents,
        CommonIsolatedCertificationCatalog isolatedCertifications)
    {
        this.httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.discovery = discovery ?? throw new ArgumentNullException(nameof(discovery));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.stateExplain = stateExplain ?? throw new ArgumentNullException(nameof(stateExplain));
        this.commonComponents = commonComponents ?? throw new ArgumentNullException(nameof(commonComponents));
        this.isolatedCertifications = isolatedCertifications ?? throw new ArgumentNullException(nameof(isolatedCertifications));
    }

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build(
        EngineeringDiagnosticLevel requestedLevel,
        string? reason,
        DiagnosticTarget? diagnosticTarget = null)
    {
        DiagnosticTarget targetSelection = diagnosticTarget ?? DiagnosticTarget.EntireControlPlane();
        var checks = new List<EngineeringDiagnosticCheckDefinition>();

        bool includeSelf =
            diagnosticTarget is null ||
            targetSelection.Type == DiagnosticTargetType.ControlPlane ||
            (targetSelection.Type == DiagnosticTargetType.ControlPlaneComponent &&
             string.Equals(targetSelection.TargetId, ControlPlaneDiagnosticTargets.Diagnostics, StringComparison.OrdinalIgnoreCase));

        if (includeSelf)
        {
            checks.Add(new EngineeringDiagnosticCheckDefinition(
                "aegis-diagnostics-self",
                "Aegis.Diagnostics self health",
                EngineeringDiagnosticLevel.Level5Scan,
                ExecuteSelfHealthAsync));
        }

        if (targetSelection.Type == DiagnosticTargetType.ControlPlane)
        {
            checks.Add(new EngineeringDiagnosticCheckDefinition(
                "control-plane-integration",
                "Control Plane cross-service agreement",
                EngineeringDiagnosticLevel.Level4Analysis,
                ExecuteControlPlaneIntegrationAsync));
        }

        if (targetSelection.Type is DiagnosticTargetType.ControlPlane or DiagnosticTargetType.CommonComponent)
        {
            checks.AddRange(commonComponents.Build(targetSelection));
            checks.AddRange(isolatedCertifications.Build(targetSelection));
        }

        IEnumerable<DiagnosticTargetOptions> selectedTargets =
            diagnosticTarget is null ? discovery.Targets : SelectTargets(targetSelection);

        foreach (DiagnosticTargetOptions target in selectedTargets)
        {
            string identity = string.IsNullOrWhiteSpace(target.ApplicationId) ? target.Name : target.ApplicationId;
            string id = $"{identity}-level-{(int)requestedLevel}".ToLowerInvariant().Replace('.', '-');
            string displayName = $"{target.Name} — Level {(int)requestedLevel}";
            string stateId = $"{identity}-state-consistency".ToLowerInvariant().Replace('.', '-');

            checks.Add(new EngineeringDiagnosticCheckDefinition(
                stateId,
                $"{target.Name} — State consistency",
                EngineeringDiagnosticLevel.Level5Scan,
                cancellationToken => ExecuteStateConsistencyAsync(stateId, target, cancellationToken)));

            if (!target.SupportsRemoteDiagnostics)
            {
                if (requestedLevel != EngineeringDiagnosticLevel.Level5Scan)
                {
                    checks.Add(new EngineeringDiagnosticCheckDefinition(
                        id,
                        displayName,
                        requestedLevel,
                        _ => Task.FromResult(NotExecuted(id, displayName, "Application does not advertise remote diagnostics capability.", target.ApplicationId))));
                }
                continue;
            }

            if (!target.SupportedLevels.Contains((int)requestedLevel))
            {
                checks.Add(new EngineeringDiagnosticCheckDefinition(
                    id,
                    displayName,
                    requestedLevel,
                    _ => Task.FromResult(NotExecuted(id, displayName, $"Application does not advertise support for Level {(int)requestedLevel}.", target.ApplicationId))));
                continue;
            }

            checks.Add(new EngineeringDiagnosticCheckDefinition(id, displayName, requestedLevel, cancellationToken => ExecuteRemoteAsync(id, target, requestedLevel, reason, cancellationToken)));
        }
        return checks;
    }

    private IEnumerable<DiagnosticTargetOptions> SelectTargets(DiagnosticTarget selection)
    {
        IEnumerable<DiagnosticTargetOptions> targets = discovery.Targets;

        return selection.Type switch
        {
            DiagnosticTargetType.ControlPlane => targets.Where(IsControlPlaneTarget),
            DiagnosticTargetType.ControlPlaneComponent => selection.TargetId.ToLowerInvariant() switch
            {
                ControlPlaneDiagnosticTargets.Operations => targets.Where(x => string.Equals(x.ApplicationId, "Aegis.Operations", StringComparison.OrdinalIgnoreCase)),
                ControlPlaneDiagnosticTargets.Configuration => targets.Where(x => string.Equals(x.ApplicationId, "Aegis.Configuration", StringComparison.OrdinalIgnoreCase)),
                ControlPlaneDiagnosticTargets.Registration => targets.Where(x => string.Equals(x.ApplicationId, "Aegis.Configuration", StringComparison.OrdinalIgnoreCase)),
                ControlPlaneDiagnosticTargets.Diagnostics => Enumerable.Empty<DiagnosticTargetOptions>(),
                _ => Enumerable.Empty<DiagnosticTargetOptions>()
            },
            DiagnosticTargetType.CommonComponent => Enumerable.Empty<DiagnosticTargetOptions>(),
            DiagnosticTargetType.RegisteredApplication => targets.Where(x =>
                string.Equals(x.ApplicationId, selection.ApplicationId, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(selection.InstanceId) ||
                 string.Equals(x.InstanceId, selection.InstanceId, StringComparison.OrdinalIgnoreCase))),
            _ => Enumerable.Empty<DiagnosticTargetOptions>()
        };
    }

    private static bool IsControlPlaneTarget(DiagnosticTargetOptions target) =>
        target.ApplicationId is not null &&
        (target.ApplicationId.Equals("Aegis.Operations", StringComparison.OrdinalIgnoreCase) ||
         target.ApplicationId.Equals("Aegis.Configuration", StringComparison.OrdinalIgnoreCase));

    public object GetCapabilities() => new
    {
        InventorySource = "Aegis.Configuration",
        DiscoveryLastSuccessfulUtc = discovery.LastSuccessfulRefreshUtc,
        DiscoveryStale = discovery.IsStale,
        DiscoveryError = discovery.LastError,
        Targets = discovery.Targets.Select(target => new
        {
            target.ApplicationId,
            target.Name,
            target.SiteId,
            target.InstanceId,
            target.BaseUrl,
            Protocol = "Common.Diagnostics Engineering Diagnostics v1",
            target.HealthPath,
            target.DiagnosticsRunPath,
            target.DiagnosticsRunsPath,
            target.TelemetryPath,
            target.SupportsRemoteDiagnostics,
            target.SupportsOperationalTelemetry,
            target.AuthenticationScheme,
            CredentialSecretName = target.SecretName,
            target.SupportedLevels,
            target.ConfigurationRegisteredAtUtc
        }).ToArray()
    };

    private async Task<EngineeringDiagnosticCheckResult> ExecuteControlPlaneIntegrationAsync(
        CancellationToken cancellationToken)
    {
        List<string> failures = [];
        List<string> warnings = [];
        List<string> evidence = [];

        if (discovery.LastSuccessfulRefreshUtc is null)
            failures.Add(discovery.LastError ?? "Configuration discovery has never completed successfully.");
        else
        {
            double ageSeconds = Math.Max(
                0,
                (DateTimeOffset.UtcNow - discovery.LastSuccessfulRefreshUtc.Value).TotalSeconds);
            evidence.Add($"ConfigurationDiscoveryLastSuccessfulUtc={discovery.LastSuccessfulRefreshUtc:O}");
            evidence.Add($"ConfigurationDiscoveryAgeSeconds={ageSeconds:0.###}");
            if (discovery.IsStale)
                warnings.Add("Configuration discovery is stale.");
        }

        string[] expectedControlPlaneApps = ["Aegis.Operations", "Aegis.Configuration"];
        foreach (string applicationId in expectedControlPlaneApps)
        {
            DiagnosticTargetOptions? target = discovery.Targets.FirstOrDefault(x =>
                string.Equals(x.ApplicationId, applicationId, StringComparison.OrdinalIgnoreCase));

            if (target is null)
            {
                failures.Add($"{applicationId} is missing from the authoritative registered-application inventory.");
                continue;
            }

            DiagnosticLevelStateExplanation? explanation =
                await stateExplain.ExplainAsync(target.ApplicationId, target.InstanceId, cancellationToken)
                    .ConfigureAwait(false);

            if (explanation is null)
            {
                failures.Add($"{applicationId} is registered but Operations did not return merged state evidence.");
                continue;
            }

            evidence.Add(
                $"{applicationId}: Registration={explanation.RegistrationState}; Effective={explanation.EffectiveState}; " +
                $"RegistrationFresh={explanation.RegistrationFresh}; TelemetryFresh={explanation.TelemetryFresh}; " +
                $"AuthorityAvailable={explanation.AuthorityAvailable}; Codes={string.Join(",", explanation.Codes)}");

            if (!explanation.AuthorityAvailable)
                failures.Add($"{applicationId} cannot confirm Configuration registration authority availability.");

            if (explanation.Codes.Contains(
                    DiagnosticLevelDiagnosticCodes.StateDerivationMismatch,
                    StringComparer.OrdinalIgnoreCase) ||
                explanation.Codes.Contains(
                    DiagnosticLevelDiagnosticCodes.ControlPlaneStateDivergence,
                    StringComparer.OrdinalIgnoreCase))
            {
                failures.Add($"{applicationId} has inconsistent authoritative/runtime state.");
            }
            else if (explanation.Codes.Count > 0)
            {
                warnings.Add($"{applicationId}: {string.Join(",", explanation.Codes)}");
            }
        }

        string evidenceText = string.Join("; ", evidence);

        if (failures.Count > 0)
        {
            return new(
                "control-plane-integration",
                "Control Plane cross-service agreement",
                EngineeringDiagnosticStatus.Failed,
                $"Control Plane integration validation found {failures.Count} failure(s).",
                string.Join(" ", failures.Concat(warnings)) + (evidenceText.Length == 0 ? string.Empty : " " + evidenceText),
                Expected: "Diagnostics must discover Configuration state, read Operations merged state, and agree on current Control Plane authority/runtime state.",
                Actual: string.Join(" | ", failures.Concat(warnings)),
                Code: DiagnosticLevelDiagnosticCodes.ControlPlaneStateDivergence);
        }

        if (warnings.Count > 0)
        {
            return new(
                "control-plane-integration",
                "Control Plane cross-service agreement",
                EngineeringDiagnosticStatus.Warning,
                $"Control Plane integration validation completed with {warnings.Count} warning(s).",
                string.Join(" ", warnings) + (evidenceText.Length == 0 ? string.Empty : " " + evidenceText),
                Expected: "Control Plane cross-service state is current and internally consistent.",
                Actual: string.Join(" | ", warnings));
        }

        return new(
            "control-plane-integration",
            "Control Plane cross-service agreement",
            EngineeringDiagnosticStatus.Passed,
            "Configuration discovery, Operations merged state and registration authority evidence agree.",
            evidenceText,
            Expected: "Control Plane cross-service state is current and internally consistent.",
            Actual: "All required Control Plane evidence paths agreed.");
    }

    private async Task<EngineeringDiagnosticCheckResult> ExecuteStateConsistencyAsync(
        string id,
        DiagnosticTargetOptions target,
        CancellationToken cancellationToken)
    {
        DiagnosticLevelStateExplanation? explanation =
            await stateExplain.ExplainAsync(target.ApplicationId, target.InstanceId, cancellationToken)
                .ConfigureAwait(false);

        if (explanation is null)
        {
            return new(
                id,
                $"{target.Name} — State consistency",
                EngineeringDiagnosticStatus.Warning,
                "Application is registered but is not present in the merged Operations application inventory.",
                target.ApplicationId,
                Expected: "Authoritative registration and Operations effective state are both observable.",
                Actual: "No merged application state was returned.",
                Code: DiagnosticLevelDiagnosticCodes.ControlPlaneStateDivergence);
        }

        EngineeringDiagnosticStatus status = explanation.Result switch
        {
            "Failed" => EngineeringDiagnosticStatus.Failed,
            "Warning" => EngineeringDiagnosticStatus.Warning,
            _ => EngineeringDiagnosticStatus.Passed
        };

        string evidence = string.Join(
            "; ",
            new[]
            {
                $"NowUtc={explanation.NowUtc:O}",
                $"LastAuthenticatedAtUtc={explanation.LastAuthenticatedAtUtc:O}",
                $"AuthenticationAgeSeconds={explanation.AuthenticationAgeSeconds?.ToString("0.###") ?? "null"}",
                $"LastTelemetryAtUtc={explanation.LastTelemetryAtUtc:O}",
                $"TelemetryAgeSeconds={explanation.TelemetryAgeSeconds?.ToString("0.###") ?? "null"}",
                $"StaleAfterSeconds={explanation.StaleAfterSeconds:0.###}",
                $"RegistrationFresh={explanation.RegistrationFresh}",
                $"TelemetryFresh={explanation.TelemetryFresh}",
                $"AuthorityAvailable={explanation.AuthorityAvailable}",
                $"EffectiveState={explanation.EffectiveState}",
                $"DisplayedState={explanation.DisplayedState ?? "null"}",
                $"Codes={string.Join(",", explanation.Codes)}"
            });

        string? code = explanation.Codes.Count == 0
            ? null
            : string.Join(",", explanation.Codes);

        return new(
            id,
            $"{target.Name} — State consistency",
            status,
            string.IsNullOrWhiteSpace(explanation.Reason)
                ? "Registration, telemetry and effective-state evidence are consistent."
                : explanation.Reason,
            evidence,
            Expected: "Fresh authority/telemetry evidence must reconcile to a consistent effective and displayed state.",
            Actual: $"Registration={explanation.RegistrationState}; Effective={explanation.EffectiveState}; Displayed={explanation.DisplayedState ?? "null"}",
            Code: code);
    }

    private async Task<EngineeringDiagnosticCheckResult> ExecuteSelfHealthAsync(CancellationToken cancellationToken)
    {
        const string id = "aegis-diagnostics-self";
        const string name = "Aegis.Diagnostics self health";
        Stopwatch stopwatch = Stopwatch.StartNew();
        List<string> failures = [];
        List<string> warnings = [];
        List<string> evidence = [];

        if (string.IsNullOrWhiteSpace(options.ApplicationId)) failures.Add("ApplicationId is not configured.");
        if (string.IsNullOrWhiteSpace(options.ApplicationName)) failures.Add("ApplicationName is not configured.");
        if (string.IsNullOrWhiteSpace(options.RunStorePath)) failures.Add("RunStorePath is not configured.");

        if (options.RequireApiKey)
        {
            if (string.IsNullOrWhiteSpace(options.ApiKeyHeader)) failures.Add("Machine authentication is enabled but ApiKeyHeader is not configured.");
            if (string.IsNullOrWhiteSpace(options.MachineCredentialSecretName)) failures.Add("Machine authentication is enabled but MachineCredentialSecretName is not configured.");
            else
            {
                try
                {
                    ISecretProvider secrets = CommonSecretProviderFactory.Create(configuration);
                    string? machineCredential = await secrets.GetAsync(options.MachineCredentialSecretName, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(machineCredential)) warnings.Add($"Machine credential secret '{options.MachineCredentialSecretName}' is not currently resolvable.");
                    else evidence.Add("Diagnostics machine credential resolves through Common.Secrets; value not displayed.");
                }
                catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
                {
                    warnings.Add($"Machine credential verification failed through Common.Secrets ({exception.GetType().Name}).");
                }
            }
        }

        if (discovery.LastSuccessfulRefreshUtc is null)
            warnings.Add(discovery.LastError ?? "Aegis.Configuration discovery has not completed successfully yet.");
        else if (discovery.IsStale)
            warnings.Add($"Aegis.Configuration discovery is stale; last successful refresh was {discovery.LastSuccessfulRefreshUtc:O}.");

        foreach (DiagnosticTargetOptions target in discovery.Targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(target.ApplicationId)) warnings.Add($"Discovered target '{target.Name}' has no ApplicationId.");
            if (string.IsNullOrWhiteSpace(target.BaseUrl)) warnings.Add($"Discovered target '{target.ApplicationId}' has no resolved public URL.");
            else if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out _)) failures.Add($"Discovered target '{target.ApplicationId}' has an invalid public URL.");
            if (target.SupportsRemoteDiagnostics && string.IsNullOrWhiteSpace(target.SecretName)) warnings.Add($"Discovered target '{target.ApplicationId}' supports remote diagnostics but publishes no machine-credential secret name.");
        }

        if (!string.IsNullOrWhiteSpace(options.RunStorePath))
        {
            try
            {
                string fullPath = Path.GetFullPath(options.RunStorePath);
                string? directory = Path.GetDirectoryName(fullPath);
                if (string.IsNullOrWhiteSpace(directory)) failures.Add("Run-store directory could not be resolved.");
                else
                {
                    Directory.CreateDirectory(directory);
                    string probePath = Path.Combine(directory, $".aegis-diagnostics-write-probe-{Guid.NewGuid():N}.tmp");
                    await File.WriteAllTextAsync(probePath, "diagnostics-self-check", cancellationToken).ConfigureAwait(false);
                    File.Delete(probePath);
                    evidence.Add($"Run-store directory is writable: {directory}");
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                failures.Add($"Run-store path is not writable ({exception.GetType().Name}).");
            }
        }

        evidence.Add($"Configuration discovery catalog loaded: {discovery.Targets.Count} diagnostic-capable application(s).");
        evidence.Add("Common.Diagnostics executed this self-check through the engineering diagnostic pipeline.");
        stopwatch.Stop();

        if (failures.Count > 0)
            return new(id, name, EngineeringDiagnosticStatus.Failed, $"Aegis.Diagnostics self-check failed with {failures.Count} problem(s).", string.Join(" ", failures.Concat(warnings).Concat(evidence)) + $" Elapsed={stopwatch.ElapsedMilliseconds} ms.");

        if (warnings.Count > 0)
            return new(id, name, EngineeringDiagnosticStatus.Warning, $"Aegis.Diagnostics self-check completed with {warnings.Count} warning(s).", string.Join(" ", warnings.Concat(evidence)) + $" Elapsed={stopwatch.ElapsedMilliseconds} ms.");

        return new(id, name, EngineeringDiagnosticStatus.Passed, "Aegis.Diagnostics self-check passed.", string.Join(" ", evidence) + $" Elapsed={stopwatch.ElapsedMilliseconds} ms.");
    }

    private async Task<EngineeringDiagnosticCheckResult> ExecuteRemoteAsync(string id, DiagnosticTargetOptions target, EngineeringDiagnosticLevel level, string? reason, CancellationToken cancellationToken)
    {
        string displayName = $"{target.Name} — Level {(int)level}";
        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri)) return Warning(id, displayName, "Application public URL is unresolved in Configuration.", target.ApplicationId);

        string? credential = null;
        if (string.Equals(target.AuthenticationScheme, "MachineCredential", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(target.SecretName)) return Warning(id, displayName, "Machine credential secret name is not published by the application.");
            try
            {
                ISecretProvider secrets = CommonSecretProviderFactory.Create(configuration);
                credential = await secrets.GetAsync(target.SecretName, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                return Warning(id, displayName, "Machine authentication credential could not be resolved through Common.Secrets.", exception.GetType().Name);
            }
            if (string.IsNullOrWhiteSpace(credential)) return Warning(id, displayName, "Machine authentication credential is unavailable through Common.Secrets.", target.SecretName);
        }

        HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
        Stopwatch stopwatch = Stopwatch.StartNew();
        try
        {
            if (level == EngineeringDiagnosticLevel.Level5Scan)
            {
                Uri healthUri = new(baseUri, target.HealthPath);
                using HttpRequestMessage healthRequest = new(HttpMethod.Get, healthUri);
                AddCredential(healthRequest, credential);
                using HttpResponseMessage healthResponse = await client.SendAsync(healthRequest, cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();
                string evidence = $"HTTP {(int)healthResponse.StatusCode} in {stopwatch.ElapsedMilliseconds} ms — {healthUri}";
                return healthResponse.IsSuccessStatusCode ? new(id, displayName, EngineeringDiagnosticStatus.Passed, "Application-reported quick health is reachable.", evidence) : new(id, displayName, EngineeringDiagnosticStatus.Failed, "Application health endpoint reported failure.", evidence);
            }

            Uri runUri = new(baseUri, target.DiagnosticsRunPath);
            using HttpRequestMessage runRequest = new(HttpMethod.Post, runUri) { Content = JsonContent.Create(new EngineeringDiagnosticRunRequest(level, reason)) };
            AddCredential(runRequest, credential);
            using HttpResponseMessage runResponse = await client.SendAsync(runRequest, cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            if (!runResponse.IsSuccessStatusCode) return new(id, displayName, EngineeringDiagnosticStatus.Failed, "Application diagnostics endpoint returned an unsuccessful status.", $"HTTP {(int)runResponse.StatusCode} in {stopwatch.ElapsedMilliseconds} ms — {runUri}");
            EngineeringDiagnosticRun? remoteRun = await runResponse.Content.ReadFromJsonAsync<EngineeringDiagnosticRun>(cancellationToken: cancellationToken).ConfigureAwait(false);
            if (remoteRun is null) return new(id, displayName, EngineeringDiagnosticStatus.Failed, "Application diagnostics response could not be read.");
            int failed = remoteRun.Checks.Count(x => x.Status == EngineeringDiagnosticStatus.Failed);
            int warnings = remoteRun.Checks.Count(x => x.Status is EngineeringDiagnosticStatus.Warning or EngineeringDiagnosticStatus.InterventionRequired);
            string summary = remoteRun.Status switch { EngineeringDiagnosticStatus.Failed => $"Application Level {(int)level} diagnostics reported {failed} failure(s).", EngineeringDiagnosticStatus.Warning => $"Application Level {(int)level} diagnostics reported {warnings} warning(s).", EngineeringDiagnosticStatus.InterventionRequired => "Application diagnostics require engineering intervention.", _ => $"Application Level {(int)level} diagnostics passed." };
            return new(id, displayName, remoteRun.Status, summary, $"Run {remoteRun.RunId:D}; checks={remoteRun.Checks.Count}; failed={failed}; warnings={warnings}; elapsed={stopwatch.ElapsedMilliseconds} ms.");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested) { stopwatch.Stop(); return new(id, displayName, EngineeringDiagnosticStatus.Failed, "Application diagnostics request timed out.", $"Elapsed {stopwatch.ElapsedMilliseconds} ms."); }
        catch (HttpRequestException exception) { stopwatch.Stop(); return new(id, displayName, EngineeringDiagnosticStatus.Failed, "Application diagnostics endpoint could not be reached.", $"{exception.GetType().Name}; elapsed={stopwatch.ElapsedMilliseconds} ms."); }
    }

    private static EngineeringDiagnosticCheckResult NotExecuted(string id, string name, string reason, string? evidence = null)
        => new(id, name, EngineeringDiagnosticStatus.Warning, $"NOT EXECUTED — {reason}", evidence);

    private static EngineeringDiagnosticCheckResult Warning(string id, string name, string summary, string? evidence = null) => new(id, name, EngineeringDiagnosticStatus.Warning, summary, evidence);
    private static void AddCredential(HttpRequestMessage request, string? credential) { if (!string.IsNullOrWhiteSpace(credential)) request.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Key", credential); }
}
