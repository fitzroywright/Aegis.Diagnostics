namespace Aegis.Diagnostics;

using Common.Diagnostics;
using Common.Secrets;
using System.Diagnostics;
using System.Net.Http.Json;

public sealed class RemoteDiagnosticCatalog
{
    private readonly IHttpClientFactory httpClientFactory;
    private readonly DiagnosticsOptions options;
    private readonly ConfigurationDiscoveryCatalog discovery;
    private readonly IConfiguration configuration;

    public RemoteDiagnosticCatalog(
        IHttpClientFactory httpClientFactory,
        DiagnosticsOptions options,
        ConfigurationDiscoveryCatalog discovery,
        IConfiguration configuration)
    {
        this.httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.discovery = discovery ?? throw new ArgumentNullException(nameof(discovery));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build(EngineeringDiagnosticLevel requestedLevel, string? reason)
    {
        List<EngineeringDiagnosticCheckDefinition> checks =
        [
            new EngineeringDiagnosticCheckDefinition(
                "aegis-diagnostics-self",
                "Aegis.Diagnostics self health",
                EngineeringDiagnosticLevel.Level5Scan,
                ExecuteSelfHealthAsync)
        ];

        foreach (DiagnosticTargetOptions target in discovery.Targets)
        {
            if (!target.SupportsRemoteDiagnostics) continue;
            if (!target.SupportedLevels.Contains((int)requestedLevel)) continue;
            string identity = string.IsNullOrWhiteSpace(target.ApplicationId) ? target.Name : target.ApplicationId;
            string id = $"{identity}-level-{(int)requestedLevel}".ToLowerInvariant().Replace('.', '-');
            checks.Add(new EngineeringDiagnosticCheckDefinition(id, $"{target.Name} — Level {(int)requestedLevel}", requestedLevel, cancellationToken => ExecuteRemoteAsync(id, target, requestedLevel, reason, cancellationToken)));
        }
        return checks;
    }

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
            target.SupportsRemoteDiagnostics,
            target.AuthenticationScheme,
            CredentialSecretName = target.SecretName,
            target.SupportedLevels,
            target.ConfigurationRegisteredAtUtc
        }).ToArray()
    };

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
            if (string.IsNullOrWhiteSpace(options.ApiKeyHeader)) failures.Add("API-key authentication is enabled but ApiKeyHeader is not configured.");
            if (string.IsNullOrWhiteSpace(options.ApiKeyEnvironmentVariable)) failures.Add("API-key authentication is enabled but ApiKeyEnvironmentVariable is not configured.");
            else if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(options.ApiKeyEnvironmentVariable))) warnings.Add($"API-key environment variable {options.ApiKeyEnvironmentVariable} is not currently available.");
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

    private static EngineeringDiagnosticCheckResult Warning(string id, string name, string summary, string? evidence = null) => new(id, name, EngineeringDiagnosticStatus.Warning, summary, evidence);
    private static void AddCredential(HttpRequestMessage request, string? credential) { if (!string.IsNullOrWhiteSpace(credential)) request.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Key", credential); }
}
