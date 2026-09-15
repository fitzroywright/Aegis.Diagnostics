namespace Aegis.Diagnostics;

using Common.Diagnostics;
using System.Diagnostics;
using System.Net.Http.Json;

public sealed class RemoteDiagnosticCatalog
{
    private readonly IHttpClientFactory httpClientFactory;
    private readonly DiagnosticsOptions options;

    public RemoteDiagnosticCatalog(IHttpClientFactory httpClientFactory, DiagnosticsOptions options)
    {
        this.httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build(EngineeringDiagnosticLevel requestedLevel, string? reason)
    {
        List<EngineeringDiagnosticCheckDefinition> checks = [];
        checks.Add(new EngineeringDiagnosticCheckDefinition(
            "aegis-diagnostics-self",
            "Aegis.Diagnostics self health",
            EngineeringDiagnosticLevel.Level5Scan,
            ExecuteSelfHealthAsync));

        foreach (DiagnosticTargetOptions target in options.Targets)
        {
            string identity = string.IsNullOrWhiteSpace(target.ApplicationId) ? target.Name : target.ApplicationId;
            string id = $"{identity}-level-{(int)requestedLevel}".ToLowerInvariant().Replace('.', '-');
            checks.Add(new EngineeringDiagnosticCheckDefinition(id, $"{target.Name} — Level {(int)requestedLevel}", requestedLevel, cancellationToken => ExecuteRemoteAsync(id, target, requestedLevel, reason, cancellationToken)));
        }
        return checks;
    }

    public object GetCapabilities() => options.Targets.Select(target => new
    {
        target.ApplicationId, target.Name, target.SiteId, target.InstanceId, target.ApplicationType, target.BaseUrl,
        Protocol = "Common.Diagnostics Engineering Diagnostics v1", target.HealthPath, target.DiagnosticsRunPath,
        target.DiagnosticsRunsPath, target.RequireMachineCredential, target.ApiKeyHeader,
        CredentialAvailable = !target.RequireMachineCredential || HasCredential(target)
    }).ToArray();

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

        foreach (DiagnosticTargetOptions target in options.Targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string targetName = string.IsNullOrWhiteSpace(target.ApplicationId) ? target.Name : target.ApplicationId;
            if (string.IsNullOrWhiteSpace(target.ApplicationId)) warnings.Add($"Target '{target.Name}' has no ApplicationId.");
            if (string.IsNullOrWhiteSpace(target.Name)) warnings.Add($"Target '{targetName}' has no display name.");
            if (!string.IsNullOrWhiteSpace(target.BaseUrl) && !Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out _)) failures.Add($"Target '{targetName}' has an invalid BaseUrl.");
            if (target.RequireMachineCredential && string.IsNullOrWhiteSpace(target.ApiKeyEnvironmentVariable)) warnings.Add($"Target '{targetName}' requires a machine credential but no credential environment variable is configured.");
        }

        if (!string.IsNullOrWhiteSpace(options.RunStorePath))
        {
            try
            {
                string fullPath = Path.GetFullPath(options.RunStorePath);
                string? directory = Path.GetDirectoryName(fullPath);
                if (string.IsNullOrWhiteSpace(directory))
                {
                    failures.Add("Run-store directory could not be resolved.");
                }
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

        evidence.Add($"Target catalog loaded: {options.Targets.Count} target(s)");
        evidence.Add("Common.Diagnostics executed this self-check through the engineering diagnostic pipeline.");
        stopwatch.Stop();

        if (failures.Count > 0)
        {
            string summary = $"Aegis.Diagnostics self-check failed with {failures.Count} problem(s).";
            string detail = string.Join(" ", failures.Concat(warnings).Concat(evidence)) + $" Elapsed={stopwatch.ElapsedMilliseconds} ms.";
            return new EngineeringDiagnosticCheckResult(id, name, EngineeringDiagnosticStatus.Failed, summary, detail);
        }

        if (warnings.Count > 0)
        {
            string summary = $"Aegis.Diagnostics self-check completed with {warnings.Count} warning(s).";
            string detail = string.Join(" ", warnings.Concat(evidence)) + $" Elapsed={stopwatch.ElapsedMilliseconds} ms.";
            return new EngineeringDiagnosticCheckResult(id, name, EngineeringDiagnosticStatus.Warning, summary, detail);
        }

        return new EngineeringDiagnosticCheckResult(
            id,
            name,
            EngineeringDiagnosticStatus.Passed,
            "Aegis.Diagnostics self-check passed.",
            string.Join(" ", evidence) + $" Elapsed={stopwatch.ElapsedMilliseconds} ms.");
    }

    private async Task<EngineeringDiagnosticCheckResult> ExecuteRemoteAsync(string id, DiagnosticTargetOptions target, EngineeringDiagnosticLevel level, string? reason, CancellationToken cancellationToken)
    {
        string displayName = $"{target.Name} — Level {(int)level}";
        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri)) return Warning(id, displayName, "Target URL is not configured correctly.", target.BaseUrl);
        string? credential = GetCredential(target);
        if (target.RequireMachineCredential && string.IsNullOrWhiteSpace(credential)) return Warning(id, displayName, "Machine authentication credential is not available.", $"Configure environment variable {target.ApiKeyEnvironmentVariable ?? "<not configured>"}.");
        HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
        Stopwatch stopwatch = Stopwatch.StartNew();
        try
        {
            if (level == EngineeringDiagnosticLevel.Level5Scan)
            {
                Uri healthUri = new(baseUri, target.HealthPath);
                using HttpRequestMessage healthRequest = new(HttpMethod.Get, healthUri);
                AddCredential(healthRequest, target, credential);
                using HttpResponseMessage healthResponse = await client.SendAsync(healthRequest, cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();
                string evidence = $"HTTP {(int)healthResponse.StatusCode} in {stopwatch.ElapsedMilliseconds} ms — {healthUri}";
                return healthResponse.IsSuccessStatusCode ? new(id, displayName, EngineeringDiagnosticStatus.Passed, "Application-reported quick health is reachable.", evidence) : new(id, displayName, EngineeringDiagnosticStatus.Failed, "Application health endpoint reported failure.", evidence);
            }
            Uri runUri = new(baseUri, target.DiagnosticsRunPath);
            using HttpRequestMessage runRequest = new(HttpMethod.Post, runUri) { Content = JsonContent.Create(new EngineeringDiagnosticRunRequest(level, reason)) };
            AddCredential(runRequest, target, credential);
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
    private static bool HasCredential(DiagnosticTargetOptions target) => !string.IsNullOrWhiteSpace(GetCredential(target));
    private static string? GetCredential(DiagnosticTargetOptions target) => string.IsNullOrWhiteSpace(target.ApiKeyEnvironmentVariable) ? null : Environment.GetEnvironmentVariable(target.ApiKeyEnvironmentVariable);
    private static void AddCredential(HttpRequestMessage request, DiagnosticTargetOptions target, string? credential) { if (!string.IsNullOrWhiteSpace(credential)) request.Headers.TryAddWithoutValidation(target.ApiKeyHeader, credential); }
}
