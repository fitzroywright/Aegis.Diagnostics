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

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build(
        EngineeringDiagnosticLevel requestedLevel,
        string? reason)
    {
        List<EngineeringDiagnosticCheckDefinition> checks = [];

        checks.Add(new EngineeringDiagnosticCheckDefinition(
            "aegis-diagnostics-self",
            "Aegis.Diagnostics self health",
            EngineeringDiagnosticLevel.Level5Scan,
            _ => Task.FromResult(new EngineeringDiagnosticCheckResult(
                "aegis-diagnostics-self",
                "Aegis.Diagnostics self health",
                EngineeringDiagnosticStatus.Passed,
                "Diagnostics console and Common.Diagnostics engine are running."))));

        foreach (DiagnosticTargetOptions target in options.Targets)
        {
            string id = $"{target.Name}-level-{(int)requestedLevel}".ToLowerInvariant().Replace('.', '-');
            checks.Add(new EngineeringDiagnosticCheckDefinition(
                id,
                $"{target.Name} — Level {(int)requestedLevel}",
                requestedLevel,
                cancellationToken => ExecuteRemoteAsync(id, target, requestedLevel, reason, cancellationToken)));
        }

        return checks;
    }

    public object GetCapabilities()
    {
        return options.Targets.Select(target => new
        {
            target.Name,
            target.ApplicationType,
            target.BaseUrl,
            Protocol = "Common.Diagnostics Engineering Diagnostics v1",
            target.HealthPath,
            target.DiagnosticsRunPath,
            target.DiagnosticsRunsPath,
            target.RequireMachineCredential,
            target.ApiKeyHeader,
            CredentialAvailable = !target.RequireMachineCredential || HasCredential(target)
        }).ToArray();
    }

    private async Task<EngineeringDiagnosticCheckResult> ExecuteRemoteAsync(
        string id,
        DiagnosticTargetOptions target,
        EngineeringDiagnosticLevel level,
        string? reason,
        CancellationToken cancellationToken)
    {
        string displayName = $"{target.Name} — Level {(int)level}";
        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri))
        {
            return Warning(id, displayName, "Target URL is not configured correctly.", target.BaseUrl);
        }

        string? credential = GetCredential(target);
        if (target.RequireMachineCredential && string.IsNullOrWhiteSpace(credential))
        {
            return Warning(
                id,
                displayName,
                "Machine authentication credential is not available.",
                $"Configure environment variable {target.ApiKeyEnvironmentVariable ?? "<not configured>"}.");
        }

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
                return healthResponse.IsSuccessStatusCode
                    ? new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Passed, "Remote quick health check passed.", evidence)
                    : new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Remote quick health check failed.", evidence);
            }

            Uri runUri = new(baseUri, target.DiagnosticsRunPath);
            using HttpRequestMessage runRequest = new(HttpMethod.Post, runUri)
            {
                Content = JsonContent.Create(new EngineeringDiagnosticRunRequest(level, reason))
            };
            AddCredential(runRequest, target, credential);

            using HttpResponseMessage runResponse = await client.SendAsync(runRequest, cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            if (!runResponse.IsSuccessStatusCode)
            {
                return new EngineeringDiagnosticCheckResult(
                    id,
                    displayName,
                    EngineeringDiagnosticStatus.Failed,
                    "Remote diagnostics endpoint returned an unsuccessful status.",
                    $"HTTP {(int)runResponse.StatusCode} in {stopwatch.ElapsedMilliseconds} ms — {runUri}");
            }

            EngineeringDiagnosticRun? remoteRun = await runResponse.Content.ReadFromJsonAsync<EngineeringDiagnosticRun>(cancellationToken: cancellationToken).ConfigureAwait(false);
            if (remoteRun is null)
            {
                return new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Remote diagnostics response could not be read.");
            }

            EngineeringDiagnosticStatus status = remoteRun.Status;
            int failed = remoteRun.Checks.Count(result => result.Status == EngineeringDiagnosticStatus.Failed);
            int warnings = remoteRun.Checks.Count(result => result.Status is EngineeringDiagnosticStatus.Warning or EngineeringDiagnosticStatus.InterventionRequired);
            string summary = status switch
            {
                EngineeringDiagnosticStatus.Failed => $"Remote Level {(int)level} diagnostics reported {failed} failure(s).",
                EngineeringDiagnosticStatus.Warning => $"Remote Level {(int)level} diagnostics reported {warnings} warning(s).",
                EngineeringDiagnosticStatus.InterventionRequired => $"Remote Level {(int)level} diagnostics require engineering intervention.",
                _ => $"Remote Level {(int)level} diagnostics passed."
            };

            return new EngineeringDiagnosticCheckResult(
                id,
                displayName,
                status,
                summary,
                $"Run {remoteRun.RunId:D}; checks={remoteRun.Checks.Count}; failed={failed}; warnings={warnings}; elapsed={stopwatch.ElapsedMilliseconds} ms.");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            return new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Remote diagnostics request timed out.", $"Elapsed {stopwatch.ElapsedMilliseconds} ms.");
        }
        catch (HttpRequestException exception)
        {
            stopwatch.Stop();
            return new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Remote diagnostics endpoint could not be reached.", $"{exception.GetType().Name}; elapsed={stopwatch.ElapsedMilliseconds} ms.");
        }
    }

    private static EngineeringDiagnosticCheckResult Warning(string id, string name, string summary, string? evidence = null)
        => new(id, name, EngineeringDiagnosticStatus.Warning, summary, evidence);

    private static bool HasCredential(DiagnosticTargetOptions target)
        => !string.IsNullOrWhiteSpace(GetCredential(target));

    private static string? GetCredential(DiagnosticTargetOptions target)
        => string.IsNullOrWhiteSpace(target.ApiKeyEnvironmentVariable)
            ? null
            : Environment.GetEnvironmentVariable(target.ApiKeyEnvironmentVariable);

    private static void AddCredential(HttpRequestMessage request, DiagnosticTargetOptions target, string? credential)
    {
        if (!string.IsNullOrWhiteSpace(credential))
        {
            request.Headers.TryAddWithoutValidation(target.ApiKeyHeader, credential);
        }
    }
}
