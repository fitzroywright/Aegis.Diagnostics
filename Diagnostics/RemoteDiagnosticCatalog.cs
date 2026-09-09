namespace Aegis.Diagnostics;

using Common.Diagnostics;
using System.Diagnostics;

public sealed class RemoteDiagnosticCatalog
{
    private readonly IHttpClientFactory httpClientFactory;
    private readonly DiagnosticsOptions options;

    public RemoteDiagnosticCatalog(IHttpClientFactory httpClientFactory, DiagnosticsOptions options)
    {
        this.httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build()
    {
        List<EngineeringDiagnosticCheckDefinition> checks = [];

        foreach (DiagnosticTargetOptions target in options.Targets)
        {
            Add(checks, target, EngineeringDiagnosticLevel.Level5Scan, target.Level5Path, "Quick health");
            Add(checks, target, EngineeringDiagnosticLevel.Level4Analysis, target.Level4Path, "Component diagnostics");
            Add(checks, target, EngineeringDiagnosticLevel.Level3Verification, target.Level3Path, "System diagnostics");
            Add(checks, target, EngineeringDiagnosticLevel.Level2Repair, target.Level2Path, "Integration diagnostics");
            Add(checks, target, EngineeringDiagnosticLevel.Level1CriticalIntervention, target.Level1Path, "Full system diagnostics");
        }

        checks.Add(new EngineeringDiagnosticCheckDefinition(
            "aegis-diagnostics-self",
            "Aegis.Diagnostics self health",
            EngineeringDiagnosticLevel.Level5Scan,
            _ => Task.FromResult(new EngineeringDiagnosticCheckResult(
                "aegis-diagnostics-self",
                "Aegis.Diagnostics self health",
                EngineeringDiagnosticStatus.Passed,
                "Diagnostics console and engine are running."))));

        return checks;
    }

    private void Add(List<EngineeringDiagnosticCheckDefinition> checks, DiagnosticTargetOptions target, EngineeringDiagnosticLevel introducedAt, string path, string name)
    {
        string id = $"{target.Name}-{(int)introducedAt}".ToLowerInvariant().Replace('.', '-');
        checks.Add(new EngineeringDiagnosticCheckDefinition(id, $"{target.Name} — {name}", introducedAt, cancellationToken => ProbeAsync(id, target, path, name, cancellationToken)));
    }

    private async Task<EngineeringDiagnosticCheckResult> ProbeAsync(string id, DiagnosticTargetOptions target, string path, string name, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri))
        {
            return new EngineeringDiagnosticCheckResult(id, $"{target.Name} — {name}", EngineeringDiagnosticStatus.Warning, "Target URL is not configured correctly.", target.BaseUrl);
        }

        Uri uri = new(baseUri, path);
        HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            using HttpResponseMessage response = await client.GetAsync(uri, cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            string evidence = $"HTTP {(int)response.StatusCode} in {stopwatch.ElapsedMilliseconds} ms — {uri}";
            return response.IsSuccessStatusCode
                ? new EngineeringDiagnosticCheckResult(id, $"{target.Name} — {name}", EngineeringDiagnosticStatus.Passed, "Endpoint responded successfully.", evidence)
                : new EngineeringDiagnosticCheckResult(id, $"{target.Name} — {name}", EngineeringDiagnosticStatus.Failed, "Endpoint returned an unsuccessful status.", evidence);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            return new EngineeringDiagnosticCheckResult(id, $"{target.Name} — {name}", EngineeringDiagnosticStatus.Failed, "Endpoint timed out.", $"{stopwatch.ElapsedMilliseconds} ms — {uri}");
        }
        catch (HttpRequestException exception)
        {
            stopwatch.Stop();
            return new EngineeringDiagnosticCheckResult(id, $"{target.Name} — {name}", EngineeringDiagnosticStatus.Failed, "Endpoint could not be reached.", $"{exception.GetType().Name} after {stopwatch.ElapsedMilliseconds} ms — {uri}");
        }
    }
}
