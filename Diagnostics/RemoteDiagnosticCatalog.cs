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
            foreach (DiagnosticProbeOptions probe in target.Probes.Where(probe => probe.Enabled))
            {
                EngineeringDiagnosticLevel level = ParseLevel(probe.Level);
                string id = string.IsNullOrWhiteSpace(probe.Id)
                    ? $"{target.Name}-{probe.Level}-{probe.Name}".ToLowerInvariant().Replace(' ', '-').Replace('.', '-')
                    : probe.Id;

                checks.Add(new EngineeringDiagnosticCheckDefinition(
                    id,
                    $"{target.Name} — {probe.Name}",
                    level,
                    cancellationToken => ProbeAsync(id, target, probe, cancellationToken)));
            }

            foreach (string component in target.CommonComponents.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string id = $"{target.Name}-component-{component}".ToLowerInvariant().Replace('.', '-');
                checks.Add(new EngineeringDiagnosticCheckDefinition(
                    id,
                    $"{target.Name} — {component} adoption",
                    EngineeringDiagnosticLevel.Level4Analysis,
                    _ => Task.FromResult(new EngineeringDiagnosticCheckResult(
                        id,
                        $"{target.Name} — {component} adoption",
                        EngineeringDiagnosticStatus.Passed,
                        $"{component} is declared as an application dependency in the diagnostics inventory."))));
            }
        }

        checks.Add(new EngineeringDiagnosticCheckDefinition(
            "aegis-diagnostics-self",
            "Aegis.Diagnostics self health",
            EngineeringDiagnosticLevel.Level5Scan,
            _ => Task.FromResult(new EngineeringDiagnosticCheckResult(
                "aegis-diagnostics-self",
                "Aegis.Diagnostics self health",
                EngineeringDiagnosticStatus.Passed,
                "Diagnostics console and Common.Diagnostics engine are running."))));

        return checks;
    }

    public object GetCapabilities()
    {
        return options.Targets.Select(target => new
        {
            target.Name,
            target.ApplicationType,
            target.BaseUrl,
            CommonComponents = target.CommonComponents,
            Probes = target.Probes.Select(probe => new
            {
                probe.Id,
                probe.Name,
                probe.Level,
                probe.Path,
                probe.Method,
                probe.Enabled,
                probe.RequiresAuthentication
            })
        }).ToArray();
    }

    private async Task<EngineeringDiagnosticCheckResult> ProbeAsync(
        string id,
        DiagnosticTargetOptions target,
        DiagnosticProbeOptions probe,
        CancellationToken cancellationToken)
    {
        string displayName = $"{target.Name} — {probe.Name}";

        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri))
        {
            return new EngineeringDiagnosticCheckResult(
                id,
                displayName,
                EngineeringDiagnosticStatus.Warning,
                "Target URL is not configured correctly.",
                target.BaseUrl);
        }

        string? headerValue = null;
        if (!string.IsNullOrWhiteSpace(probe.HeaderEnvironmentVariable))
        {
            headerValue = Environment.GetEnvironmentVariable(probe.HeaderEnvironmentVariable);
            if (probe.RequiresAuthentication && string.IsNullOrWhiteSpace(headerValue))
            {
                return new EngineeringDiagnosticCheckResult(
                    id,
                    displayName,
                    EngineeringDiagnosticStatus.Warning,
                    "Probe is configured but its machine authentication credential is not available.",
                    $"Environment variable {probe.HeaderEnvironmentVariable} is not set.");
            }
        }

        Uri uri = new(baseUri, probe.Path);
        HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
        using HttpRequestMessage request = new(new HttpMethod(probe.Method), uri);

        if (!string.IsNullOrWhiteSpace(probe.HeaderName) && !string.IsNullOrWhiteSpace(headerValue))
        {
            request.Headers.TryAddWithoutValidation(probe.HeaderName, headerValue);
        }

        Stopwatch stopwatch = Stopwatch.StartNew();
        try
        {
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            int statusCode = (int)response.StatusCode;
            bool success = probe.SuccessStatusCodes.Length == 0
                ? response.IsSuccessStatusCode
                : probe.SuccessStatusCodes.Contains(statusCode);
            string evidence = $"HTTP {statusCode} in {stopwatch.ElapsedMilliseconds} ms — {uri}";

            return success
                ? new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Passed, "Application-aware probe succeeded.", evidence)
                : new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Application-aware probe returned an unexpected status.", evidence);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            return new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Endpoint timed out.", $"{stopwatch.ElapsedMilliseconds} ms — {uri}");
        }
        catch (HttpRequestException exception)
        {
            stopwatch.Stop();
            return new EngineeringDiagnosticCheckResult(id, displayName, EngineeringDiagnosticStatus.Failed, "Endpoint could not be reached.", $"{exception.GetType().Name} after {stopwatch.ElapsedMilliseconds} ms — {uri}");
        }
    }

    private static EngineeringDiagnosticLevel ParseLevel(int level)
    {
        return level switch
        {
            5 => EngineeringDiagnosticLevel.Level5Scan,
            4 => EngineeringDiagnosticLevel.Level4Analysis,
            3 => EngineeringDiagnosticLevel.Level3Verification,
            2 => EngineeringDiagnosticLevel.Level2Repair,
            1 => EngineeringDiagnosticLevel.Level1CriticalIntervention,
            _ => throw new InvalidOperationException($"Unsupported diagnostic level {level}. Expected 1 through 5.")
        };
    }
}
