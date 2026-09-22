namespace Aegis.Diagnostics;

using System.Net.Http.Json;
using Common.Secrets;
using Common.Registration;

public interface IDiagnosticTargetCatalog
{
    IReadOnlyList<DiagnosticTargetOptions> Targets { get; }
    DateTimeOffset? LastSuccessfulRefreshUtc { get; }
    string? LastError { get; }
    bool IsStale { get; }
}

public sealed class ConfigurationDiscoveryCatalog(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    DiagnosticsOptions options,
    ILogger<ConfigurationDiscoveryCatalog> logger) : IDiagnosticTargetCatalog
{
    private readonly object gate = new();
    private DiagnosticTargetOptions[] targets = [];
    private DateTimeOffset? lastSuccessfulRefreshUtc;
    private string? lastError;

    public IReadOnlyList<DiagnosticTargetOptions> Targets
    {
        get { lock (gate) return targets.ToArray(); }
    }

    public DateTimeOffset? LastSuccessfulRefreshUtc
    {
        get { lock (gate) return lastSuccessfulRefreshUtc; }
    }

    public string? LastError
    {
        get { lock (gate) return lastError; }
    }

    public bool IsStale
    {
        get
        {
            DateTimeOffset? last = LastSuccessfulRefreshUtc;
            return !last.HasValue || DateTimeOffset.UtcNow - last.Value > TimeSpan.FromSeconds(Math.Max(30, options.ObservationStaleSeconds));
        }
    }

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        string baseUrl = AegisControlPlaneEndpoints.ResolveInternal(
            configuration,
            AegisControlPlaneService.Configuration,
            logger);
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out Uri? configurationUri))
        {
            SetError("Resolved Configuration endpoint is not an absolute URL.");
            return;
        }

        try
        {
            string credentialFile = configuration["Aegis:Registration:CredentialFile"]?.Trim()
                ?? "/var/lib/aegis/diagnostics/registration.key";
            if (!File.Exists(credentialFile))
            {
                SetError($"Diagnostics control-plane registration credential is missing at '{credentialFile}'.");
                return;
            }

            string credential = (await File.ReadAllTextAsync(credentialFile, cancellationToken).ConfigureAwait(false)).Trim();
            if (string.IsNullOrWhiteSpace(credential))
            {
                SetError("Diagnostics control-plane registration credential is empty.");
                return;
            }

            string instanceId =
                options.InstanceId?.Trim() ??
                configuration["Service:Identity"]?.Trim() ??
                Environment.MachineName;

            HttpClient client = httpClientFactory.CreateClient("configuration-discovery");
            using HttpRequestMessage request = new(HttpMethod.Get, new Uri(configurationUri, "/api/contracts/discovery"));
            request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Key", credential);
            request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", options.ApplicationId);
            request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", instanceId);
            request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", Guid.NewGuid().ToString("N"));
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                SetError($"Aegis.Configuration discovery returned HTTP {(int)response.StatusCode}.");
                return;
            }

            ConfigurationApplicationContract[] contracts = await response.Content.ReadFromJsonAsync<ConfigurationApplicationContract[]>(cancellationToken: cancellationToken).ConfigureAwait(false) ?? [];
            DiagnosticTargetOptions[] discovered = contracts
                .Where(contract => !string.Equals(contract.ApplicationId, options.ApplicationId, StringComparison.OrdinalIgnoreCase))
                .Where(contract => contract.Diagnostics is not null)
                .Select(ToTarget)
                .OrderBy(target => target.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            lock (gate)
            {
                targets = discovered;
                lastSuccessfulRefreshUtc = DateTimeOffset.UtcNow;
                lastError = null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Unable to refresh diagnostic target inventory from Aegis.Configuration.");
            SetError($"{exception.GetType().Name}: unable to refresh Configuration discovery.");
        }
    }

    private static DiagnosticTargetOptions ToTarget(ConfigurationApplicationContract contract)
    {
        ConfigurationDiagnosticsCapability capability = contract.Diagnostics!;
        string baseUrl = capability.BaseUrl?.Trim() ?? string.Empty;
        return new(
            contract.ApplicationId ?? string.Empty,
            string.IsNullOrWhiteSpace(contract.DisplayName) ? contract.ApplicationId ?? "Unknown application" : contract.DisplayName,
            contract.SiteId,
            contract.InstanceId,
            baseUrl,
            DefaultPath(capability.HealthPath, "/health"),
            DefaultPath(capability.DiagnosticsRunPath, "/api/engineering/diagnostics/run"),
            DefaultPath(capability.DiagnosticsRunsPath, "/api/engineering/diagnostics/runs"),
            DefaultPath(capability.TelemetryPath, "/api/engineering/diagnostics/telemetry"),
            capability.SupportsRemoteDiagnostics,
            capability.SupportsOperationalTelemetry,
            string.IsNullOrWhiteSpace(capability.AuthenticationScheme) ? "MachineCredential" : capability.AuthenticationScheme,
            capability.SecretName ?? string.Empty,
            capability.SupportedLevels is { Length: > 0 } ? capability.SupportedLevels : [1, 2, 3, 4, 5],
            contract.LastRegisteredAtUtc,
            contract.Presentation?.IconUrl,
            contract.Presentation?.ShortName,
            contract.Presentation?.Accent);
    }

    private void SetError(string message)
    {
        lock (gate) lastError = message;
        logger.LogWarning("{Message}", message);
    }

    private static string DefaultPath(string? value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private sealed record ConfigurationApplicationContract(
        string? ApplicationId,
        string? DisplayName,
        string? SiteId,
        string? InstanceId,
        DateTimeOffset? LastRegisteredAtUtc,
        ConfigurationRequirementContract[]? Requirements,
        ConfigurationDiagnosticsCapability? Diagnostics,
        ConfigurationPresentationContract? Presentation);

    private sealed record ConfigurationPresentationContract(
        string? IconUrl,
        string? ShortName,
        string? Accent);

    private sealed record ConfigurationRequirementContract(
        string? ConfigurationKey,
        string? DisplayValue,
        bool Sensitive = false);

    private sealed record ConfigurationDiagnosticsCapability(
        string? BaseUrl,
        string? HealthPath,
        string? DiagnosticsRunPath,
        string? DiagnosticsRunsPath,
        string? TelemetryPath,
        bool SupportsRemoteDiagnostics = true,
        bool SupportsOperationalTelemetry = true,
        string? AuthenticationScheme = null,
        string? SecretName = null,
        int[]? SupportedLevels = null);
}

public sealed class ConfigurationDiscoveryWorker(ConfigurationDiscoveryCatalog catalog, DiagnosticsOptions options) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan interval = TimeSpan.FromSeconds(Math.Max(30, options.DiscoveryRefreshSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            await catalog.RefreshAsync(stoppingToken).ConfigureAwait(false);
            try { await Task.Delay(interval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }
}
