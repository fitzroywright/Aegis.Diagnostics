namespace Aegis.Diagnostics;

using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Common.Secrets;

public sealed class ConfigurationDiscoveryCatalog(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    DiagnosticsOptions options,
    ILogger<ConfigurationDiscoveryCatalog> logger)
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
        string? baseUrl = configuration["Aegis:Configuration:Url"];
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out Uri? configurationUri))
        {
            SetError("Aegis:Configuration:Url is not configured as an absolute URL.");
            return;
        }

        try
        {
            ISecretProvider secrets = CommonSecretProviderFactory.Create(configuration);
            string registrationSecretPath = $"configuration/registration/{options.ApplicationId}";
            string? credential = await secrets.GetAsync(registrationSecretPath, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(credential))
            {
                SetError($"Configuration discovery credential '{registrationSecretPath}' is unavailable.");
                return;
            }

            HttpClient client = httpClientFactory.CreateClient("configuration-discovery");
            using HttpRequestMessage request = new(HttpMethod.Get, new Uri(configurationUri, "/api/contracts/discovery"));
            request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Key", credential);
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

    private DiagnosticTargetOptions ToTarget(ConfigurationApplicationContract contract)
    {
        ConfigurationDiagnosticsCapability capability = contract.Diagnostics!;
        string baseUrl = ResolveBaseUrl(contract, capability.BaseUrlConfigurationKey);
        return new(
            contract.ApplicationId ?? string.Empty,
            string.IsNullOrWhiteSpace(contract.DisplayName) ? contract.ApplicationId ?? "Unknown application" : contract.DisplayName,
            contract.SiteId,
            contract.InstanceId,
            baseUrl,
            DefaultPath(capability.HealthPath, "/health"),
            DefaultPath(capability.DiagnosticsRunPath, "/api/engineering/diagnostics/run"),
            DefaultPath(capability.DiagnosticsRunsPath, "/api/engineering/diagnostics/runs"),
            capability.SupportsRemoteDiagnostics,
            string.IsNullOrWhiteSpace(capability.AuthenticationScheme) ? "MachineCredential" : capability.AuthenticationScheme,
            capability.SecretName ?? string.Empty,
            capability.SupportedLevels is { Length: > 0 } ? capability.SupportedLevels : [1, 2, 3, 4, 5],
            contract.LastRegisteredAtUtc);
    }

    private static string ResolveBaseUrl(ConfigurationApplicationContract contract, string? configurationKey)
    {
        if (string.IsNullOrWhiteSpace(configurationKey)) return string.Empty;
        ConfigurationRequirementContract? requirement = contract.Requirements?.FirstOrDefault(item =>
            string.Equals(item.ConfigurationKey, configurationKey, StringComparison.OrdinalIgnoreCase));
        if (requirement is null || requirement.Sensitive) return string.Empty;
        return requirement.SafeDisplayValue?.Trim() ?? string.Empty;
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
        ConfigurationDiagnosticsCapability? Diagnostics);

    private sealed record ConfigurationRequirementContract(
        string? ConfigurationKey,
        string? SafeDisplayValue,
        bool Sensitive = false);

    private sealed record ConfigurationDiagnosticsCapability(
        string? BaseUrlConfigurationKey,
        string? HealthPath,
        string? DiagnosticsRunPath,
        string? DiagnosticsRunsPath,
        bool SupportsRemoteDiagnostics,
        string? AuthenticationScheme,
        string? SecretName,
        int[]? SupportedLevels);
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
