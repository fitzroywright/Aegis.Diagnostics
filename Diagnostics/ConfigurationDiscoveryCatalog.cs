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
    Task RefreshAsync(CancellationToken cancellationToken = default);
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
            Dictionary<string, ConfigurationApplicationContract> contractsByIdentity = contracts
                .Where(contract => !string.IsNullOrWhiteSpace(contract.ApplicationId))
                .GroupBy(contract => IdentityKey(contract.ApplicationId!, contract.InstanceId), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.OrderByDescending(x => x.LastRegisteredAtUtc).First(), StringComparer.OrdinalIgnoreCase);

            RegisteredApplicationInventoryItem[] registered = [];
            try
            {
                registered = await LoadRegisteredApplicationsAsync(
                    credential,
                    instanceId,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                logger.LogWarning(
                    exception,
                    "Operations application inventory is unavailable; Configuration contracts remain authoritative for diagnostic capabilities.");
            }

            Dictionary<string, RegisteredApplicationInventoryItem> registeredByIdentity = registered
                .Where(item => !string.IsNullOrWhiteSpace(item.ApplicationId))
                .Where(item => string.Equals(item.RegistrationStatus, "Registered", StringComparison.OrdinalIgnoreCase))
                .GroupBy(item => IdentityKey(item.ApplicationId, item.InstanceId), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.OrderByDescending(x => x.RegistrationObservedAtUtc).First(), StringComparer.OrdinalIgnoreCase);

            DiagnosticTargetOptions[] discovered = contracts
                .Where(contract => !string.IsNullOrWhiteSpace(contract.ApplicationId))
                .Where(contract => !string.Equals(contract.ApplicationId, options.ApplicationId, StringComparison.OrdinalIgnoreCase))
                .Select(contract =>
                {
                    registeredByIdentity.TryGetValue(
                        IdentityKey(contract.ApplicationId!, contract.InstanceId),
                        out RegisteredApplicationInventoryItem? item);

                    item ??= new RegisteredApplicationInventoryItem(
                        contract.ApplicationId!,
                        contract.DisplayName,
                        contract.InstanceId,
                        "Registered",
                        contract.LastRegisteredAtUtc,
                        false,
                        null);

                    return ToTarget(item, contract);
                })
                .OrderBy(target => target.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(target => target.InstanceId, StringComparer.OrdinalIgnoreCase)
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

    private static DiagnosticTargetOptions ToTarget(
        RegisteredApplicationInventoryItem item,
        ConfigurationApplicationContract? contract)
    {
        ConfigurationDiagnosticsCapability? capability = contract?.Diagnostics;
        string baseUrl = capability?.BaseUrl?.Trim() ?? string.Empty;
        bool supportsRemote = capability?.SupportsRemoteDiagnostics ?? false;
        bool supportsTelemetry = capability?.SupportsOperationalTelemetry ?? item.TelemetryAvailable;

        return new(
            item.ApplicationId,
            string.IsNullOrWhiteSpace(contract?.DisplayName)
                ? string.IsNullOrWhiteSpace(item.DisplayName) ? item.ApplicationId : item.DisplayName
                : contract!.DisplayName!,
            contract?.SiteId,
            item.InstanceId,
            baseUrl,
            DefaultPath(capability?.HealthPath, "/health"),
            DefaultPath(capability?.DiagnosticsRunPath, "/api/engineering/diagnostics/run"),
            DefaultPath(capability?.DiagnosticsRunsPath, "/api/engineering/diagnostics/runs"),
            DefaultPath(capability?.TelemetryPath, "/api/engineering/diagnostics/telemetry"),
            supportsRemote,
            supportsTelemetry,
            string.IsNullOrWhiteSpace(capability?.AuthenticationScheme) ? "MachineCredential" : capability!.AuthenticationScheme!,
            capability?.SecretName ?? string.Empty,
            capability?.SupportedLevels is { Length: > 0 } ? capability.SupportedLevels : [5],
            item.RegistrationObservedAtUtc ?? contract?.LastRegisteredAtUtc,
            contract?.Presentation?.IconUrl,
            contract?.Presentation?.ShortName,
            contract?.Presentation?.Accent);
    }

    private async Task<RegisteredApplicationInventoryItem[]> LoadRegisteredApplicationsAsync(
        string credential,
        string instanceId,
        CancellationToken cancellationToken)
    {
        string operationsBaseUrl = AegisControlPlaneEndpoints.ResolveInternal(
            configuration,
            AegisControlPlaneService.Operations,
            logger);

        if (!Uri.TryCreate(operationsBaseUrl, UriKind.Absolute, out Uri? operationsUri))
            throw new InvalidOperationException("Resolved Operations endpoint is not an absolute URL.");

        HttpClient client = httpClientFactory.CreateClient("operations-activity");
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            new Uri(operationsUri, "/api/operations/registered-applications"));
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", credential);
        request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", options.ApplicationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", instanceId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", Guid.NewGuid().ToString("N"));

        using HttpResponseMessage response =
            await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Aegis.Operations registered-application inventory returned HTTP {(int)response.StatusCode}.");

        RegisteredApplicationInventoryEnvelope? envelope =
            await response.Content.ReadFromJsonAsync<RegisteredApplicationInventoryEnvelope>(
                cancellationToken: cancellationToken).ConfigureAwait(false);

        return envelope?.Applications ?? [];
    }

    private static string IdentityKey(string applicationId, string? instanceId) =>
        applicationId.Trim() + "\u001f" + (instanceId?.Trim() ?? string.Empty);

    private void SetError(string message)
    {
        lock (gate) lastError = message;
        logger.LogWarning("{Message}", message);
    }

    private static string DefaultPath(string? value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private sealed record RegisteredApplicationInventoryEnvelope(
        bool AuthorityAvailable,
        DateTimeOffset GeneratedAtUtc,
        RegisteredApplicationInventoryItem[] Applications);

    private sealed record RegisteredApplicationInventoryItem(
        string ApplicationId,
        string? DisplayName,
        string? InstanceId,
        string RegistrationStatus,
        DateTimeOffset? RegistrationObservedAtUtc,
        bool TelemetryAvailable,
        string? State);

    private sealed record ConfigurationApplicationContract(
        string? ApplicationId,
        string? DisplayName,
        string? SiteId,
        string? InstanceId,
        DateTimeOffset? LastRegisteredAtUtc,
        ConfigurationDiagnosticsCapability? Diagnostics,
        ConfigurationPresentationContract? Presentation);

    private sealed record ConfigurationPresentationContract(
        string? IconUrl,
        string? ShortName,
        string? Accent);

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
