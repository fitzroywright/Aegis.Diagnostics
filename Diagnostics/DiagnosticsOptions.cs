namespace Aegis.Diagnostics;

public sealed class DiagnosticsOptions
{
    public string ApplicationId { get; init; } = "Aegis.Diagnostics";
    public string ApplicationName { get; init; } = "Aegis.Diagnostics";
    public string? SiteId { get; init; }
    public string? InstanceId { get; init; }
    public string EnvironmentName { get; init; } = "Production";
    public bool RequireApiKey { get; init; } = true;
    public string ApiKeyHeader { get; init; } = "X-Aegis-Diagnostics-Key";
    public string ApiKeyEnvironmentVariable { get; init; } = "AEGIS_DIAGNOSTICS_KEY";
    public string RunStorePath { get; init; } = "data/engineering-diagnostic-runs.json";
    public int DiscoveryRefreshSeconds { get; init; } = 60;
    public int ObservationStaleSeconds { get; init; } = 180;
}

public sealed record DiagnosticTargetOptions(
    string ApplicationId,
    string Name,
    string? SiteId,
    string? InstanceId,
    string BaseUrl,
    string HealthPath,
    string DiagnosticsRunPath,
    string DiagnosticsRunsPath,
    bool SupportsRemoteDiagnostics,
    string AuthenticationScheme,
    string SecretName,
    IReadOnlyList<int> SupportedLevels,
    DateTimeOffset? ConfigurationRegisteredAtUtc);
