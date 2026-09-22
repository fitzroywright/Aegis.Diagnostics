namespace Aegis.Diagnostics;

public sealed class DiagnosticsOptions
{
    public string ApplicationId { get; init; } = "Aegis.Diagnostics";
    public string ApplicationName { get; init; } = "Aegis.Diagnostics";
    public string? SiteId { get; init; }
    public string? InstanceId { get; init; }
    public string EnvironmentName { get; set; } = "Production";
    public bool RequireApiKey { get; init; } = true;
    public string ApiKeyHeader { get; init; } = "X-Aegis-Diagnostics-Key";
    public string MachineCredentialSecretName { get; init; } = "diagnostics/machine/Aegis.Diagnostics";
    public string RunStorePath { get; init; } = "data/engineering-diagnostic-runs.json";
    public string IncidentStorePath { get; init; } = "data/operational-incidents.json";
    public int DiscoveryRefreshSeconds { get; init; } = 60;
    public int HealthPollSeconds { get; init; } = 10;
    public int ObservationStaleSeconds { get; init; } = 45;
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
    string TelemetryPath,
    bool SupportsRemoteDiagnostics,
    bool SupportsOperationalTelemetry,
    string AuthenticationScheme,
    string SecretName,
    IReadOnlyList<int> SupportedLevels,
    DateTimeOffset? ConfigurationRegisteredAtUtc,
    string? IconUrl = null,
    string? ShortName = null,
    string? Accent = null);
