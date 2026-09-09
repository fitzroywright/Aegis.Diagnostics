namespace Aegis.Diagnostics;

public sealed class DiagnosticsOptions
{
    public string ApplicationName { get; init; } = "Aegis.Diagnostics";
    public string EnvironmentName { get; init; } = "Production";
    public bool RequireApiKey { get; init; } = true;
    public string ApiKeyHeader { get; init; } = "X-Aegis-Diagnostics-Key";
    public string ApiKeyEnvironmentVariable { get; init; } = "AEGIS_DIAGNOSTICS_KEY";
    public string RunStorePath { get; init; } = "data/engineering-diagnostic-runs.json";
    public List<DiagnosticTargetOptions> Targets { get; init; } = [];
}

public sealed class DiagnosticTargetOptions
{
    public string Name { get; init; } = string.Empty;
    public string BaseUrl { get; init; } = string.Empty;
    public string ApplicationType { get; init; } = string.Empty;
    public string HealthPath { get; init; } = "/health";
    public string DiagnosticsRunPath { get; init; } = "/api/engineering/diagnostics/run";
    public string DiagnosticsRunsPath { get; init; } = "/api/engineering/diagnostics/runs";
    public bool RequireMachineCredential { get; init; } = true;
    public string ApiKeyHeader { get; init; } = "X-Aegis-Diagnostics-Key";
    public string? ApiKeyEnvironmentVariable { get; init; }
}
