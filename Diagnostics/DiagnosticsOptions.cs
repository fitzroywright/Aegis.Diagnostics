namespace Aegis.Diagnostics;

public sealed class DiagnosticsOptions
{
    public string ApplicationName { get; init; } = "Aegis.Diagnostics";
    public string EnvironmentName { get; init; } = "Production";
    public bool RequireApiKey { get; init; }
    public string ApiKey { get; init; } = string.Empty;
    public string RunStorePath { get; init; } = "data/engineering-diagnostic-runs.json";
    public List<DiagnosticTargetOptions> Targets { get; init; } = [];
}

public sealed class DiagnosticTargetOptions
{
    public string Name { get; init; } = string.Empty;
    public string BaseUrl { get; init; } = string.Empty;
    public string Level5Path { get; init; } = "/health";
    public string Level4Path { get; init; } = "/health/components";
    public string Level3Path { get; init; } = "/health/system";
    public string Level2Path { get; init; } = "/health/integrations";
    public string Level1Path { get; init; } = "/health/full";
}
