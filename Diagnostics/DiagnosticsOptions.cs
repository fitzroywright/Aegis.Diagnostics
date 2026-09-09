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
    public string ApplicationType { get; init; } = string.Empty;
    public List<string> CommonComponents { get; init; } = [];
    public List<string> ExpectedCommonComponents { get; init; } = [];
    public List<DiagnosticProbeOptions> Probes { get; init; } = [];
}

public sealed class DiagnosticProbeOptions
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public int Level { get; init; } = 5;
    public string Path { get; init; } = "/health";
    public string Method { get; init; } = "GET";
    public bool Enabled { get; init; } = true;
    public bool RequiresAuthentication { get; init; }
    public string? HeaderName { get; init; }
    public string? HeaderEnvironmentVariable { get; init; }
    public int[] SuccessStatusCodes { get; init; } = [200];
}
