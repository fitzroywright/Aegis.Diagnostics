namespace Aegis.Diagnostics;

using Common.Diagnostics;
using Common.Registration;
using System.Net.Http.Headers;
using System.Text.Json;

public sealed record DiagnosticLevelStateExplanation(
    string ApplicationId,
    string? InstanceId,
    string RegistrationState,
    string EffectiveState,
    string? DisplayedState,
    DateTimeOffset NowUtc,
    DateTimeOffset? LastAuthenticatedAtUtc,
    DateTimeOffset? LastTelemetryAtUtc,
    double? AuthenticationAgeSeconds,
    double? TelemetryAgeSeconds,
    double StaleAfterSeconds,
    bool RegistrationFresh,
    bool TelemetryFresh,
    bool AuthorityAvailable,
    bool TelemetryAvailable,
    string Result,
    IReadOnlyList<string> Codes,
    string Reason);

public interface IDiagnosticLevelStateExplainService
{
    Task<DiagnosticLevelStateExplanation?> ExplainAsync(
        string applicationId,
        string? instanceId,
        CancellationToken cancellationToken = default);
}

public sealed class DiagnosticLevelStateExplainService(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    DiagnosticsOptions options,
    ILogger<DiagnosticLevelStateExplainService> logger) : IDiagnosticLevelStateExplainService
{
    public async Task<DiagnosticLevelStateExplanation?> ExplainAsync(
        string applicationId,
        string? instanceId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
            throw new ArgumentException("ApplicationId is required.", nameof(applicationId));

        string operationsUrl = AegisControlPlaneEndpoints.ResolveInternal(
            configuration,
            AegisControlPlaneService.Operations,
            logger);

        if (!Uri.TryCreate(operationsUrl, UriKind.Absolute, out Uri? baseUri))
            throw new InvalidOperationException("Resolved Operations endpoint is invalid.");

        string credentialFile = configuration["Aegis:Registration:CredentialFile"]?.Trim()
            ?? "/var/lib/aegis/diagnostics/registration.key";

        if (!File.Exists(credentialFile))
            throw new InvalidOperationException("Diagnostics control-plane registration credential is unavailable.");

        string credential = (await File.ReadAllTextAsync(credentialFile, cancellationToken).ConfigureAwait(false)).Trim();
        if (string.IsNullOrWhiteSpace(credential))
            throw new InvalidOperationException("Diagnostics control-plane registration credential is empty.");

        string diagnosticsInstance =
            options.InstanceId?.Trim() ??
            configuration["Service:Identity"]?.Trim() ??
            Environment.MachineName;

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(baseUri, "/api/operations/registered-applications"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", options.ApplicationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", diagnosticsInstance);
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", Guid.NewGuid().ToString("N"));

        HttpClient client = httpClientFactory.CreateClient("operations-activity");
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Operations application inventory returned HTTP {(int)response.StatusCode}.");

        using JsonDocument document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));

        bool authorityAvailable =
            document.RootElement.TryGetProperty("authorityAvailable", out JsonElement authorityValue) &&
            authorityValue.ValueKind is JsonValueKind.True or JsonValueKind.False &&
            authorityValue.GetBoolean();

        DateTimeOffset nowUtc =
            document.RootElement.TryGetProperty("generatedAtUtc", out JsonElement generatedValue) &&
            generatedValue.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(generatedValue.GetString(), out DateTimeOffset parsedGenerated)
                ? parsedGenerated
                : DateTimeOffset.UtcNow;

        if (!document.RootElement.TryGetProperty("applications", out JsonElement applications) ||
            applications.ValueKind != JsonValueKind.Array)
            return null;

        JsonElement? selected = null;
        foreach (JsonElement application in applications.EnumerateArray())
        {
            string app = application.TryGetProperty("applicationId", out JsonElement appValue)
                ? appValue.GetString() ?? string.Empty
                : string.Empty;
            string? instance = application.TryGetProperty("instanceId", out JsonElement instanceValue)
                ? instanceValue.GetString()
                : null;

            if (!string.Equals(app, applicationId, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.IsNullOrWhiteSpace(instanceId) &&
                !string.Equals(instance, instanceId, StringComparison.OrdinalIgnoreCase))
                continue;

            selected = application.Clone();
            break;
        }

        if (!selected.HasValue)
            return null;

        JsonElement item = selected.Value;
        string registrationState = Text(item, "registrationStatus") ?? "Unknown";
        string effectiveState = Text(item, "state") ?? "Unknown";
        string? displayedState = Text(item, "registrationFlowLabel");
        DateTimeOffset? lastAuthenticated = Date(item, "registrationObservedAtUtc");
        DateTimeOffset? lastTelemetry = Date(item, "observedAtUtc");
        bool telemetryAvailable = Bool(item, "telemetryAvailable");
        bool stale = Bool(item, "stale");
        string reason = Text(item, "reason") ?? string.Empty;

        TimeSpan staleAfter = TimeSpan.FromSeconds(
            Math.Max(30, configuration.GetValue("Operations:StaleAfterSeconds", 300)));

        bool registrationFresh =
            registrationState.Equals("Registered", StringComparison.OrdinalIgnoreCase) &&
            lastAuthenticated.HasValue &&
            nowUtc - lastAuthenticated.Value <= staleAfter;

        bool telemetryFresh =
            lastTelemetry.HasValue &&
            nowUtc - lastTelemetry.Value <= staleAfter;

        List<string> codes = [];

        if (!authorityAvailable)
            codes.Add(DiagnosticLevelDiagnosticCodes.AuthorityUnavailable);

        if (lastAuthenticated.HasValue && !registrationFresh &&
            registrationState.Equals("Registered", StringComparison.OrdinalIgnoreCase))
            codes.Add(DiagnosticLevelDiagnosticCodes.StaleAuthority);

        if (telemetryAvailable && !telemetryFresh)
            codes.Add(DiagnosticLevelDiagnosticCodes.StaleTelemetry);

        if (registrationFresh &&
            effectiveState.Equals("Offline", StringComparison.OrdinalIgnoreCase))
            codes.Add(DiagnosticLevelDiagnosticCodes.StateDerivationMismatch);

        if (!string.IsNullOrWhiteSpace(displayedState) &&
            registrationFresh &&
            displayedState.Contains("Offline", StringComparison.OrdinalIgnoreCase))
            codes.Add(DiagnosticLevelDiagnosticCodes.StateDerivationMismatch);

        string result = codes.Any(code =>
                code == DiagnosticLevelDiagnosticCodes.StateDerivationMismatch ||
                code == DiagnosticLevelDiagnosticCodes.ControlPlaneStateDivergence)
            ? "Failed"
            : codes.Count > 0
                ? "Warning"
                : "Passed";

        return new DiagnosticLevelStateExplanation(
            applicationId,
            Text(item, "instanceId"),
            registrationState,
            effectiveState,
            displayedState,
            nowUtc,
            lastAuthenticated,
            lastTelemetry,
            lastAuthenticated.HasValue ? (nowUtc - lastAuthenticated.Value).TotalSeconds : null,
            lastTelemetry.HasValue ? (nowUtc - lastTelemetry.Value).TotalSeconds : null,
            staleAfter.TotalSeconds,
            registrationFresh,
            telemetryFresh,
            authorityAvailable,
            telemetryAvailable,
            result,
            codes.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            reason);
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool Bool(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind is JsonValueKind.True or JsonValueKind.False &&
        value.GetBoolean();

    private static DateTimeOffset? Date(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String &&
        DateTimeOffset.TryParse(value.GetString(), out DateTimeOffset parsed)
            ? parsed
            : null;
}
