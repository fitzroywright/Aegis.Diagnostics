namespace Aegis.Diagnostics;

using Common.Diagnostics;
using System.Net;
using System.Text.Json;

public static class ApplicationHealthResponseClassifier
{
    public static (OperationalHealth Health, string Summary) Classify(
        HttpStatusCode statusCode,
        string? payload)
    {
        if ((int)statusCode is < 200 or >= 300)
        {
            return (
                OperationalHealth.Unhealthy,
                $"Health endpoint returned HTTP {(int)statusCode}.");
        }

        if (string.IsNullOrWhiteSpace(payload))
        {
            return (
                OperationalHealth.Unknown,
                "Health endpoint responded without diagnostic telemetry.");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(payload);
            string? published = document.RootElement.TryGetProperty("status", out JsonElement status) &&
                                status.ValueKind == JsonValueKind.String
                ? status.GetString()
                : null;

            OperationalHealth health = published?.Trim().ToLowerInvariant() switch
            {
                "healthy" => OperationalHealth.Healthy,
                "degraded" or "warning" => OperationalHealth.Degraded,
                "unhealthy" or "failed" or "offline" => OperationalHealth.Unhealthy,
                _ => OperationalHealth.Unknown
            };

            return (
                health,
                health == OperationalHealth.Unknown
                    ? "Health endpoint responded but did not publish a recognized operational state."
                    : $"Application published {published}.");
        }
        catch (JsonException)
        {
            return (
                OperationalHealth.Unknown,
                "Health endpoint responded with malformed or non-JSON telemetry.");
        }
    }
}
