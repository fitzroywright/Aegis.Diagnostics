namespace Aegis.Diagnostics.UnitTests;

using Aegis.Diagnostics;
using Common.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;
using System.Text;
using Xunit;

public sealed class DiagnosticLevelStateExplainServiceTests
{
    [Fact]
    public async Task FreshRegistration_WithStaleTelemetry_DoesNotReportStateDerivationMismatch()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string json = $$"""
        {
          "authorityAvailable": true,
          "generatedAtUtc": "{{now:O}}",
          "applications": [
            {
              "applicationId": "Aegis.Hello",
              "instanceId": "Production",
              "registrationStatus": "Registered",
              "state": "Healthy",
              "registrationFlowLabel": "Registered",
              "registrationObservedAtUtc": "{{now.AddSeconds(-15):O}}",
              "observedAtUtc": "{{now.AddMinutes(-10):O}}",
              "telemetryAvailable": true,
              "stale": false,
              "reason": "Operational heartbeat is stale, but the registration authority has a fresh successful observation."
            }
          ]
        }
        """;

        DiagnosticLevelStateExplanation result = await ExecuteAsync(json);

        Assert.True(result.RegistrationFresh);
        Assert.False(result.TelemetryFresh);
        Assert.Contains(DiagnosticLevelDiagnosticCodes.StaleTelemetry, result.Codes);
        Assert.DoesNotContain(DiagnosticLevelDiagnosticCodes.StateDerivationMismatch, result.Codes);
        Assert.Equal("Warning", result.Result);
    }

    [Fact]
    public async Task FreshRegistration_WithOfflineEffectiveState_ReportsMismatch()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string json = $$"""
        {
          "authorityAvailable": true,
          "generatedAtUtc": "{{now:O}}",
          "applications": [
            {
              "applicationId": "Aegis.Hello",
              "instanceId": "Production",
              "registrationStatus": "Registered",
              "state": "Offline",
              "registrationFlowLabel": "Registered (Offline)",
              "registrationObservedAtUtc": "{{now.AddSeconds(-10):O}}",
              "observedAtUtc": "{{now.AddMinutes(-10):O}}",
              "telemetryAvailable": true,
              "stale": true,
              "reason": "No recent heartbeat has been received."
            }
          ]
        }
        """;

        DiagnosticLevelStateExplanation result = await ExecuteAsync(json);

        Assert.Contains(DiagnosticLevelDiagnosticCodes.StateDerivationMismatch, result.Codes);
        Assert.Equal("Failed", result.Result);
    }

    private static async Task<DiagnosticLevelStateExplanation> ExecuteAsync(string json)
    {
        string credentialFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(credentialFile, "test-credential");

        try
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Aegis:Operations:Url"] = "https://operations.test",
                    ["Aegis:Registration:CredentialFile"] = credentialFile,
                    ["Operations:StaleAfterSeconds"] = "300"
                })
                .Build();

            var handler = new StaticHandler(json);
            var service = new DiagnosticLevelStateExplainService(
                new TestHttpClientFactory(handler),
                configuration,
                new DiagnosticsOptions { InstanceId = "DIAG-TEST" },
                NullLogger<DiagnosticLevelStateExplainService>.Instance);

            return Assert.IsType<DiagnosticLevelStateExplanation>(
                await service.ExplainAsync("Aegis.Hello", "Production"));
        }
        finally
        {
            File.Delete(credentialFile);
        }
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class StaticHandler(string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            });
    }
}
