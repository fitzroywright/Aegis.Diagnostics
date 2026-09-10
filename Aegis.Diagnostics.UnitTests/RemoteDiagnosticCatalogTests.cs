namespace Aegis.Diagnostics.UnitTests;

using Common.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Xunit;

public sealed class RemoteDiagnosticCatalogTests
{
    [Fact]
    public async Task Level5UsesHealthEndpoint()
    {
        CapturingHandler handler = new(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("https://studio.test/health", request.RequestUri!.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, requireCredential: false);

        EngineeringDiagnosticCheckDefinition check = catalog
            .Build(EngineeringDiagnosticLevel.Level5Scan, null)
            .Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);

        Assert.Equal(EngineeringDiagnosticStatus.Passed, result.Status);
    }

    [Fact]
    public async Task Level4PostsCommonDiagnosticsRunRequest()
    {
        CapturingHandler handler = new(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://studio.test/api/engineering/diagnostics/run", request.RequestUri!.ToString());
            EngineeringDiagnosticRunRequest? posted = await request.Content!.ReadFromJsonAsync<EngineeringDiagnosticRunRequest>();
            Assert.NotNull(posted);
            Assert.Equal(EngineeringDiagnosticLevel.Level4Analysis, posted.Level);

            EngineeringDiagnosticRun run = CreateRemoteRun(EngineeringDiagnosticStatus.Passed);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(run) };
        });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, requireCredential: false);

        EngineeringDiagnosticCheckDefinition check = catalog
            .Build(EngineeringDiagnosticLevel.Level4Analysis, "component check")
            .Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);

        Assert.Equal(EngineeringDiagnosticStatus.Passed, result.Status);
    }

    [Fact]
    public async Task StorageEvidenceIsPromotedIntoCentralDiagnosticResult()
    {
        CapturingHandler handler = new(_ =>
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            EngineeringDiagnosticRun run = new(
                Guid.NewGuid(),
                EngineeringDiagnosticLevel.Level4Analysis,
                "Aegis.Studio",
                "Test",
                "tests",
                null,
                now,
                now,
                EngineeringDiagnosticStatus.Warning,
                [new EngineeringDiagnosticCheckResult(
                    "studio-l4-storage",
                    "Common.Storage",
                    EngineeringDiagnosticStatus.Warning,
                    "Storage is degraded.",
                    "Provider=LocalFileStorage; Writable=false")]);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(run) };
        });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, requireCredential: false);

        EngineeringDiagnosticCheckDefinition check = catalog
            .Build(EngineeringDiagnosticLevel.Level4Analysis, "storage check")
            .Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);

        Assert.Equal(EngineeringDiagnosticStatus.Warning, result.Status);
        Assert.Contains("Storage:", result.Evidence, StringComparison.Ordinal);
        Assert.Contains("Storage is degraded", result.Evidence, StringComparison.Ordinal);
        Assert.Contains("Writable=false", result.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingRequiredCredentialReturnsWarningWithoutNetworkCall()
    {
        const string variable = "AEGIS_DIAGNOSTICS_TEST_MISSING_KEY";
        Environment.SetEnvironmentVariable(variable, null);
        Func<HttpRequestMessage, HttpResponseMessage> shouldNotCallNetwork = _ => throw new InvalidOperationException("Network should not be called.");
        CapturingHandler handler = new(shouldNotCallNetwork);
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, requireCredential: true, environmentVariable: variable);

        EngineeringDiagnosticCheckDefinition check = catalog
            .Build(EngineeringDiagnosticLevel.Level3Verification, null)
            .Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);

        Assert.Equal(EngineeringDiagnosticStatus.Warning, result.Status);
        Assert.Contains("credential", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(EngineeringDiagnosticStatus.Warning, EngineeringDiagnosticStatus.Warning)]
    [InlineData(EngineeringDiagnosticStatus.Failed, EngineeringDiagnosticStatus.Failed)]
    [InlineData(EngineeringDiagnosticStatus.InterventionRequired, EngineeringDiagnosticStatus.InterventionRequired)]
    public async Task RemoteOutcomePropagatesToAggregateStatus(
        EngineeringDiagnosticStatus remoteStatus,
        EngineeringDiagnosticStatus expected)
    {
        CapturingHandler handler = new(_ =>
        {
            EngineeringDiagnosticRun run = CreateRemoteRun(remoteStatus);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(run) };
        });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, requireCredential: false);

        EngineeringDiagnosticCheckDefinition check = catalog
            .Build(EngineeringDiagnosticLevel.Level2Repair, "repair investigation")
            .Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);

        Assert.Equal(expected, result.Status);
    }

    private static RemoteDiagnosticCatalog CreateCatalog(
        HttpMessageHandler handler,
        bool requireCredential,
        string? environmentVariable = null)
    {
        DiagnosticsOptions options = new()
        {
            Targets =
            [
                new DiagnosticTargetOptions
                {
                    Name = "Aegis.Studio",
                    BaseUrl = "https://studio.test",
                    RequireMachineCredential = requireCredential,
                    ApiKeyEnvironmentVariable = environmentVariable
                }
            ]
        };
        return new RemoteDiagnosticCatalog(new TestHttpClientFactory(handler), options);
    }

    private static EngineeringDiagnosticRun CreateRemoteRun(EngineeringDiagnosticStatus status)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new EngineeringDiagnosticRun(
            Guid.NewGuid(),
            EngineeringDiagnosticLevel.Level4Analysis,
            "Aegis.Studio",
            "Test",
            "tests",
            null,
            now,
            now,
            status,
            [new EngineeringDiagnosticCheckResult("check", "Check", status, "Result")]);
    }

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler handler;

        public TestHttpClientFactory(HttpMessageHandler handler)
        {
            this.handler = handler;
        }

        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> responder;

        public CapturingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
            : this(request => Task.FromResult(responder(request)))
        {
        }

        public CapturingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> responder)
        {
            this.responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => responder(request);
    }
}
