namespace Aegis.Diagnostics.UnitTests;

using Common.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;
using System.Net.Http.Json;
using Xunit;

public sealed class RemoteDiagnosticCatalogTests
{
    [Fact]
    public async Task Level5UsesHealthEndpoint()
    {
        CapturingHandler handler = new((HttpRequestMessage request) => { Assert.Equal(HttpMethod.Get, request.Method); Assert.Equal("https://studio.test/health", request.RequestUri!.ToString()); return new HttpResponseMessage(HttpStatusCode.OK); });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, false);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level5Scan, null).Single(item => item.CheckId.Contains("-level-", StringComparison.Ordinal) && item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(EngineeringDiagnosticStatus.Passed, (await check.RunAsync(CancellationToken.None)).Status);
    }

    [Fact]
    public async Task Level4PostsCommonDiagnosticsRunRequest()
    {
        CapturingHandler handler = new(async request => { Assert.Equal(HttpMethod.Post, request.Method); Assert.Equal("https://studio.test/api/engineering/diagnostics/run", request.RequestUri!.ToString()); EngineeringDiagnosticRunRequest? posted = await request.Content!.ReadFromJsonAsync<EngineeringDiagnosticRunRequest>(); Assert.NotNull(posted); Assert.Equal(EngineeringDiagnosticLevel.Level4Analysis, posted.Level); return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(CreateRemoteRun(EngineeringDiagnosticStatus.Passed)) }; });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, false);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level4Analysis, "component check").Single(item => item.CheckId.Contains("-level-", StringComparison.Ordinal) && item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(EngineeringDiagnosticStatus.Passed, (await check.RunAsync(CancellationToken.None)).Status);
    }

    [Fact]
    public async Task MissingRequiredCredentialReturnsWarningWithoutNetworkCall()
    {
        CapturingHandler handler = new((Func<HttpRequestMessage, HttpResponseMessage>)(_ => throw new InvalidOperationException("Network should not be called.")));
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, true, includeCredential: false);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level3Verification, null).Single(item => item.CheckId.Contains("-level-", StringComparison.Ordinal) && item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);
        Assert.Equal(EngineeringDiagnosticStatus.Warning, result.Status);
        Assert.Contains("credential", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MachineCredentialComesFromCommonSecrets()
    {
        CapturingHandler handler = new(request =>
        {
            Assert.True(request.Headers.TryGetValues("X-Aegis-Diagnostics-Key", out IEnumerable<string>? values));
            Assert.Equal("test-machine-key", Assert.Single(values));
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(CreateRemoteRun(EngineeringDiagnosticStatus.Passed)) };
        });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, true, includeCredential: true);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level4Analysis, "credential test").Single(item => item.CheckId.Contains("-level-", StringComparison.Ordinal) && item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(EngineeringDiagnosticStatus.Passed, (await check.RunAsync(CancellationToken.None)).Status);
    }

    [Fact]
    public void RegisteredApplicationTargetFiltersToExactApplicationAndInstance()
    {
        DiagnosticTargetOptions studio = Target("Aegis.Studio", "STUDIO-01", "https://studio.test");
        DiagnosticTargetOptions hello = Target("Aegis.Hello", "Production", "https://hello.test");
        RemoteDiagnosticCatalog catalog = CreateCatalogWithTargets(
            new CapturingHandler((HttpRequestMessage _) => new HttpResponseMessage(HttpStatusCode.OK)),
            [studio, hello]);

        IReadOnlyList<EngineeringDiagnosticCheckDefinition> checks = catalog.Build(
            EngineeringDiagnosticLevel.Level5Scan,
            null,
            DiagnosticTarget.RegisteredApplication("Aegis.Hello", "Production"));

        Assert.Contains(checks, x => x.CheckId.StartsWith("aegis-hello", StringComparison.Ordinal));
        Assert.DoesNotContain(checks, x => x.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
    }

    [Fact]
    public void DiagnosticsComponentTargetIncludesOnlyDiagnosticsSelfCheck()
    {
        RemoteDiagnosticCatalog catalog = CreateCatalog(
            new CapturingHandler((HttpRequestMessage _) => new HttpResponseMessage(HttpStatusCode.OK)),
            false);

        IReadOnlyList<EngineeringDiagnosticCheckDefinition> checks = catalog.Build(
            EngineeringDiagnosticLevel.Level5Scan,
            null,
            DiagnosticTarget.ComponentTarget(ControlPlaneDiagnosticTargets.Diagnostics));

        EngineeringDiagnosticCheckDefinition check = Assert.Single(checks);
        Assert.Equal("aegis-diagnostics-self", check.CheckId);
    }

    [Fact]
    public void CapabilitiesExposeConfigurationCompatibleIdentity()
    {
        RemoteDiagnosticCatalog catalog = CreateCatalog(new CapturingHandler((HttpRequestMessage _) => new HttpResponseMessage(HttpStatusCode.OK)), false);
        string json = System.Text.Json.JsonSerializer.Serialize(catalog.GetCapabilities());
        Assert.Contains("Aegis.Configuration", json);
        Assert.Contains("Aegis.Studio", json);
        Assert.Contains("FFP-JM", json);
        Assert.Contains("STUDIO-01", json);
    }

    [Theory]
    [InlineData(EngineeringDiagnosticStatus.Warning, EngineeringDiagnosticStatus.Warning)]
    [InlineData(EngineeringDiagnosticStatus.Failed, EngineeringDiagnosticStatus.Failed)]
    [InlineData(EngineeringDiagnosticStatus.InterventionRequired, EngineeringDiagnosticStatus.InterventionRequired)]
    public async Task RemoteOutcomePropagatesToAggregateStatus(EngineeringDiagnosticStatus remoteStatus, EngineeringDiagnosticStatus expected)
    {
        CapturingHandler handler = new((HttpRequestMessage _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(CreateRemoteRun(remoteStatus)) });
        EngineeringDiagnosticCheckDefinition check = CreateCatalog(handler, false).Build(EngineeringDiagnosticLevel.Level2Repair, "repair investigation").Single(item => item.CheckId.Contains("-level-", StringComparison.Ordinal) && item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(expected, (await check.RunAsync(CancellationToken.None)).Status);
    }

    private static DiagnosticTargetOptions Target(string applicationId, string instanceId, string baseUrl) => new(
        applicationId,
        applicationId,
        "FFP-JM",
        instanceId,
        baseUrl,
        "/health",
        "/api/engineering/diagnostics/run",
        "/api/engineering/diagnostics/runs",
        "/api/engineering/diagnostics/telemetry",
        true,
        true,
        "None",
        string.Empty,
        [1, 2, 3, 4, 5],
        DateTimeOffset.UtcNow);

    private static RemoteDiagnosticCatalog CreateCatalogWithTargets(HttpMessageHandler handler, IReadOnlyList<DiagnosticTargetOptions> targets)
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CommonSecrets:Mode"] = "Test",
            ["CommonSecrets:ProviderOrder:0"] = "LocalConfiguration",
            ["CommonSecrets:Providers:LocalConfiguration:Type"] = "Configuration"
        }).Build();
        var targetCatalog = new TestTargetCatalog(targets);
        var stateExplain = new TestStateExplainService();
        var commonComponents = new CommonComponentDiagnosticCatalog(
            new ServiceCollection().BuildServiceProvider(),
            configuration,
            targetCatalog,
            stateExplain,
            NullLogger<CommonComponentDiagnosticCatalog>.Instance);
        return new RemoteDiagnosticCatalog(
            new TestHttpClientFactory(handler),
            new DiagnosticsOptions { RequireApiKey = false },
            targetCatalog,
            configuration,
            stateExplain,
            commonComponents);
    }

    private static RemoteDiagnosticCatalog CreateCatalog(HttpMessageHandler handler, bool requireCredential, bool includeCredential = false)
    {
        const string secretName = "diagnostics/machine/Aegis.Studio";
        Dictionary<string, string?> values = new()
        {
            ["CommonSecrets:Mode"] = "Test",
            ["CommonSecrets:ProviderOrder:0"] = "LocalConfiguration",
            ["CommonSecrets:Providers:LocalConfiguration:Type"] = "Configuration"
        };
        if (includeCredential) values[secretName] = "test-machine-key";
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        DiagnosticsOptions options = new() { RequireApiKey = false };
        DiagnosticTargetOptions target = new(
            "Aegis.Studio",
            "Aegis Studio",
            "FFP-JM",
            "STUDIO-01",
            "https://studio.test",
            "/health",
            "/api/engineering/diagnostics/run",
            "/api/engineering/diagnostics/runs",
            "/api/engineering/diagnostics/telemetry",
            true,
            true,
            requireCredential ? "MachineCredential" : "None",
            requireCredential ? secretName : string.Empty,
            [1, 2, 3, 4, 5],
            DateTimeOffset.UtcNow);
        var targetCatalog = new TestTargetCatalog([target]);
        var stateExplain = new TestStateExplainService();
        var commonComponents = new CommonComponentDiagnosticCatalog(
            new ServiceCollection().BuildServiceProvider(),
            configuration,
            targetCatalog,
            stateExplain,
            NullLogger<CommonComponentDiagnosticCatalog>.Instance);
        return new RemoteDiagnosticCatalog(new TestHttpClientFactory(handler), options, targetCatalog, configuration, stateExplain, commonComponents);
    }

    private static EngineeringDiagnosticRun CreateRemoteRun(EngineeringDiagnosticStatus status)
    {
        DateTimeOffset now=DateTimeOffset.UtcNow;
        return new EngineeringDiagnosticRun(Guid.NewGuid(),EngineeringDiagnosticLevel.Level4Analysis,"Aegis.Studio","Test","tests",null,now,now,status,[new EngineeringDiagnosticCheckResult("check","Check",status,"Result")]);
    }

    private sealed class TestTargetCatalog(IReadOnlyList<DiagnosticTargetOptions> targets) : IDiagnosticTargetCatalog
    {
        public IReadOnlyList<DiagnosticTargetOptions> Targets { get; } = targets;
        public DateTimeOffset? LastSuccessfulRefreshUtc { get; } = DateTimeOffset.UtcNow;
        public string? LastError => null;
        public bool IsStale => false;
    }

    private sealed class TestStateExplainService : ILevelXStateExplainService
    {
        public Task<LevelXStateExplanation?> ExplainAsync(
            string applicationId,
            string? instanceId,
            CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            return Task.FromResult<LevelXStateExplanation?>(new(
                applicationId,
                instanceId,
                "Registered",
                "Healthy",
                "Registered",
                now,
                now.AddSeconds(-5),
                now.AddSeconds(-5),
                5,
                5,
                90,
                true,
                true,
                true,
                true,
                "Passed",
                [],
                "State evidence is consistent."));
        }
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory { public HttpClient CreateClient(string name)=>new(handler,false); }
    private sealed class CapturingHandler : HttpMessageHandler { private readonly Func<HttpRequestMessage,Task<HttpResponseMessage>> responder; public CapturingHandler(Func<HttpRequestMessage,HttpResponseMessage> responder):this(r=>Task.FromResult(responder(r))){} public CapturingHandler(Func<HttpRequestMessage,Task<HttpResponseMessage>> responder){this.responder=responder;} protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>responder(request); }
}
