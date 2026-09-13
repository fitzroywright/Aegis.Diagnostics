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
        CapturingHandler handler = new((HttpRequestMessage request) => { Assert.Equal(HttpMethod.Get, request.Method); Assert.Equal("https://studio.test/health", request.RequestUri!.ToString()); return new HttpResponseMessage(HttpStatusCode.OK); });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, false);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level5Scan, null).Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(EngineeringDiagnosticStatus.Passed, (await check.RunAsync(CancellationToken.None)).Status);
    }

    [Fact]
    public async Task Level4PostsCommonDiagnosticsRunRequest()
    {
        CapturingHandler handler = new(async request => { Assert.Equal(HttpMethod.Post, request.Method); Assert.Equal("https://studio.test/api/engineering/diagnostics/run", request.RequestUri!.ToString()); EngineeringDiagnosticRunRequest? posted = await request.Content!.ReadFromJsonAsync<EngineeringDiagnosticRunRequest>(); Assert.NotNull(posted); Assert.Equal(EngineeringDiagnosticLevel.Level4Analysis, posted.Level); return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(CreateRemoteRun(EngineeringDiagnosticStatus.Passed)) }; });
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, false);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level4Analysis, "component check").Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(EngineeringDiagnosticStatus.Passed, (await check.RunAsync(CancellationToken.None)).Status);
    }

    [Fact]
    public async Task MissingRequiredCredentialReturnsWarningWithoutNetworkCall()
    {
        const string variable = "AEGIS_DIAGNOSTICS_TEST_MISSING_KEY"; Environment.SetEnvironmentVariable(variable, null);
        CapturingHandler handler = new((HttpRequestMessage _) => throw new InvalidOperationException("Network should not be called."));
        RemoteDiagnosticCatalog catalog = CreateCatalog(handler, true, variable);
        EngineeringDiagnosticCheckDefinition check = catalog.Build(EngineeringDiagnosticLevel.Level3Verification, null).Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        EngineeringDiagnosticCheckResult result = await check.RunAsync(CancellationToken.None);
        Assert.Equal(EngineeringDiagnosticStatus.Warning, result.Status); Assert.Contains("credential", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CapabilitiesExposeConfigurationCompatibleIdentity()
    {
        RemoteDiagnosticCatalog catalog = CreateCatalog(new CapturingHandler((HttpRequestMessage _) => new HttpResponseMessage(HttpStatusCode.OK)), false);
        string json = System.Text.Json.JsonSerializer.Serialize(catalog.GetCapabilities());
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
        EngineeringDiagnosticCheckDefinition check = CreateCatalog(handler, false).Build(EngineeringDiagnosticLevel.Level2Repair, "repair investigation").Single(item => item.CheckId.StartsWith("aegis-studio", StringComparison.Ordinal));
        Assert.Equal(expected, (await check.RunAsync(CancellationToken.None)).Status);
    }

    private static RemoteDiagnosticCatalog CreateCatalog(HttpMessageHandler handler, bool requireCredential, string? environmentVariable = null)
    {
        DiagnosticsOptions options = new() { Targets = [new DiagnosticTargetOptions { ApplicationId="Aegis.Studio", Name="Aegis Studio", SiteId="FFP-JM", InstanceId="STUDIO-01", BaseUrl="https://studio.test", RequireMachineCredential=requireCredential, ApiKeyEnvironmentVariable=environmentVariable }] };
        return new RemoteDiagnosticCatalog(new TestHttpClientFactory(handler), options);
    }
    private static EngineeringDiagnosticRun CreateRemoteRun(EngineeringDiagnosticStatus status) { DateTimeOffset now=DateTimeOffset.UtcNow; return new EngineeringDiagnosticRun(Guid.NewGuid(),EngineeringDiagnosticLevel.Level4Analysis,"Aegis.Studio","Test","tests",null,now,now,status,[new EngineeringDiagnosticCheckResult("check","Check",status,"Result")]); }
    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory { public HttpClient CreateClient(string name)=>new(handler,false); }
    private sealed class CapturingHandler : HttpMessageHandler { private readonly Func<HttpRequestMessage,Task<HttpResponseMessage>> responder; public CapturingHandler(Func<HttpRequestMessage,HttpResponseMessage> responder):this(r=>Task.FromResult(responder(r))){} public CapturingHandler(Func<HttpRequestMessage,Task<HttpResponseMessage>> responder){this.responder=responder;} protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>responder(request); }
}
