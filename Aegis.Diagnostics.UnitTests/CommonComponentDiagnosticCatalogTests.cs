namespace Aegis.Diagnostics.UnitTests;

using Common.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public sealed class CommonComponentDiagnosticCatalogTests
{
    [Fact]
    public void Catalogue_has_unique_stable_test_ids()
    {
        CommonComponentDiagnosticCatalog catalog = Create();
        string[] ids = catalog.Catalogue.Select(x => x.TestId).ToArray();

        Assert.Equal(49, ids.Length);
        Assert.Equal(ids.Length, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Level5_and_Level4_tests_are_non_destructive()
    {
        CommonComponentDiagnosticCatalog catalog = Create();

        LevelXCatalogueEntry[] unsafeEntries = catalog.Catalogue
            .Where(x => x.IntroducedAtLevel is EngineeringDiagnosticLevel.Level5Scan or EngineeringDiagnosticLevel.Level4Analysis)
            .Where(x => x.Destructive)
            .ToArray();

        Assert.Empty(unsafeEntries);
    }

    [Theory]
    [InlineData("Common.Diagnostics", 8)]
    [InlineData("Common.Registration", 9)]
    [InlineData("Common.Security", 8)]
    [InlineData("Common.Secrets", 8)]
    [InlineData("Common.Messaging", 10)]
    [InlineData("Common.Storage", 6)]
    public void Each_common_component_has_multiple_discrete_tests(string component, int expected)
    {
        CommonComponentDiagnosticCatalog catalog = Create();
        Assert.Equal(expected, catalog.Catalogue.Count(x => x.Component.Equals(component, StringComparison.OrdinalIgnoreCase)));
    }

    private static CommonComponentDiagnosticCatalog Create()
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CommonSecrets:Mode"] = "Development",
            ["CommonSecrets:Providers:Local:Type"] = "Configuration"
        }).Build();

        return new(
            new ServiceCollection().BuildServiceProvider(),
            configuration,
            new EmptyTargetCatalog(),
            new EmptyExplainService(),
            NullLogger<CommonComponentDiagnosticCatalog>.Instance);
    }

    private sealed class EmptyTargetCatalog : IDiagnosticTargetCatalog
    {
        public IReadOnlyList<DiagnosticTargetOptions> Targets => [];
        public DateTimeOffset? LastSuccessfulRefreshUtc => DateTimeOffset.UtcNow;
        public string? LastError => null;
        public bool IsStale => false;
    }

    private sealed class EmptyExplainService : ILevelXStateExplainService
    {
        public Task<LevelXStateExplanation?> ExplainAsync(string applicationId, string? instanceId, CancellationToken cancellationToken = default)
            => Task.FromResult<LevelXStateExplanation?>(null);
    }
}
