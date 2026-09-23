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
        DiagnosticLevelCatalogueEntry[] entries = AllEntries();
        string[] ids = entries.Select(x => x.TestId).ToArray();

        Assert.Equal(85, ids.Length);
        Assert.Equal(ids.Length, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Level5_and_Level4_tests_are_non_destructive()
    {
        DiagnosticLevelCatalogueEntry[] unsafeEntries = AllEntries()
            .Where(x => x.IntroducedAtLevel is EngineeringDiagnosticLevel.Level5Scan or EngineeringDiagnosticLevel.Level4Analysis)
            .Where(x => x.Destructive)
            .ToArray();

        Assert.Empty(unsafeEntries);
    }

    [Theory]
    [InlineData("Common.Diagnostics", 14)]
    [InlineData("Common.Registration", 15)]
    [InlineData("Common.Security", 14)]
    [InlineData("Common.Secrets", 14)]
    [InlineData("Common.Messaging", 16)]
    [InlineData("Common.Storage", 12)]
    public void Each_common_component_has_multiple_discrete_tests(string component, int expected)
    {
        Assert.Equal(expected, AllEntries().Count(x => x.Component.Equals(component, StringComparison.OrdinalIgnoreCase)));
    }

    [Theory]
    [InlineData("Common.Diagnostics")]
    [InlineData("Common.Registration")]
    [InlineData("Common.Security")]
    [InlineData("Common.Secrets")]
    [InlineData("Common.Messaging")]
    [InlineData("Common.Storage")]
    public void Every_common_component_has_multiple_tests_at_every_level(string component)
    {
        DiagnosticLevelCatalogueEntry[] entries = AllEntries().Where(x => x.Component.Equals(component, StringComparison.OrdinalIgnoreCase)).ToArray();

        foreach (EngineeringDiagnosticLevel level in EngineeringDiagnosticLevelSemantics.StarfleetOrder)
            Assert.True(entries.Count(x => x.IntroducedAtLevel == level) >= 2, $"{component} needs at least two discrete tests introduced at Level {(int)level}.");
    }

    private static DiagnosticLevelCatalogueEntry[] AllEntries()
        => Create().Catalogue.Concat(new CommonIsolatedCertificationCatalog().Catalogue).ToArray();

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

    private sealed class EmptyExplainService : IDiagnosticLevelStateExplainService
    {
        public Task<DiagnosticLevelStateExplanation?> ExplainAsync(string applicationId, string? instanceId, CancellationToken cancellationToken = default)
            => Task.FromResult<DiagnosticLevelStateExplanation?>(null);
    }
}
