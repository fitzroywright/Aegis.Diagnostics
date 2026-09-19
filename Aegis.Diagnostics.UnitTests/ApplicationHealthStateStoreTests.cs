using Common.Diagnostics;
using Xunit;

namespace Aegis.Diagnostics.UnitTests;

public sealed class ApplicationHealthStateStoreTests
{
    [Fact]
    public void Stale_healthy_observation_becomes_unknown()
    {
        var options = new DiagnosticsOptions { ObservationStaleSeconds = 30 };
        var store = new ApplicationHealthStateStore(options);
        store.Set(new ApplicationHealthObservation(
            "App",
            "Application",
            null,
            "instance-1",
            OperationalHealth.Healthy,
            DateTimeOffset.UtcNow.AddMinutes(-2),
            12,
            200,
            "Healthy when observed."));

        ApplicationHealthObservation observed = Assert.Single(store.GetAll());

        Assert.Equal(OperationalHealth.Unknown, observed.Health);
        Assert.Contains("Stale observation", observed.Summary, StringComparison.Ordinal);
    }
}
