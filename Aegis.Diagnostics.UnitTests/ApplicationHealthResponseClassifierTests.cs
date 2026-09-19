using System.Net;
using Common.Diagnostics;
using Xunit;

namespace Aegis.Diagnostics.UnitTests;

public sealed class ApplicationHealthResponseClassifierTests
{
    [Fact]
    public void Http200_with_healthy_payload_is_healthy()
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.OK,
            """{"status":"Healthy"}""");

        Assert.Equal(OperationalHealth.Healthy, result.Health);
    }

    [Fact]
    public void Http200_without_status_is_unknown()
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.OK,
            """{"service":"up"}""");

        Assert.Equal(OperationalHealth.Unknown, result.Health);
    }

    [Fact]
    public void Http200_with_malformed_payload_is_unknown()
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.OK,
            "{not-json");

        Assert.Equal(OperationalHealth.Unknown, result.Health);
    }

    [Fact]
    public void Empty_success_payload_is_unknown()
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.OK,
            "");

        Assert.Equal(OperationalHealth.Unknown, result.Health);
    }

    [Fact]
    public void Server_error_is_unhealthy()
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.ServiceUnavailable,
            null);

        Assert.Equal(OperationalHealth.Unhealthy, result.Health);
    }

    [Theory]
    [InlineData("Degraded")]
    [InlineData("Warning")]
    public void Degraded_or_warning_payload_is_degraded(string state)
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.OK,
            $$"""{"status":"{{state}}"}""");

        Assert.Equal(OperationalHealth.Degraded, result.Health);
    }

    [Theory]
    [InlineData("Failed")]
    [InlineData("Unhealthy")]
    [InlineData("Offline")]
    public void Explicit_failure_payload_is_unhealthy(string state)
    {
        var result = ApplicationHealthResponseClassifier.Classify(
            HttpStatusCode.OK,
            $$"""{"status":"{{state}}"}""");

        Assert.Equal(OperationalHealth.Unhealthy, result.Health);
    }
}
