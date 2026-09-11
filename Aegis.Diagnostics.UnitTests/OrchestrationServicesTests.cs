using Aegis.Diagnostics;
using Common.Diagnostics;

namespace Aegis.Diagnostics.UnitTests;

public sealed class OrchestrationServicesTests
{
    [Fact]
    public void Playbook_catalog_matches_database_failure()
    {
        EngineeringDiagnosticRun run = CreateRun(
            "Aegis.Studio",
            "Aegis.Studio — Level 4",
            "PostgreSQL database connectivity failed.",
            EngineeringDiagnosticStatus.Failed);

        DiagnosticPlaybookCatalog catalog = new();
        IReadOnlyList<DiagnosticPlaybook> matches = catalog.Match(run);

        Assert.Contains(matches, playbook => playbook.Id == "database");
    }

    [Fact]
    public void Correlation_requires_same_signal_across_multiple_applications()
    {
        EngineeringDiagnosticRun studio = CreateRun(
            "Aegis.Diagnostics",
            "Aegis.Studio — Level 4",
            "PostgreSQL database connectivity failed.",
            EngineeringDiagnosticStatus.Failed);
        EngineeringDiagnosticRun cafeteria = CreateRun(
            "Aegis.Diagnostics",
            "Aegis.Cafeteria — Level 4",
            "Database endpoint is unreachable.",
            EngineeringDiagnosticStatus.Failed);

        IncidentCorrelationService correlation = new();
        IReadOnlyList<CorrelatedIncident> incidents = correlation.Correlate([studio, cafeteria], TimeSpan.FromMinutes(15));

        CorrelatedIncident incident = Assert.Single(incidents);
        Assert.Contains("Aegis.Studio", incident.Applications);
        Assert.Contains("Aegis.Cafeteria", incident.Applications);
        Assert.Contains("database", incident.Signals);
    }

    [Fact]
    public void Correlation_does_not_create_incident_for_single_application()
    {
        EngineeringDiagnosticRun studio = CreateRun(
            "Aegis.Diagnostics",
            "Aegis.Studio — Level 4",
            "PostgreSQL database connectivity failed.",
            EngineeringDiagnosticStatus.Failed);

        IncidentCorrelationService correlation = new();
        IReadOnlyList<CorrelatedIncident> incidents = correlation.Correlate([studio], TimeSpan.FromMinutes(15));

        Assert.Empty(incidents);
    }

    private static EngineeringDiagnosticRun CreateRun(
        string application,
        string checkName,
        string summary,
        EngineeringDiagnosticStatus status)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new EngineeringDiagnosticRun(
            Guid.NewGuid(),
            EngineeringDiagnosticLevel.Level4Analysis,
            application,
            "Test",
            "unit-test",
            null,
            now.AddSeconds(-1),
            now,
            status,
            [new EngineeringDiagnosticCheckResult("test", checkName, status, summary)]);
    }
}
