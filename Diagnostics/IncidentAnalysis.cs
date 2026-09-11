namespace Aegis.Diagnostics.Diagnostics;

public enum OperationalSeverity { Healthy, Advisory, Degraded, Critical }

public sealed record DependencyImpact(string ApplicationId, string FailedDependencyId, bool Critical, int Distance, IReadOnlyList<string> Path, string Purpose);
public sealed record DependencyFailure(string FailedDependencyId, IReadOnlyList<DependencyImpact> Impacts);
public sealed record OperationalRiskItem(string ApplicationId, OperationalSeverity Level, int Priority, string Cause, string RecommendedAction, IReadOnlyList<string> Evidence);
public sealed record OperationalRiskReport(DateTimeOffset EvaluatedAtUtc, IReadOnlyList<OperationalRiskItem> Items);
public sealed record RemediationStep(int Order, string Target, string Action, string Reason, bool Critical);
public sealed record IncidentSummary(Guid IncidentId, DateTimeOffset CreatedAtUtc, OperationalSeverity Severity, string Headline, IReadOnlyList<string> RootSuspects, IReadOnlyList<string> AffectedApplications, IReadOnlyList<RemediationStep> RecoveryPlan, IReadOnlyList<string> Evidence);

public sealed class IncidentAnalyzer
{
    public IncidentSummary Analyze(IReadOnlyList<OperationalRiskItem> observedRisks)
    {
        OperationalRiskItem[] affected = observedRisks.Where(x => x.Level != OperationalSeverity.Healthy).OrderByDescending(x => x.Priority).ToArray();
        OperationalSeverity severity = affected.Length == 0 ? OperationalSeverity.Healthy : affected.Max(x => x.Level);
        string[] suspects = affected.Select(x => ExtractQuoted(x.Cause)).Where(x => x is not null).Cast<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        int order = 1;
        RemediationStep[] recovery = affected.Select(x => new RemediationStep(order++, x.ApplicationId, x.RecommendedAction, x.Cause, x.Level == OperationalSeverity.Critical)).ToArray();
        return new(Guid.NewGuid(), DateTimeOffset.UtcNow, severity,
            affected.Length == 0 ? "Fleet healthy" : $"{affected.Length} application(s) require operational attention; highest severity {severity}.",
            suspects,
            affected.Select(x => x.ApplicationId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            recovery,
            affected.SelectMany(x => x.Evidence).Distinct().ToArray());
    }

    private static string? ExtractQuoted(string value)
    {
        int start = value.IndexOf('\'');
        if (start < 0) return null;
        int end = value.IndexOf('\'', start + 1);
        return end > start ? value[(start + 1)..end] : null;
    }
}

public sealed class RecoveryVerifier
{
    public (bool Recovered, int PreviousRisk, int CurrentRisk, string Message) Verify(OperationalRiskReport before, OperationalRiskReport after)
    {
        int previous = before.Items.Sum(x => x.Priority);
        int current = after.Items.Sum(x => x.Priority);
        bool recovered = after.Items.All(x => x.Level == OperationalSeverity.Healthy);
        string message = recovered ? "Recovery verified." : current < previous ? $"Recovery progressing: risk reduced from {previous} to {current}." : $"Recovery not proven: risk is {current} versus {previous}.";
        return (recovered, previous, current, message);
    }
}
