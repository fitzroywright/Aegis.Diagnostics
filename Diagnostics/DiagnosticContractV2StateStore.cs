namespace Aegis.Diagnostics;

using Common.Diagnostics;
using System.Collections.Concurrent;

public sealed class DiagnosticContractV2StateStore
{
    private readonly ConcurrentDictionary<string, DiagnosticObservation> observations = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DiagnosticFlowInstance> flows = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SynchronizationDiagnostic> synchronization = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, QueueDiagnostic> queues = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DecisionDiagnostic> decisions = new(StringComparer.OrdinalIgnoreCase);

    public void Set(DiagnosticObservation item) =>
        observations[$"{item.ApplicationId}|{item.InstanceId}|{item.Component}|{item.Category}"] = item;

    public void Set(DiagnosticFlowInstance item) =>
        flows[$"{item.ApplicationId}|{item.CorrelationId}"] = item;

    public void Set(SynchronizationDiagnostic item) =>
        synchronization[$"{item.ApplicationId}|{item.InstanceId}|{item.EndpointId}"] = item;

    public void Set(QueueDiagnostic item) =>
        queues[$"{item.ApplicationId}|{item.QueueName}"] = item;

    public void Set(DecisionDiagnostic item) =>
        decisions[$"{item.ApplicationId}|{item.Component}|{item.CorrelationId}|{item.ObservedAtUtc:O}"] = item;

    public IReadOnlyList<DiagnosticObservation> GetObservations(string? applicationId = null) =>
        Filter(observations.Values, applicationId, x => x.ApplicationId)
            .OrderByDescending(x => x.ObservedAtUtc).ToArray();

    public IReadOnlyList<DiagnosticFlowInstance> GetFlows(string? applicationId = null) =>
        Filter(flows.Values, applicationId, x => x.ApplicationId)
            .OrderByDescending(x => x.ObservedAtUtc).Take(1000).ToArray();

    public IReadOnlyList<SynchronizationDiagnostic> GetSynchronization(string? applicationId = null) =>
        Filter(synchronization.Values, applicationId, x => x.ApplicationId)
            .OrderByDescending(x => x.ObservedAtUtc).ToArray();

    public IReadOnlyList<QueueDiagnostic> GetQueues(string? applicationId = null) =>
        Filter(queues.Values, applicationId, x => x.ApplicationId)
            .OrderByDescending(x => x.ObservedAtUtc).ToArray();

    public IReadOnlyList<DecisionDiagnostic> GetDecisions(string? applicationId = null) =>
        Filter(decisions.Values, applicationId, x => x.ApplicationId)
            .OrderByDescending(x => x.ObservedAtUtc).Take(1000).ToArray();

    private static IEnumerable<T> Filter<T>(
        IEnumerable<T> source,
        string? applicationId,
        Func<T, string> selector) =>
        string.IsNullOrWhiteSpace(applicationId)
            ? source
            : source.Where(x => selector(x).Equals(applicationId, StringComparison.OrdinalIgnoreCase));
}
