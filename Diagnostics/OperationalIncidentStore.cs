namespace Aegis.Diagnostics;

using Common.Diagnostics;
using System.Text.Json;

public sealed record OperationalIncident(
    Guid IncidentId,
    string ApplicationId,
    string Name,
    OperationalHealth Health,
    string Status,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset LastObservedAtUtc,
    DateTimeOffset? ResolvedAtUtc,
    string Summary);

public sealed class OperationalIncidentStore
{
    private readonly object gate = new();
    private readonly string path;
    private readonly List<OperationalIncident> incidents;

    public OperationalIncidentStore(DiagnosticsOptions options)
    {
        path = Path.GetFullPath(options.IncidentStorePath, AppContext.BaseDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        incidents = Load(path);
    }

    public IReadOnlyList<OperationalIncident> GetAll(bool includeResolved)
    {
        lock (gate)
        {
            return incidents
                .Where(x => includeResolved || !string.Equals(x.Status, "Resolved", StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => string.Equals(x.Status, "Active", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenByDescending(x => x.StartedAtUtc)
                .ToArray();
        }
    }

    public void Reconcile(IEnumerable<ApplicationHealthObservation> observations)
    {
        lock (gate)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            foreach (ApplicationHealthObservation observation in observations)
            {
                OperationalIncident? active = incidents
                    .LastOrDefault(x =>
                        string.Equals(x.ApplicationId, observation.ApplicationId, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(x.Status, "Active", StringComparison.OrdinalIgnoreCase));

                if (observation.Health == OperationalHealth.Healthy)
                {
                    if (active is not null)
                    {
                        Replace(active, active with
                        {
                            Health = OperationalHealth.Healthy,
                            Status = "Resolved",
                            LastObservedAtUtc = observation.ObservedAtUtc,
                            ResolvedAtUtc = now,
                            Summary = $"Recovered. {observation.Summary}"
                        });
                    }
                    continue;
                }

                if (active is null)
                {
                    incidents.Add(new(
                        Guid.NewGuid(),
                        observation.ApplicationId,
                        observation.Name,
                        observation.Health,
                        "Active",
                        observation.ObservedAtUtc,
                        observation.ObservedAtUtc,
                        null,
                        observation.Summary));
                }
                else
                {
                    Replace(active, active with
                    {
                        Name = observation.Name,
                        Health = observation.Health,
                        LastObservedAtUtc = observation.ObservedAtUtc,
                        Summary = observation.Summary
                    });
                }
            }

            Persist();
        }
    }

    private void Replace(OperationalIncident previous, OperationalIncident updated)
    {
        int index = incidents.FindIndex(x => x.IncidentId == previous.IncidentId);
        if (index >= 0) incidents[index] = updated;
    }

    private void Persist()
    {
        string temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(incidents, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, path, true);
    }

    private static List<OperationalIncident> Load(string path)
    {
        if (!File.Exists(path)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<OperationalIncident>>(File.ReadAllText(path)) ?? [];
        }
        catch
        {
            return [];
        }
    }
}

public sealed class OperationalIncidentReconciler(
    ApplicationHealthStateStore health,
    OperationalIncidentStore incidents,
    ConfigurationDiscoveryCatalog discovery,
    DiagnosticsOptions options) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan interval = TimeSpan.FromSeconds(Math.Max(5, options.HealthPollSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            List<ApplicationHealthObservation> observations = health.GetAll().ToList();

            observations.Add(new(
                options.ApplicationId,
                options.ApplicationName,
                options.SiteId,
                options.InstanceId ?? Environment.MachineName,
                discovery.IsStale ? OperationalHealth.Degraded : OperationalHealth.Healthy,
                DateTimeOffset.UtcNow,
                null,
                null,
                discovery.IsStale
                    ? "Diagnostics is running but Configuration discovery is stale."
                    : "Diagnostics is running and Configuration discovery is current."));

            incidents.Reconcile(observations);

            try { await Task.Delay(interval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }
}
