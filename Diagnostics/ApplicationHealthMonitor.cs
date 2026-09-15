namespace Aegis.Diagnostics;

using Common.Diagnostics;
using System.Diagnostics;

public sealed record ApplicationHealthObservation(
    string ApplicationId,
    string Name,
    string? SiteId,
    string? InstanceId,
    OperationalHealth Health,
    DateTimeOffset ObservedAtUtc,
    long? LatencyMilliseconds,
    int? HttpStatusCode,
    string Summary);

public sealed class ApplicationHealthStateStore(DiagnosticsOptions options)
{
    private readonly object gate = new();
    private readonly Dictionary<string, ApplicationHealthObservation> observations = new(StringComparer.OrdinalIgnoreCase);

    public void Set(ApplicationHealthObservation observation)
    {
        lock (gate) observations[observation.ApplicationId] = observation;
    }

    public IReadOnlyList<ApplicationHealthObservation> GetAll()
    {
        lock (gate)
        {
            DateTimeOffset staleBefore = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(Math.Max(30, options.ObservationStaleSeconds));
            return observations.Values
                .Select(item => item.ObservedAtUtc < staleBefore
                    ? item with { Health = OperationalHealth.Unknown, Summary = $"Stale observation; last checked {item.ObservedAtUtc:O}." }
                    : item)
                .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }
}

public sealed class ApplicationHealthMonitor(
    ConfigurationDiscoveryCatalog discovery,
    ApplicationHealthStateStore state,
    IHttpClientFactory httpClientFactory,
    DiagnosticsOptions options,
    ILogger<ApplicationHealthMonitor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan interval = TimeSpan.FromSeconds(Math.Max(30, options.DiscoveryRefreshSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            foreach (DiagnosticTargetOptions target in discovery.Targets)
            {
                try { await ObserveAsync(target, stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
                catch (Exception exception) { logger.LogWarning(exception, "Unexpected health-monitor failure for {ApplicationId}.", target.ApplicationId); }
            }

            try { await Task.Delay(interval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }

    private async Task ObserveAsync(DiagnosticTargetOptions target, CancellationToken cancellationToken)
    {
        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri))
        {
            state.Set(new(target.ApplicationId, target.Name, target.SiteId, target.InstanceId, OperationalHealth.Unknown, observedAt, null, null, "Public application URL is unresolved in Configuration."));
            return;
        }

        Uri healthUri = new(baseUri, target.HealthPath);
        HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
        Stopwatch stopwatch = Stopwatch.StartNew();
        try
        {
            using HttpResponseMessage response = await client.GetAsync(healthUri, cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            OperationalHealth health = response.IsSuccessStatusCode ? OperationalHealth.Healthy : OperationalHealth.Unhealthy;
            state.Set(new(target.ApplicationId, target.Name, target.SiteId, target.InstanceId, health, observedAt, stopwatch.ElapsedMilliseconds, (int)response.StatusCode,
                response.IsSuccessStatusCode ? "Health endpoint responded successfully." : $"Health endpoint returned HTTP {(int)response.StatusCode}."));
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            state.Set(new(target.ApplicationId, target.Name, target.SiteId, target.InstanceId, OperationalHealth.Unhealthy, observedAt, stopwatch.ElapsedMilliseconds, null, "Health request timed out."));
        }
        catch (HttpRequestException exception)
        {
            stopwatch.Stop();
            state.Set(new(target.ApplicationId, target.Name, target.SiteId, target.InstanceId, OperationalHealth.Unhealthy, observedAt, stopwatch.ElapsedMilliseconds, null, $"Health endpoint is unreachable ({exception.GetType().Name})."));
        }
    }
}
