namespace Aegis.Diagnostics;

using Common.Diagnostics;
using Common.Messaging;

public sealed record DiagnosticPlaybookStep(int Order, string Action, string Purpose, bool RequiresAuthorization = false);
public sealed record DiagnosticPlaybook(string Id, string Name, IReadOnlyList<string> MatchTerms, IReadOnlyList<DiagnosticPlaybookStep> Steps);
public sealed record CorrelatedIncident(Guid IncidentId, DateTimeOffset CreatedAtUtc, EngineeringDiagnosticStatus Status, IReadOnlyList<string> Applications, IReadOnlyList<string> Signals, string Summary);
public sealed record OrchestrationRecommendation(EngineeringDiagnosticLevel CurrentLevel, EngineeringDiagnosticLevel? RecommendedLevel, bool RequiresAuthorization, string Reason, IReadOnlyList<DiagnosticPlaybook> Playbooks, IReadOnlyList<CorrelatedIncident> Incidents);
public sealed record OrchestratedDiagnosticResult(EngineeringDiagnosticRun Run, OrchestrationRecommendation Recommendation, IReadOnlyList<EngineeringDiagnosticRun> Runs);

public sealed class DiagnosticPlaybookCatalog
{
    private static readonly DiagnosticPlaybook[] Playbooks =
    [
        new("database", "Database availability", ["database", "postgres", "sql", "npgsql"],
        [
            new(1, "Verify network reachability and DNS resolution.", "Separate transport failure from database failure."),
            new(2, "Verify the configured database endpoint and port.", "Confirm the application is targeting the intended service."),
            new(3, "Execute the application's non-destructive database diagnostic query.", "Prove the service accepts application traffic."),
            new(4, "Review recent database and application errors.", "Correlate service-side and application-side evidence.")
        ]),
        new("messaging", "Messaging delivery", ["messaging", "smtp", "slack", "teams", "queue"],
        [
            new(1, "Verify Common.Messaging is registered and healthy.", "Confirm the shared messaging runtime is available."),
            new(2, "Inspect queue and dead-letter health.", "Identify blocked or repeatedly failing deliveries."),
            new(3, "Verify configured external channel endpoints.", "Separate queue health from provider connectivity.")
        ]),
        new("secrets", "Secrets provider", ["secret", "openbao", "vault", "credential"],
        [
            new(1, "Verify the configured Common.Secrets provider is enabled.", "Confirm provider selection and bootstrap configuration."),
            new(2, "Run provider health and reauthentication diagnostics.", "Prove the provider can authenticate and recover."),
            new(3, "Verify the required application secret exists without disclosing its value.", "Distinguish provider health from missing secret material.")
        ]),
        new("storage", "Storage availability", ["storage", "attachment", "filesystem", "file"],
        [
            new(1, "Run the application's non-destructive storage probe.", "Verify the configured storage path/provider is reachable."),
            new(2, "Check capacity, permissions, and recent storage errors.", "Identify environmental causes without modifying user data."),
            new(3, "Verify Common.Storage provider selection and configuration.", "Confirm the application is using the intended storage implementation.")
        ]),
        new("network", "Network dependency", ["network", "timeout", "unreachable", "http", "dns"],
        [
            new(1, "Verify DNS and endpoint resolution.", "Confirm the target can be located."),
            new(2, "Verify TCP/HTTP reachability to the dependency.", "Confirm transport connectivity."),
            new(3, "Compare failures across registered applications.", "Detect shared infrastructure incidents.")
        ])
    ];

    public IReadOnlyList<DiagnosticPlaybook> Match(EngineeringDiagnosticRun run)
    {
        string evidence = string.Join(' ', run.Checks.Select(check => $"{check.Name} {check.Summary} {check.Evidence}"));
        return Playbooks.Where(playbook => playbook.MatchTerms.Any(term => evidence.Contains(term, StringComparison.OrdinalIgnoreCase))).ToArray();
    }

    public IReadOnlyList<DiagnosticPlaybook> GetAll() => Playbooks;
}

public sealed class IncidentCorrelationService
{
    public IReadOnlyList<CorrelatedIncident> Correlate(IReadOnlyList<EngineeringDiagnosticRun> runs, TimeSpan? window = null)
    {
        TimeSpan correlationWindow = window ?? TimeSpan.FromMinutes(15);
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - correlationWindow;
        EngineeringDiagnosticRun[] recent = runs.Where(run => run.CompletedAt >= cutoff).ToArray();
        List<(string App, EngineeringDiagnosticStatus Status, string Signal)> signals = [];

        foreach (EngineeringDiagnosticRun run in recent)
        {
            foreach (EngineeringDiagnosticCheckResult check in run.Checks.Where(check => check.Status != EngineeringDiagnosticStatus.Passed))
            {
                string signal = NormalizeSignal(check);
                signals.Add((ExtractApplication(check.Name, run.Application), check.Status, signal));
            }
        }

        return signals
            .GroupBy(item => item.Signal, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Select(item => item.App).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            .Select(group => new CorrelatedIncident(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                group.Max(item => item.Status),
                group.Select(item => item.App).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToArray(),
                [group.Key],
                $"Shared diagnostic signal '{group.Key}' affects {group.Select(item => item.App).Distinct(StringComparer.OrdinalIgnoreCase).Count()} applications."))
            .ToArray();
    }

    private static string NormalizeSignal(EngineeringDiagnosticCheckResult check)
    {
        string text = $"{check.Name} {check.Summary} {check.Evidence}".ToLowerInvariant();
        string[] known = ["database", "postgres", "sql", "messaging", "smtp", "storage", "secret", "openbao", "network", "timeout", "unreachable", "authentication"];
        return known.FirstOrDefault(text.Contains) ?? check.Name.Trim().ToLowerInvariant();
    }

    private static string ExtractApplication(string checkName, string fallback)
    {
        int separator = checkName.IndexOf('—');
        return separator > 0 ? checkName[..separator].Trim() : fallback;
    }
}

public interface IIncidentNotificationPublisher
{
    Task PublishAsync(EngineeringDiagnosticRun run, OrchestrationRecommendation recommendation, CancellationToken cancellationToken = default);
}

public sealed class CommonMessagingIncidentNotificationPublisher(IServiceProvider services, IConfiguration configuration, ILogger<CommonMessagingIncidentNotificationPublisher> logger) : IIncidentNotificationPublisher
{
    public async Task PublishAsync(EngineeringDiagnosticRun run, OrchestrationRecommendation recommendation, CancellationToken cancellationToken = default)
    {
        string[] recipients = configuration.GetSection("Diagnostics:Notifications:RecipientIds").Get<string[]>() ?? [];
        if (recipients.Length == 0) return;

        IMessageService? messaging = services.GetService<IMessageService>();
        if (messaging is null)
        {
            logger.LogWarning("Diagnostics notification recipients are configured but Common.Messaging IMessageService is not registered.");
            return;
        }

        MessageSeverity severity = run.Status switch
        {
            EngineeringDiagnosticStatus.InterventionRequired => MessageSeverity.Critical,
            EngineeringDiagnosticStatus.Failed => MessageSeverity.Error,
            EngineeringDiagnosticStatus.Warning => MessageSeverity.Warning,
            _ => MessageSeverity.Information
        };

        MessageChannel channels = run.Status switch
        {
            EngineeringDiagnosticStatus.InterventionRequired => MessageChannel.InApp | MessageChannel.Smtp | MessageChannel.Slack | MessageChannel.MsTeams,
            EngineeringDiagnosticStatus.Failed => MessageChannel.InApp | MessageChannel.Smtp | MessageChannel.Slack,
            EngineeringDiagnosticStatus.Warning => MessageChannel.InApp,
            _ => MessageChannel.InApp
        };

        string body = recommendation.RecommendedLevel is EngineeringDiagnosticLevel next
            ? $"Run {run.RunId:D} finished {run.Status}. Recommended next level: {(int)next}. {recommendation.Reason}"
            : $"Run {run.RunId:D} finished {run.Status}. {recommendation.Reason}";

        await messaging.SendAsync(new MessageRequest
        {
            RecipientIds = recipients,
            Title = $"Aegis.Diagnostics {run.Status}",
            Body = body,
            Severity = severity,
            Channels = channels,
            Source = "Aegis.Diagnostics",
            CorrelationId = run.RunId.ToString("D")
        }, cancellationToken);
    }
}

public sealed class DiagnosticOrchestrationService(
    EngineeringDiagnosticEngine engine,
    RemoteDiagnosticCatalog remoteCatalog,
    IEngineeringDiagnosticRunStore store,
    DiagnosticPlaybookCatalog playbooks,
    IncidentCorrelationService correlation,
    IIncidentNotificationPublisher notifications,
    DiagnosticsOptions options)
{
    public async Task<OrchestratedDiagnosticResult> RunAsync(EngineeringDiagnosticRunRequest request, string requestedBy, CancellationToken cancellationToken = default)
    {
        EngineeringDiagnosticPolicy.ValidateLevel(request.Level);
        EngineeringDiagnosticPolicy.ValidateReason(request.Level, request.Reason);

        List<EngineeringDiagnosticRun> runs = [];
        EngineeringDiagnosticRun run = await RunLevelAsync(request.Level, request.Reason, requestedBy, cancellationToken);
        runs.Add(run);

        while (run.Status != EngineeringDiagnosticStatus.Passed && TryGetAutomaticEvidenceLevel(run.Level, out EngineeringDiagnosticLevel nextAutomatic))
        {
            run = await RunLevelAsync(nextAutomatic, request.Reason, requestedBy, cancellationToken);
            runs.Add(run);
        }

        IReadOnlyList<EngineeringDiagnosticRun> recent = await store.GetRecentAsync(100, cancellationToken);
        IReadOnlyList<CorrelatedIncident> incidents = correlation.Correlate(recent);
        IReadOnlyList<DiagnosticPlaybook> matched = runs.SelectMany(playbooks.Match).DistinctBy(playbook => playbook.Id).ToArray();
        EngineeringDiagnosticLevel? next = RecommendNextLevel(run);
        bool requiresAuthorization = next is EngineeringDiagnosticLevel.Level2Repair or EngineeringDiagnosticLevel.Level1CriticalIntervention;
        string reason = BuildRecommendationReason(run, next, incidents, runs.Count);
        OrchestrationRecommendation recommendation = new(run.Level, next, requiresAuthorization, reason, matched, incidents);

        await notifications.PublishAsync(run, recommendation, cancellationToken);
        return new(run, recommendation, runs);
    }

    private async Task<EngineeringDiagnosticRun> RunLevelAsync(
        EngineeringDiagnosticLevel level,
        string? reason,
        string requestedBy,
        CancellationToken cancellationToken)
    {
        return await engine.RunAsync(
            level,
            options.ApplicationName,
            options.EnvironmentName,
            requestedBy,
            reason,
            remoteCatalog.Build(level, reason),
            cancellationToken);
    }

    private static bool TryGetAutomaticEvidenceLevel(EngineeringDiagnosticLevel current, out EngineeringDiagnosticLevel next)
    {
        next = current switch
        {
            EngineeringDiagnosticLevel.Level5Scan => EngineeringDiagnosticLevel.Level4Analysis,
            EngineeringDiagnosticLevel.Level4Analysis => EngineeringDiagnosticLevel.Level3Verification,
            _ => default
        };
        return current is EngineeringDiagnosticLevel.Level5Scan or EngineeringDiagnosticLevel.Level4Analysis;
    }

    private static EngineeringDiagnosticLevel? RecommendNextLevel(EngineeringDiagnosticRun run)
    {
        if (run.Status == EngineeringDiagnosticStatus.Passed) return null;
        return run.Level switch
        {
            EngineeringDiagnosticLevel.Level5Scan => EngineeringDiagnosticLevel.Level4Analysis,
            EngineeringDiagnosticLevel.Level4Analysis => EngineeringDiagnosticLevel.Level3Verification,
            EngineeringDiagnosticLevel.Level3Verification => EngineeringDiagnosticLevel.Level2Repair,
            EngineeringDiagnosticLevel.Level2Repair => EngineeringDiagnosticLevel.Level1CriticalIntervention,
            _ => null
        };
    }

    private static string BuildRecommendationReason(
        EngineeringDiagnosticRun run,
        EngineeringDiagnosticLevel? next,
        IReadOnlyList<CorrelatedIncident> incidents,
        int executedLevels)
    {
        string orchestrationText = executedLevels > 1
            ? $"Aegis.Diagnostics automatically completed {executedLevels} non-destructive evidence levels before stopping. "
            : string.Empty;
        if (run.Status == EngineeringDiagnosticStatus.Passed)
            return $"{orchestrationText}No further escalation is recommended because the final diagnostic level passed.";

        string correlationText = incidents.Count == 0
            ? "No cross-application incident correlation was detected."
            : $"{incidents.Count} cross-application correlated incident(s) were detected.";
        if (next is null)
            return $"{orchestrationText}The run still requires attention, but no automatic escalation beyond Level 1 is defined. {correlationText}";
        if (next is EngineeringDiagnosticLevel.Level2Repair or EngineeringDiagnosticLevel.Level1CriticalIntervention)
            return $"{orchestrationText}Escalation to Level {(int)next} is recommended, but explicit operator reason/authorization is required and no destructive action will run automatically. {correlationText}";
        return $"{orchestrationText}Escalation to Level {(int)next} is recommended for deeper evidence collection. {correlationText}";
    }
}
