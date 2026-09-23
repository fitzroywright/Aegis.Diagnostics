namespace Aegis.Diagnostics;

using Common.Diagnostics;
using Common.Messaging;
using Common.Registration;
using Common.Secrets;
using Common.Security.Abstractions;
using Common.Security.Authorization;
using Common.Security.Constants;
using Common.Security.Services.Functions;
using Common.Storage;
using Microsoft.Extensions.DependencyInjection;
using System.Text;

public sealed record LevelXCatalogueEntry(
    string TestId,
    string Component,
    string Name,
    EngineeringDiagnosticLevel IntroducedAtLevel,
    bool Destructive,
    string Description);

public sealed class CommonComponentDiagnosticCatalog(
    IServiceProvider services,
    IConfiguration configuration,
    IDiagnosticTargetCatalog discovery,
    ILevelXStateExplainService stateExplain,
    ILogger<CommonComponentDiagnosticCatalog> logger)
{
    private readonly IReadOnlyList<LevelXCatalogueEntry> catalogue =
    [
        // Common.Diagnostics
        new("DIA-001", CommonDiagnosticTargets.Diagnostics, "Engineering engine registered", EngineeringDiagnosticLevel.Level5Scan, false, "Verify the LevelX engine is available in dependency injection."),
        new("DIA-002", CommonDiagnosticTargets.Diagnostics, "Run store registered", EngineeringDiagnosticLevel.Level5Scan, false, "Verify persistent diagnostic run storage is registered."),
        new("DIA-003", CommonDiagnosticTargets.Diagnostics, "Discovery freshness", EngineeringDiagnosticLevel.Level5Scan, false, "Verify Configuration-backed discovery has completed and is not stale."),
        new("DIA-004", CommonDiagnosticTargets.Diagnostics, "Target inventory available", EngineeringDiagnosticLevel.Level5Scan, false, "Verify at least one registered diagnostic target is discoverable."),
        new("DIA-005", CommonDiagnosticTargets.Diagnostics, "Starfleet level ordering", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify Level 5 through Level 1 ordering and depth semantics."),
        new("DIA-006", CommonDiagnosticTargets.Diagnostics, "UTC clock semantics", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify diagnostics freshness arithmetic is based on UTC DateTimeOffset."),
        new("DIA-007", CommonDiagnosticTargets.Diagnostics, "Diagnostic codes unique", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify LevelX diagnostic code identifiers do not collide."),
        new("DIA-008", CommonDiagnosticTargets.Diagnostics, "Common target registry unique", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify Common component target identifiers are unique."),

        // Common.Registration
        new("REG-001", CommonDiagnosticTargets.Registration, "Configuration endpoint resolves", EngineeringDiagnosticLevel.Level5Scan, false, "Resolve the internal Configuration endpoint without modifying registration state."),
        new("REG-002", CommonDiagnosticTargets.Registration, "Operations endpoint resolves", EngineeringDiagnosticLevel.Level5Scan, false, "Resolve the internal Operations endpoint without modifying registration state."),
        new("REG-003", CommonDiagnosticTargets.Registration, "Registered inventory available", EngineeringDiagnosticLevel.Level5Scan, false, "Verify registered applications are discoverable."),
        new("REG-004", CommonDiagnosticTargets.Registration, "Registration identities complete", EngineeringDiagnosticLevel.Level5Scan, false, "Verify discovered applications have ApplicationId and InstanceId."),
        new("REG-005", CommonDiagnosticTargets.Registration, "Reference registration explainable", EngineeringDiagnosticLevel.Level5Scan, false, "Verify at least one registration can be explained using authoritative Operations evidence."),
        new("REG-006", CommonDiagnosticTargets.Registration, "Registration identities unique", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify ApplicationId/InstanceId identities do not collide."),
        new("REG-007", CommonDiagnosticTargets.Registration, "Public endpoint transport policy", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify public Operations and Configuration URLs use HTTPS."),
        new("REG-008", CommonDiagnosticTargets.Registration, "Published application URLs valid", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify published application diagnostic base URLs are absolute when present."),
        new("REG-009", CommonDiagnosticTargets.Registration, "Cross-application registration consistency", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify authoritative registration state is consistent for discovered applications."),

        // Common.Security
        new("SEC-001", CommonDiagnosticTargets.Security, "Operational permissions present", EngineeringDiagnosticLevel.Level5Scan, false, "Verify the operational permission catalogue is populated."),
        new("SEC-002", CommonDiagnosticTargets.Security, "Operational permissions unique", EngineeringDiagnosticLevel.Level5Scan, false, "Verify operational permission keys are unique."),
        new("SEC-003", CommonDiagnosticTargets.Security, "Capability naming policy", EngineeringDiagnosticLevel.Level5Scan, false, "Verify operational permissions are capability names rather than job titles."),
        new("SEC-004", CommonDiagnosticTargets.Security, "Required diagnostics permissions present", EngineeringDiagnosticLevel.Level5Scan, false, "Verify Diagnostics.View and Diagnostics.Run are defined."),
        new("SEC-005", CommonDiagnosticTargets.Security, "LDAP filter escaping", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify LDAP metacharacters are escaped safely."),
        new("SEC-006", CommonDiagnosticTargets.Security, "Username normalization", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify domain-qualified usernames normalize consistently."),
        new("SEC-007", CommonDiagnosticTargets.Security, "Login normalization", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify default-domain login normalization."),
        new("SEC-008", CommonDiagnosticTargets.Security, "Ungrant permission denial", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify the permission authorizer denies an ungranted capability."),

        // Common.Secrets
        new("SCR-001", CommonDiagnosticTargets.Secrets, "Secrets health service registered", EngineeringDiagnosticLevel.Level5Scan, false, "Verify Common.Secrets health is registered."),
        new("SCR-002", CommonDiagnosticTargets.Secrets, "Secret provider configured", EngineeringDiagnosticLevel.Level5Scan, false, "Verify a provider is configured."),
        new("SCR-003", CommonDiagnosticTargets.Secrets, "Secret provider reachable", EngineeringDiagnosticLevel.Level5Scan, false, "Verify the configured provider is reachable without reading secret values."),
        new("SCR-004", CommonDiagnosticTargets.Secrets, "Provider health probes available", EngineeringDiagnosticLevel.Level5Scan, false, "Verify provider health probes are registered."),
        new("SCR-005", CommonDiagnosticTargets.Secrets, "Provider policy valid", EngineeringDiagnosticLevel.Level4Analysis, false, "Validate current CommonSecrets policy without changing provider state."),
        new("SCR-006", CommonDiagnosticTargets.Secrets, "Provider order resolvable", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify provider precedence is explicit and resolvable."),
        new("SCR-007", CommonDiagnosticTargets.Secrets, "Enabled providers healthy", EngineeringDiagnosticLevel.Level4Analysis, false, "Probe enabled providers without exposing values."),
        new("SCR-008", CommonDiagnosticTargets.Secrets, "Secrets V2 health classification", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify configured/reachable/authenticated classification using health-only evidence."),

        // Common.Messaging
        new("MSG-001", CommonDiagnosticTargets.Messaging, "Queue health service registered", EngineeringDiagnosticLevel.Level5Scan, false, "Verify messaging queue health is registered."),
        new("MSG-002", CommonDiagnosticTargets.Messaging, "Queue available", EngineeringDiagnosticLevel.Level5Scan, false, "Read queue health without consuming or modifying messages."),
        new("MSG-003", CommonDiagnosticTargets.Messaging, "Pending backlog below critical", EngineeringDiagnosticLevel.Level5Scan, false, "Compare pending count with the configured critical threshold."),
        new("MSG-004", CommonDiagnosticTargets.Messaging, "Dead-letter backlog below critical", EngineeringDiagnosticLevel.Level5Scan, false, "Compare dead-letter count with the configured critical threshold."),
        new("MSG-005", CommonDiagnosticTargets.Messaging, "Expired leases below critical", EngineeringDiagnosticLevel.Level5Scan, false, "Verify expired delivery leases are below the critical threshold."),
        new("MSG-006", CommonDiagnosticTargets.Messaging, "Oldest pending age below critical", EngineeringDiagnosticLevel.Level5Scan, false, "Verify the oldest pending item is not critically stale."),
        new("MSG-007", CommonDiagnosticTargets.Messaging, "Threshold ordering valid", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify warning thresholds do not exceed critical thresholds."),
        new("MSG-008", CommonDiagnosticTargets.Messaging, "Queue metric invariants", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify queue counters and ages cannot be negative."),
        new("MSG-009", CommonDiagnosticTargets.Messaging, "Provider acceptance semantics", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify provider acceptance is not misclassified as delivery."),
        new("MSG-010", CommonDiagnosticTargets.Messaging, "Delivery receipt semantics", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify positive and negative receipts map to Delivered and Failed."),

        // Common.Storage
        new("STO-001", CommonDiagnosticTargets.Storage, "Storage library available", EngineeringDiagnosticLevel.Level5Scan, false, "Verify Common.Storage is loadable."),
        new("STO-002", CommonDiagnosticTargets.Storage, "Host storage provider registration", EngineeringDiagnosticLevel.Level5Scan, false, "Report whether this host has an IFileStorage provider configured."),
        new("STO-003", CommonDiagnosticTargets.Storage, "Ephemeral storage health probe", EngineeringDiagnosticLevel.Level5Scan, false, "Create/read/delete only inside an isolated temporary directory and remove it after the test."),
        new("STO-004", CommonDiagnosticTargets.Storage, "Ephemeral store/read/delete round trip", EngineeringDiagnosticLevel.Level4Analysis, false, "Exercise storage in an isolated temporary directory with guaranteed cleanup."),
        new("STO-005", CommonDiagnosticTargets.Storage, "Ephemeral metadata integrity", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify stored metadata and content hash in an isolated temporary directory."),
        new("STO-006", CommonDiagnosticTargets.Storage, "Path traversal rejection", EngineeringDiagnosticLevel.Level4Analysis, false, "Verify unsafe storage keys are rejected without writing outside the temporary sandbox.")
    ];

    public IReadOnlyList<LevelXCatalogueEntry> Catalogue => catalogue;

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build(DiagnosticTarget target)
    {
        IEnumerable<LevelXCatalogueEntry> selected = target.Type switch
        {
            DiagnosticTargetType.ControlPlane => catalogue,
            DiagnosticTargetType.CommonComponent => catalogue.Where(x => string.Equals(x.Component, target.TargetId, StringComparison.OrdinalIgnoreCase)),
            _ => []
        };

        return selected.Select(ToDefinition).ToArray();
    }

    private EngineeringDiagnosticCheckDefinition ToDefinition(LevelXCatalogueEntry item) =>
        new(item.TestId, $"{item.TestId} — {item.Name}", item.IntroducedAtLevel, ct => RunAsync(item, ct));

    private async Task<EngineeringDiagnosticCheckResult> RunAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        return item.TestId switch
        {
            "DIA-001" => ServiceRegistered<EngineeringDiagnosticEngine>(item),
            "DIA-002" => ServiceRegistered<IEngineeringDiagnosticRunStore>(item),
            "DIA-003" => DiscoveryFresh(item),
            "DIA-004" => discovery.Targets.Count > 0 ? Pass(item, "Diagnostic target inventory is populated.", "> 0 target", discovery.Targets.Count.ToString()) : Warn(item, "No registered diagnostic targets are currently discoverable.", "> 0 target", "0"),
            "DIA-005" => StarfleetOrder(item),
            "DIA-006" => DateTimeOffset.UtcNow.Offset == TimeSpan.Zero ? Pass(item, "UTC clock semantics are correct.", "UTC offset 00:00", DateTimeOffset.UtcNow.Offset.ToString()) : Fail(item, "UTC clock semantics are inconsistent.", "UTC offset 00:00", DateTimeOffset.UtcNow.Offset.ToString()),
            "DIA-007" => UniqueStrings(item, [LevelXDiagnosticCodes.StateDerivationMismatch, LevelXDiagnosticCodes.StaleTelemetry, LevelXDiagnosticCodes.StaleAuthority, LevelXDiagnosticCodes.HealthMismatch, LevelXDiagnosticCodes.AuthorityUnavailable, LevelXDiagnosticCodes.ControlPlaneStateDivergence]),
            "DIA-008" => UniqueStrings(item, CommonDiagnosticTargets.Components),

            "REG-001" => EndpointResolves(item, AegisControlPlaneService.Configuration, false),
            "REG-002" => EndpointResolves(item, AegisControlPlaneService.Operations, false),
            "REG-003" => discovery.Targets.Count > 0 ? Pass(item, "Registered application inventory is available.", "> 0 registrations", discovery.Targets.Count.ToString()) : Warn(item, "No registered application inventory is currently available.", "> 0 registrations", "0"),
            "REG-004" => RegistrationIdentityCompleteness(item),
            "REG-005" => await ReferenceRegistrationExplainableAsync(item, ct),
            "REG-006" => RegistrationIdentityUniqueness(item),
            "REG-007" => PublicEndpointPolicy(item),
            "REG-008" => PublishedUrlsValid(item),
            "REG-009" => await RegistrationConsistencyAsync(item, ct),

            "SEC-001" => OperationalPermissions.All.Count > 0 ? Pass(item, "Operational permission catalogue is populated.", "> 0 permissions", OperationalPermissions.All.Count.ToString()) : Fail(item, "Operational permission catalogue is empty.", "> 0 permissions", "0"),
            "SEC-002" => UniqueStrings(item, OperationalPermissions.All),
            "SEC-003" => CapabilityNames(item),
            "SEC-004" => RequiredPermissions(item),
            "SEC-005" => LdapFilterEscaper.Escape("a*(b)\\c") == @"a\2a\28b\29\5cc" ? Pass(item, "LDAP metacharacters are escaped correctly.", @"a\2a\28b\29\5cc", LdapFilterEscaper.Escape("a*(b)\\c")) : Fail(item, "LDAP escaping invariant failed.", @"a\2a\28b\29\5cc", LdapFilterEscaper.Escape("a*(b)\\c")),
            "SEC-006" => UserNameNormalizer.GetUserNameWithoutDomain("EXAMPLE\\TestUser") == "testuser" && UserNameNormalizer.GetUserNameWithoutDomain("testuser@example.local") == "testuser" ? Pass(item, "Username normalization is consistent.", "testuser", "testuser") : Fail(item, "Username normalization invariant failed.", "testuser", "unexpected"),
            "SEC-007" => UserNameNormalizer.NormalizeLogin("TestUser", "example.local") == "testuser@example.local" ? Pass(item, "Login normalization is consistent.", "testuser@example.local", UserNameNormalizer.NormalizeLogin("TestUser", "example.local")) : Fail(item, "Login normalization invariant failed.", "testuser@example.local", UserNameNormalizer.NormalizeLogin("TestUser", "example.local")),
            "SEC-008" => await PermissionDenialAsync(item, ct),

            "SCR-001" => ServiceRegistered<ICommonSecretsHealthCheck>(item),
            "SCR-002" => await SecretsConfiguredAsync(item, ct),
            "SCR-003" => await SecretsReachableAsync(item, ct),
            "SCR-004" => services.GetServices<ISecretProviderHealth>().Any() ? Pass(item, "Secret provider health probes are registered.", "> 0 probes", services.GetServices<ISecretProviderHealth>().Count().ToString()) : Warn(item, "No secret provider health probes are registered.", "> 0 probes", "0"),
            "SCR-005" => SecretsPolicy(item),
            "SCR-006" => SecretsProviderOrder(item),
            "SCR-007" => await EnabledSecretProvidersHealthyAsync(item, ct),
            "SCR-008" => await SecretsV2HealthAsync(item, ct),

            "MSG-001" => ServiceRegistered<IExternalDeliveryQueueHealth>(item),
            "MSG-002" => await MessagingQueueAvailableAsync(item, ct),
            "MSG-003" => await MessagingThresholdAsync(item, ct, "pending"),
            "MSG-004" => await MessagingThresholdAsync(item, ct, "dead"),
            "MSG-005" => await MessagingThresholdAsync(item, ct, "expired"),
            "MSG-006" => await MessagingThresholdAsync(item, ct, "age"),
            "MSG-007" => MessagingThresholdOrdering(item),
            "MSG-008" => await MessagingMetricInvariantsAsync(item, ct),
            "MSG-009" => MessagingDeliverySemantics.ProviderSendCompleted(true) == MessageDeliveryState.ProviderAccepted ? Pass(item, "Provider acceptance remains distinct from delivery.", "ProviderAccepted", MessagingDeliverySemantics.ProviderSendCompleted(true).ToString()) : Fail(item, "Provider acceptance semantics are invalid.", "ProviderAccepted", MessagingDeliverySemantics.ProviderSendCompleted(true).ToString()),
            "MSG-010" => MessagingDeliverySemantics.Receipt(true) == MessageDeliveryState.Delivered && MessagingDeliverySemantics.Receipt(false) == MessageDeliveryState.Failed ? Pass(item, "Delivery receipt semantics are correct.", "Delivered/Failed", $"{MessagingDeliverySemantics.Receipt(true)}/{MessagingDeliverySemantics.Receipt(false)}") : Fail(item, "Delivery receipt semantics are invalid.", "Delivered/Failed", $"{MessagingDeliverySemantics.Receipt(true)}/{MessagingDeliverySemantics.Receipt(false)}"),

            "STO-001" => typeof(LocalFileStorage).Assembly.GetName().Name == "Common.Storage" ? Pass(item, "Common.Storage assembly is available.", "Common.Storage", typeof(LocalFileStorage).Assembly.GetName().Name ?? "") : Fail(item, "Common.Storage assembly identity is unexpected.", "Common.Storage", typeof(LocalFileStorage).Assembly.GetName().Name ?? ""),
            "STO-002" => services.GetService<IFileStorage>() is null ? Warn(item, "This Diagnostics host does not configure a live IFileStorage provider; isolated library probes remain available.", "Provider registered when host uses Common.Storage", "Not registered") : Pass(item, "A live IFileStorage provider is registered on this host.", "Registered or not applicable", "Registered"),
            "STO-003" => await StorageHealthProbeAsync(item, ct),
            "STO-004" => await StorageRoundTripAsync(item, ct, verifyMetadata: false),
            "STO-005" => await StorageRoundTripAsync(item, ct, verifyMetadata: true),
            "STO-006" => await StorageTraversalAsync(item, ct),
            _ => Fail(item, "Unknown LevelX catalogue test.", "Known test ID", item.TestId)
        };
    }

    private EngineeringDiagnosticCheckResult ServiceRegistered<T>(LevelXCatalogueEntry item) where T : class =>
        services.GetService<T>() is not null
            ? Pass(item, $"{typeof(T).Name} is registered.", "Registered", "Registered")
            : Fail(item, $"{typeof(T).Name} is not registered.", "Registered", "Missing");

    private EngineeringDiagnosticCheckResult DiscoveryFresh(LevelXCatalogueEntry item)
    {
        if (!discovery.LastSuccessfulRefreshUtc.HasValue)
            return Fail(item, discovery.LastError ?? "Discovery has never completed successfully.", "Successful current discovery", "Never completed");
        return discovery.IsStale
            ? Warn(item, discovery.LastError ?? "Discovery is stale.", "Current discovery", $"Last success {discovery.LastSuccessfulRefreshUtc:O}")
            : Pass(item, "Configuration discovery is current.", "Current discovery", $"Last success {discovery.LastSuccessfulRefreshUtc:O}");
    }

    private static EngineeringDiagnosticCheckResult StarfleetOrder(LevelXCatalogueEntry item)
    {
        int[] actual = EngineeringDiagnosticLevelSemantics.StarfleetOrder.Select(x => (int)x).ToArray();
        return actual.SequenceEqual([5,4,3,2,1])
            ? Pass(item, "Starfleet level ordering is correct.", "5,4,3,2,1", string.Join(',', actual))
            : Fail(item, "Starfleet level ordering is incorrect.", "5,4,3,2,1", string.Join(',', actual));
    }

    private static EngineeringDiagnosticCheckResult UniqueStrings(LevelXCatalogueEntry item, IEnumerable<string> values)
    {
        string[] all = values.ToArray();
        int unique = all.Distinct(StringComparer.OrdinalIgnoreCase).Count();
        return unique == all.Length
            ? Pass(item, "Identifiers are unique.", $"{all.Length} unique", $"{unique} unique")
            : Fail(item, "Duplicate identifiers detected.", $"{all.Length} unique", $"{unique} unique");
    }

    private EngineeringDiagnosticCheckResult EndpointResolves(LevelXCatalogueEntry item, AegisControlPlaneService service, bool requireHttps)
    {
        try
        {
            string value = requireHttps
                ? AegisControlPlaneEndpoints.ResolvePublic(configuration, service, logger)
                : AegisControlPlaneEndpoints.ResolveInternal(configuration, service, logger);
            bool valid = Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && (!requireHttps || uri.Scheme == Uri.UriSchemeHttps);
            return valid ? Pass(item, $"{service} endpoint resolves.", requireHttps ? "Absolute HTTPS URI" : "Absolute URI", value) : Fail(item, $"{service} endpoint is invalid.", requireHttps ? "Absolute HTTPS URI" : "Absolute URI", value);
        }
        catch (Exception ex) { return Fail(item, $"{service} endpoint resolution failed.", "Resolvable endpoint", ex.GetType().Name); }
    }

    private EngineeringDiagnosticCheckResult RegistrationIdentityCompleteness(LevelXCatalogueEntry item)
    {
        int invalid = discovery.Targets.Count(x => string.IsNullOrWhiteSpace(x.ApplicationId) || string.IsNullOrWhiteSpace(x.InstanceId));
        return invalid == 0 ? Pass(item, "All discovered registration identities are complete.", "0 incomplete", "0") : Fail(item, "Incomplete registration identities were discovered.", "0 incomplete", invalid.ToString());
    }

    private async Task<EngineeringDiagnosticCheckResult> ReferenceRegistrationExplainableAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        DiagnosticTargetOptions? target = discovery.Targets.FirstOrDefault(x => x.ApplicationId.Equals("Aegis.Hello", StringComparison.OrdinalIgnoreCase)) ?? discovery.Targets.FirstOrDefault();
        if (target is null) return Warn(item, "No registered application is available for state explanation.", "At least one target", "None");
        try
        {
            LevelXStateExplanation? explanation = await stateExplain.ExplainAsync(target.ApplicationId, target.InstanceId, ct);
            return explanation is null ? Fail(item, "Reference registration could not be found in authoritative inventory.", "Explainable registration", "Not found") : Pass(item, "Reference registration is explainable.", "Authoritative explanation", $"{explanation.RegistrationState}; {explanation.EffectiveState}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { return Fail(item, "Reference registration explanation failed.", "Authoritative explanation", ex.GetType().Name); }
    }

    private EngineeringDiagnosticCheckResult RegistrationIdentityUniqueness(LevelXCatalogueEntry item)
    {
        string[] ids = discovery.Targets.Select(x => $"{x.ApplicationId}\u001f{x.InstanceId}").ToArray();
        return ids.Distinct(StringComparer.OrdinalIgnoreCase).Count() == ids.Length ? Pass(item, "Registration identities are unique.", $"{ids.Length} unique", $"{ids.Length} unique") : Fail(item, "Duplicate ApplicationId/InstanceId identities were discovered.", $"{ids.Length} unique", $"{ids.Distinct(StringComparer.OrdinalIgnoreCase).Count()} unique");
    }

    private EngineeringDiagnosticCheckResult PublicEndpointPolicy(LevelXCatalogueEntry item)
    {
        string[] values =
        [
            AegisControlPlaneEndpoints.ResolvePublic(configuration, AegisControlPlaneService.Configuration, logger),
            AegisControlPlaneEndpoints.ResolvePublic(configuration, AegisControlPlaneService.Operations, logger)
        ];
        string[] invalid = values.Where(x => !Uri.TryCreate(x, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps).ToArray();
        return invalid.Length == 0 ? Pass(item, "Public Control Plane endpoints use HTTPS.", "All HTTPS", string.Join(", ", values)) : Fail(item, "One or more public Control Plane endpoints are not HTTPS.", "All HTTPS", string.Join(", ", invalid));
    }

    private EngineeringDiagnosticCheckResult PublishedUrlsValid(LevelXCatalogueEntry item)
    {
        string[] invalid = discovery.Targets.Where(x => !string.IsNullOrWhiteSpace(x.BaseUrl) && !Uri.TryCreate(x.BaseUrl, UriKind.Absolute, out _)).Select(x => x.ApplicationId).ToArray();
        return invalid.Length == 0 ? Pass(item, "Published diagnostic base URLs are valid.", "0 invalid", "0 invalid") : Fail(item, "Invalid published diagnostic base URLs detected.", "0 invalid", string.Join(", ", invalid));
    }

    private async Task<EngineeringDiagnosticCheckResult> RegistrationConsistencyAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var failures = new List<string>();
        var warnings = new List<string>();
        foreach (DiagnosticTargetOptions target in discovery.Targets.Take(25))
        {
            try
            {
                LevelXStateExplanation? x = await stateExplain.ExplainAsync(target.ApplicationId, target.InstanceId, ct);
                if (x is null) { failures.Add($"{target.ApplicationId}/{target.InstanceId}: missing"); continue; }
                if (x.Codes.Contains(LevelXDiagnosticCodes.StateDerivationMismatch, StringComparer.OrdinalIgnoreCase)) failures.Add($"{target.ApplicationId}/{target.InstanceId}: state mismatch");
                else if (!x.AuthorityAvailable || !x.RegistrationFresh) warnings.Add($"{target.ApplicationId}/{target.InstanceId}: authority/freshness warning");
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { failures.Add($"{target.ApplicationId}/{target.InstanceId}: {ex.GetType().Name}"); }
        }
        if (failures.Count > 0) return Fail(item, "Registration consistency failures were detected.", "0 failures", string.Join("; ", failures));
        if (warnings.Count > 0) return Warn(item, "Registration consistency completed with warnings.", "0 warnings", string.Join("; ", warnings));
        return Pass(item, "Registration state is consistent across checked applications.", "0 failures/warnings", "0");
    }

    private static EngineeringDiagnosticCheckResult CapabilityNames(LevelXCatalogueEntry item)
    {
        string[] invalid = OperationalPermissions.All.Where(p => !p.Contains('.') || p.Contains("Manager", StringComparison.OrdinalIgnoreCase) || p.Contains("Administrator", StringComparison.OrdinalIgnoreCase)).ToArray();
        return invalid.Length == 0 ? Pass(item, "Operational permissions follow capability naming policy.", "0 invalid", "0") : Fail(item, "Invalid operational permission names detected.", "0 invalid", string.Join(", ", invalid));
    }

    private static EngineeringDiagnosticCheckResult RequiredPermissions(LevelXCatalogueEntry item)
    {
        bool ok = OperationalPermissions.All.Contains(OperationalPermissions.DiagnosticsView) && OperationalPermissions.All.Contains(OperationalPermissions.DiagnosticsRun);
        return ok ? Pass(item, "Required Diagnostics permissions are present.", "Diagnostics.View and Diagnostics.Run", "Present") : Fail(item, "Required Diagnostics permissions are missing.", "Diagnostics.View and Diagnostics.Run", "Missing");
    }

    private static async Task<EngineeringDiagnosticCheckResult> PermissionDenialAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore();
        var authorizer = new PermissionAuthorizer(store);
        AuthorizationDecision decision = await authorizer.AuthorizeAsync(new AuthorizationSubject("levelx-probe", []), OperationalPermissions.AlertsResolve, ct);
        return !decision.Allowed ? Pass(item, "Ungrant permission is denied.", "Denied", "Denied") : Fail(item, "Ungrant permission was unexpectedly allowed.", "Denied", "Allowed");
    }

    private async Task<EngineeringDiagnosticCheckResult> SecretsConfiguredAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        ICommonSecretsHealthCheck? health = services.GetService<ICommonSecretsHealthCheck>();
        if (health is null) return Fail(item, "Secrets health service is unavailable.", "Registered", "Missing");
        CommonSecretsHealth result = await health.CheckAsync(ct);
        return result.IsConfigured ? Pass(item, "A secret provider is configured.", "Configured", result.ProviderName) : Fail(item, "No secret provider is configured.", "Configured", "Not configured");
    }

    private async Task<EngineeringDiagnosticCheckResult> SecretsReachableAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        ICommonSecretsHealthCheck? health = services.GetService<ICommonSecretsHealthCheck>();
        if (health is null) return Fail(item, "Secrets health service is unavailable.", "Reachable provider", "Health service missing");
        CommonSecretsHealth result = await health.CheckAsync(ct);
        return result.IsAvailable ? Pass(item, "Secret provider is reachable.", "Reachable", result.ProviderName) : Fail(item, result.Message, "Reachable", "Unavailable");
    }

    private EngineeringDiagnosticCheckResult SecretsPolicy(LevelXCatalogueEntry item)
    {
        try
        {
            CommonSecretsOptions options = configuration.GetSection("CommonSecrets").Get<CommonSecretsOptions>() ?? new();
            IReadOnlyDictionary<string, SecretProviderDefinition> providers = SecretProviderConfiguration.ReadProviders(configuration);
            CommonSecretsPolicy.Validate(options, providers);
            return Pass(item, "Current CommonSecrets policy is valid.", "Valid policy", "Valid");
        }
        catch (Exception ex) { return Fail(item, "Current CommonSecrets policy is invalid.", "Valid policy", ex.Message); }
    }

    private EngineeringDiagnosticCheckResult SecretsProviderOrder(LevelXCatalogueEntry item)
    {
        try
        {
            CommonSecretsOptions options = configuration.GetSection("CommonSecrets").Get<CommonSecretsOptions>() ?? new();
            IReadOnlyDictionary<string, SecretProviderDefinition> providers = SecretProviderConfiguration.ReadProviders(configuration);
            string[] order = CommonSecretsPolicy.ResolveProviderOrder(options, providers);
            bool unique = order.Distinct(StringComparer.OrdinalIgnoreCase).Count() == order.Length;
            return order.Length > 0 && unique ? Pass(item, "Provider order resolves and is unique.", "> 0 unique providers", string.Join(" -> ", order)) : Fail(item, "Provider order is empty or contains duplicates.", "> 0 unique providers", string.Join(" -> ", order));
        }
        catch (Exception ex) { return Fail(item, "Provider order could not be resolved.", "Resolvable provider order", ex.Message); }
    }

    private async Task<EngineeringDiagnosticCheckResult> EnabledSecretProvidersHealthyAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        SecretProviderHealth[] results = await Task.WhenAll(services.GetServices<ISecretProviderHealth>().Select(x => x.CheckHealthAsync(ct)));
        SecretProviderHealth[] enabled = results.Where(x => x.IsEnabled).ToArray();
        SecretProviderHealth[] unavailable = enabled.Where(x => !x.IsAvailable).ToArray();
        if (enabled.Length == 0) return Warn(item, "No enabled secret providers were reported.", "> 0 enabled", "0");
        return unavailable.Length == 0 ? Pass(item, "All enabled secret providers are healthy.", "0 unavailable", "0") : Fail(item, "One or more enabled secret providers are unavailable.", "0 unavailable", string.Join(", ", unavailable.Select(x => x.ProviderName)));
    }

    private async Task<EngineeringDiagnosticCheckResult> SecretsV2HealthAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        ISecretProvider? provider = services.GetService<ISecretProvider>();
        ICommonSecretsHealthCheck? health = services.GetService<ICommonSecretsHealthCheck>();
        if (provider is null || health is null) return Fail(item, "Secrets V2 prerequisites are unavailable.", "Provider + health service", "Missing");
        CommonSecretsHealthV2 result = await CommonSecretsHealthEvaluator.EvaluateAsync(provider, health, [], ct);
        return result.IsReady ? Pass(item, "Secrets V2 health is ready.", "Ready", $"{result.ProviderName}; {result.AuthenticationState}") : Warn(item, result.Message, "Ready", $"{result.ProviderName}; {result.AuthenticationState}");
    }

    private async Task<ExternalDeliveryQueueHealth?> QueueHealthAsync(CancellationToken ct) =>
        services.GetService<IExternalDeliveryQueueHealth>() is { } health ? await health.CheckHealthAsync(ct) : null;

    private async Task<EngineeringDiagnosticCheckResult> MessagingQueueAvailableAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        ExternalDeliveryQueueHealth? h = await QueueHealthAsync(ct);
        if (h is null) return Fail(item, "Messaging queue health service is unavailable.", "Health service registered", "Missing");
        return h.IsAvailable ? Pass(item, "Messaging queue is available.", "Available", h.QueueName ?? "default") : Fail(item, h.Message, "Available", "Unavailable");
    }

    private async Task<EngineeringDiagnosticCheckResult> MessagingThresholdAsync(LevelXCatalogueEntry item, CancellationToken ct, string kind)
    {
        ExternalDeliveryQueueHealth? h = await QueueHealthAsync(ct);
        ExternalDeliveryOptions? o = services.GetService<ExternalDeliveryOptions>();
        if (h is null || o is null) return Fail(item, "Messaging health/options are unavailable.", "Health + options", "Missing");
        return kind switch
        {
            "pending" => h.Pending < o.PendingCriticalThreshold ? Pass(item, "Pending backlog is below critical threshold.", $"< {o.PendingCriticalThreshold}", h.Pending.ToString()) : Fail(item, "Pending backlog is critical.", $"< {o.PendingCriticalThreshold}", h.Pending.ToString()),
            "dead" => h.DeadLettered < o.DeadLetterCriticalThreshold ? Pass(item, "Dead-letter backlog is below critical threshold.", $"< {o.DeadLetterCriticalThreshold}", h.DeadLettered.ToString()) : Fail(item, "Dead-letter backlog is critical.", $"< {o.DeadLetterCriticalThreshold}", h.DeadLettered.ToString()),
            "expired" => h.ExpiredLeases < o.ExpiredLeaseCriticalThreshold ? Pass(item, "Expired leases are below critical threshold.", $"< {o.ExpiredLeaseCriticalThreshold}", h.ExpiredLeases.ToString()) : Fail(item, "Expired leases are critical.", $"< {o.ExpiredLeaseCriticalThreshold}", h.ExpiredLeases.ToString()),
            "age" => !h.OldestPendingAge.HasValue || h.OldestPendingAge < o.OldestPendingCriticalAge ? Pass(item, "Oldest pending age is below critical threshold.", $"< {o.OldestPendingCriticalAge}", h.OldestPendingAge?.ToString() ?? "none") : Fail(item, "Oldest pending item is critically stale.", $"< {o.OldestPendingCriticalAge}", h.OldestPendingAge.ToString()!),
            _ => Fail(item, "Unknown messaging threshold check.", "Known threshold", kind)
        };
    }

    private EngineeringDiagnosticCheckResult MessagingThresholdOrdering(LevelXCatalogueEntry item)
    {
        ExternalDeliveryOptions? o = services.GetService<ExternalDeliveryOptions>();
        if (o is null) return Fail(item, "Messaging options are unavailable.", "Options registered", "Missing");
        bool ok = o.PendingWarningThreshold <= o.PendingCriticalThreshold && o.DeadLetterWarningThreshold <= o.DeadLetterCriticalThreshold && o.OldestPendingWarningAge <= o.OldestPendingCriticalAge;
        return ok ? Pass(item, "Messaging warning/critical thresholds are ordered correctly.", "warning <= critical", "Valid") : Fail(item, "Messaging threshold ordering is invalid.", "warning <= critical", "Invalid");
    }

    private async Task<EngineeringDiagnosticCheckResult> MessagingMetricInvariantsAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        ExternalDeliveryQueueHealth? h = await QueueHealthAsync(ct);
        if (h is null) return Fail(item, "Messaging queue health is unavailable.", "Metrics available", "Missing");
        bool ok = h.Pending >= 0 && h.DeadLettered >= 0 && h.Ready >= 0 && h.Leased >= 0 && h.Retrying >= 0 && h.ExpiredLeases >= 0 && (!h.OldestPendingAge.HasValue || h.OldestPendingAge.Value >= TimeSpan.Zero);
        return ok ? Pass(item, "Queue metric invariants are valid.", "All counts/ages >= 0", "Valid") : Fail(item, "Negative queue metric detected.", "All counts/ages >= 0", h.ToString());
    }

    private async Task<EngineeringDiagnosticCheckResult> StorageHealthProbeAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-levelx-storage-" + Guid.NewGuid().ToString("N"));
        try
        {
            var storage = new LocalFileStorage(root);
            StorageHealth health = await storage.CheckHealthAsync(ct);
            return health.Available && health.Writable ? Pass(item, "Ephemeral storage health probe passed and will be cleaned up.", "Available + writable", $"{health.Available}/{health.Writable}") : Fail(item, "Ephemeral storage health probe failed.", "Available + writable", $"{health.Available}/{health.Writable}");
        }
        finally { TryDeleteDirectory(root); }
    }

    private async Task<EngineeringDiagnosticCheckResult> StorageRoundTripAsync(LevelXCatalogueEntry item, CancellationToken ct, bool verifyMetadata)
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-levelx-storage-" + Guid.NewGuid().ToString("N"));
        try
        {
            var storage = new LocalFileStorage(root);
            byte[] bytes = Encoding.UTF8.GetBytes("levelx-ephemeral-probe");
            await using var input = new MemoryStream(bytes);
            StoredFile stored = await storage.StoreAsync(new StorageWriteRequest("probe/test.txt", input, "text/plain", "test.txt", "LevelX"), ct);
            await using Stream output = await storage.OpenReadAsync("probe/test.txt", ct);
            using var reader = new StreamReader(output, Encoding.UTF8);
            string text = await reader.ReadToEndAsync(ct);
            if (text != "levelx-ephemeral-probe") return Fail(item, "Ephemeral storage round trip returned different content.", "Exact content match", text);
            if (verifyMetadata)
            {
                StoredFile? metadata = await storage.GetMetadataAsync("probe/test.txt", ct);
                if (metadata is null || metadata.Length != bytes.Length || string.IsNullOrWhiteSpace(metadata.Sha256)) return Fail(item, "Ephemeral storage metadata validation failed.", "Length + SHA256 present", metadata?.ToString() ?? "Missing");
            }
            await storage.DeleteAsync("probe/test.txt", ct);
            return Pass(item, verifyMetadata ? "Ephemeral metadata integrity passed; sandbox cleaned up." : "Ephemeral store/read/delete round trip passed; sandbox cleaned up.", "Successful isolated round trip", "Passed");
        }
        finally { TryDeleteDirectory(root); }
    }

    private async Task<EngineeringDiagnosticCheckResult> StorageTraversalAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-levelx-storage-" + Guid.NewGuid().ToString("N"));
        try
        {
            var storage = new LocalFileStorage(root);
            try
            {
                await storage.GetMetadataAsync("../escape.txt", ct);
                return Fail(item, "Unsafe storage key was not rejected.", "StorageException", "Accepted");
            }
            catch (StorageException) { return Pass(item, "Unsafe storage key is rejected.", "StorageException", "Rejected"); }
        }
        finally { TryDeleteDirectory(root); }
    }

    private static void TryDeleteDirectory(string root)
    {
        try { if (Directory.Exists(root)) Directory.Delete(root, true); } catch { }
    }

    private static EngineeringDiagnosticCheckResult Pass(LevelXCatalogueEntry item, string summary, string expected, string actual, string? evidence = null) =>
        new(item.TestId, $"{item.TestId} — {item.Name}", EngineeringDiagnosticStatus.Passed, summary, evidence, expected, actual);
    private static EngineeringDiagnosticCheckResult Warn(LevelXCatalogueEntry item, string summary, string expected, string actual, string? evidence = null) =>
        new(item.TestId, $"{item.TestId} — {item.Name}", EngineeringDiagnosticStatus.Warning, summary, evidence, expected, actual);
    private static EngineeringDiagnosticCheckResult Fail(LevelXCatalogueEntry item, string summary, string expected, string actual, string? evidence = null) =>
        new(item.TestId, $"{item.TestId} — {item.Name}", EngineeringDiagnosticStatus.Failed, summary, evidence, expected, actual);

    private sealed class ProbeAuthorizationStore : IAuthorizationStore
    {
        public Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(IReadOnlyCollection<string> roleKeys, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyCollection<RoleDefinition>>([new RoleDefinition("operator", "Operator", [OperationalPermissions.DiagnosticsView])]);
        public Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(string subjectId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyCollection<string>>(["operator"]);
        public Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(IReadOnlyCollection<string> groupNames, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyCollection<string>>([]);
    }
}
