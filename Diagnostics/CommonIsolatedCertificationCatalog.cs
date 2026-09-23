namespace Aegis.Diagnostics;

using Common.Diagnostics;
using Common.Messaging;
using Common.Registration;
using Common.Secrets;
using Common.Security.Abstractions;
using Common.Security.Authorization;
using Common.Security.Constants;
using Common.Storage;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Http.Json;
using System.Text;

public sealed class CommonIsolatedCertificationCatalog
{
    private readonly IReadOnlyList<LevelXCatalogueEntry> catalogue =
    [
        new("DIA-009", CommonDiagnosticTargets.Diagnostics, "Isolated run-store round trip", EngineeringDiagnosticLevel.Level3Verification, false, "Persist and retrieve a synthetic diagnostic run in a temporary isolated store."),
        new("DIA-010", CommonDiagnosticTargets.Diagnostics, "Cumulative engine execution", EngineeringDiagnosticLevel.Level3Verification, false, "Verify Level 3 executes Level 5, 4 and 3 check definitions."),
        new("DIA-011", CommonDiagnosticTargets.Diagnostics, "Check failure containment", EngineeringDiagnosticLevel.Level2Repair, false, "Verify an isolated throwing check is captured as a failed result rather than crashing the run."),
        new("DIA-012", CommonDiagnosticTargets.Diagnostics, "Warning aggregation", EngineeringDiagnosticLevel.Level2Repair, false, "Verify an isolated warning produces Warning aggregate status."),
        new("DIA-013", CommonDiagnosticTargets.Diagnostics, "Target model certification", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify all supported target types can be constructed with stable identities."),
        new("DIA-014", CommonDiagnosticTargets.Diagnostics, "Result precedence certification", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify aggregate result precedence across Passed, Warning, InterventionRequired and Failed."),

        new("REG-010", CommonDiagnosticTargets.Registration, "Isolated first introduction to Pending", EngineeringDiagnosticLevel.Level3Verification, false, "Run a zero-trust first registration against an in-memory authority and temporary identity file."),
        new("REG-011", CommonDiagnosticTargets.Registration, "Isolated approved claim to Registered", EngineeringDiagnosticLevel.Level3Verification, false, "Claim an approved temporary registration credential in isolation."),
        new("REG-012", CommonDiagnosticTargets.Registration, "Isolated invalid-credential recovery", EngineeringDiagnosticLevel.Level2Repair, false, "Verify an invalid durable credential enters RecoveryPending instead of creating a duplicate registration."),
        new("REG-013", CommonDiagnosticTargets.Registration, "Isolated revocation enforcement", EngineeringDiagnosticLevel.Level2Repair, false, "Verify HTTP 410 revocation remains Revoked and does not silently re-register."),
        new("REG-014", CommonDiagnosticTargets.Registration, "Isolated purge and clean re-introduction", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify a purged authority record preserves InstallationId but creates a fresh pending RegistrationId."),
        new("REG-015", CommonDiagnosticTargets.Registration, "Isolated IdentityConflict enforcement", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify an authority conflict is surfaced as IdentityConflict without self-healing."),

        new("SEC-009", CommonDiagnosticTargets.Security, "Granted capability authorization", EngineeringDiagnosticLevel.Level3Verification, false, "Verify an explicitly granted capability is allowed."),
        new("SEC-010", CommonDiagnosticTargets.Security, "Group role authorization", EngineeringDiagnosticLevel.Level3Verification, false, "Verify a mapped group role grants its capability."),
        new("SEC-011", CommonDiagnosticTargets.Security, "Wildcard capability authorization", EngineeringDiagnosticLevel.Level2Repair, false, "Verify wildcard permission grants a requested capability in an isolated store."),
        new("SEC-012", CommonDiagnosticTargets.Security, "No-role denial", EngineeringDiagnosticLevel.Level2Repair, false, "Verify a subject with no roles is denied."),
        new("SEC-013", CommonDiagnosticTargets.Security, "Operational permission matrix", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify every shared operational permission can be resolved through an isolated granting role."),
        new("SEC-014", CommonDiagnosticTargets.Security, "Case-insensitive permission matching", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify permission comparison remains case-insensitive."),

        new("SCR-009", CommonDiagnosticTargets.Secrets, "Single-provider order inference", EngineeringDiagnosticLevel.Level3Verification, false, "Verify a single provider can safely infer provider order."),
        new("SCR-010", CommonDiagnosticTargets.Secrets, "Multiple-provider order enforcement", EngineeringDiagnosticLevel.Level3Verification, false, "Verify multiple providers require explicit ordering."),
        new("SCR-011", CommonDiagnosticTargets.Secrets, "Production provider policy rejection", EngineeringDiagnosticLevel.Level2Repair, false, "Verify Production rejects a non-production provider type in isolated configuration."),
        new("SCR-012", CommonDiagnosticTargets.Secrets, "Production HTTPS enforcement", EngineeringDiagnosticLevel.Level2Repair, false, "Verify Production rejects insecure OpenBao transport in isolated configuration."),
        new("SCR-013", CommonDiagnosticTargets.Secrets, "Offline-development locality enforcement", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify OfflineDevelopment rejects a remote OpenBao endpoint."),
        new("SCR-014", CommonDiagnosticTargets.Secrets, "Chained provider fallback", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify provider fallback selects the first non-empty value without exposing it."),

        new("MSG-011", CommonDiagnosticTargets.Messaging, "In-memory queue enqueue/health", EngineeringDiagnosticLevel.Level3Verification, false, "Exercise an isolated in-memory queue and validate pending metrics."),
        new("MSG-012", CommonDiagnosticTargets.Messaging, "In-memory idempotency", EngineeringDiagnosticLevel.Level3Verification, false, "Verify isolated delivery idempotency records delivered state."),
        new("MSG-013", CommonDiagnosticTargets.Messaging, "Isolated retry attempt increment", EngineeringDiagnosticLevel.Level2Repair, false, "Verify retry increments Attempt in an isolated in-memory queue."),
        new("MSG-014", CommonDiagnosticTargets.Messaging, "Isolated dead-letter accounting", EngineeringDiagnosticLevel.Level2Repair, false, "Verify dead-letter handling removes an item from active pending count."),
        new("MSG-015", CommonDiagnosticTargets.Messaging, "Ephemeral durable queue round trip", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Exercise the file-backed durable queue entirely inside a temporary directory."),
        new("MSG-016", CommonDiagnosticTargets.Messaging, "Ephemeral dead-letter persistence", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify dead-letter evidence persists in an isolated temporary durable queue."),

        new("STO-007", CommonDiagnosticTargets.Storage, "Ephemeral version increment", EngineeringDiagnosticLevel.Level3Verification, false, "Write two isolated versions of the same key and verify version increments."),
        new("STO-008", CommonDiagnosticTargets.Storage, "Ephemeral delete semantics", EngineeringDiagnosticLevel.Level3Verification, false, "Store then delete a temporary object and verify current metadata reflects deletion/missing state."),
        new("STO-009", CommonDiagnosticTargets.Storage, "Ephemeral corruption detection", EngineeringDiagnosticLevel.Level2Repair, false, "Tamper only with an isolated temporary object and verify integrity detection."),
        new("STO-010", CommonDiagnosticTargets.Storage, "Ephemeral concurrent serialization", EngineeringDiagnosticLevel.Level2Repair, false, "Perform isolated concurrent writes to one key and verify valid serialized versions."),
        new("STO-011", CommonDiagnosticTargets.Storage, "Ephemeral version history certification", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Verify complete isolated version history remains readable and ordered."),
        new("STO-012", CommonDiagnosticTargets.Storage, "Ephemeral multi-object certification", EngineeringDiagnosticLevel.Level1CriticalIntervention, false, "Store, read, verify and delete multiple isolated objects with guaranteed cleanup.")
    ];

    public IReadOnlyList<LevelXCatalogueEntry> Catalogue => catalogue;

    public IReadOnlyList<EngineeringDiagnosticCheckDefinition> Build(DiagnosticTarget target)
    {
        IEnumerable<LevelXCatalogueEntry> selected = target.Type switch
        {
            DiagnosticTargetType.ControlPlane => catalogue,
            DiagnosticTargetType.CommonComponent => catalogue.Where(x => x.Component.Equals(target.TargetId, StringComparison.OrdinalIgnoreCase)),
            _ => []
        };
        return selected.Select(x => new EngineeringDiagnosticCheckDefinition(
            x.TestId,
            $"{x.TestId} — {x.Name}",
            x.IntroducedAtLevel,
            ct => RunAsync(x, ct))).ToArray();
    }

    private async Task<EngineeringDiagnosticCheckResult> RunAsync(LevelXCatalogueEntry item, CancellationToken ct) =>
        item.TestId switch
        {
            "DIA-009" => await DiagnosticsRunStoreAsync(item, ct),
            "DIA-010" => await DiagnosticsCumulativeEngineAsync(item, ct),
            "DIA-011" => await DiagnosticsFailureContainmentAsync(item, ct),
            "DIA-012" => await DiagnosticsWarningAggregationAsync(item, ct),
            "DIA-013" => DiagnosticsTargetModel(item),
            "DIA-014" => DiagnosticsStatusPrecedence(item),

            "REG-010" => await RegistrationFirstPendingAsync(item, ct),
            "REG-011" => await RegistrationClaimAsync(item, ct),
            "REG-012" => await RegistrationRecoveryAsync(item, ct),
            "REG-013" => await RegistrationRevokedAsync(item, ct),
            "REG-014" => await RegistrationPurgeAsync(item, ct),
            "REG-015" => await RegistrationConflictAsync(item, ct),

            "SEC-009" => await SecurityGrantedAsync(item, ct),
            "SEC-010" => await SecurityGroupAsync(item, ct),
            "SEC-011" => await SecurityWildcardAsync(item, ct),
            "SEC-012" => await SecurityNoRoleAsync(item, ct),
            "SEC-013" => await SecurityPermissionMatrixAsync(item, ct),
            "SEC-014" => await SecurityCaseInsensitiveAsync(item, ct),

            "SCR-009" => SecretsSingleOrder(item),
            "SCR-010" => SecretsMultipleOrder(item),
            "SCR-011" => SecretsProductionProviderPolicy(item),
            "SCR-012" => SecretsProductionHttps(item),
            "SCR-013" => SecretsOfflineLocality(item),
            "SCR-014" => await SecretsFallbackAsync(item, ct),

            "MSG-011" => await MessagingQueueAsync(item, ct),
            "MSG-012" => await MessagingIdempotencyAsync(item, ct),
            "MSG-013" => await MessagingRetryAsync(item, ct),
            "MSG-014" => await MessagingDeadLetterAccountingAsync(item, ct),
            "MSG-015" => await MessagingDurableRoundTripAsync(item, ct),
            "MSG-016" => await MessagingDeadLetterPersistenceAsync(item, ct),

            "STO-007" => await StorageVersionIncrementAsync(item, ct),
            "STO-008" => await StorageDeleteAsync(item, ct),
            "STO-009" => await StorageCorruptionAsync(item, ct),
            "STO-010" => await StorageConcurrentAsync(item, ct),
            "STO-011" => await StorageHistoryAsync(item, ct),
            "STO-012" => await StorageMultiObjectAsync(item, ct),
            _ => Fail(item, "Unknown isolated certification test.", "Known test", item.TestId)
        };

    private static async Task<EngineeringDiagnosticCheckResult> DiagnosticsRunStoreAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("diag-store");
        try
        {
            var store = new JsonEngineeringDiagnosticRunStore(Path.Combine(root, "runs.json"));
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var run = new EngineeringDiagnosticRun(Guid.NewGuid(), EngineeringDiagnosticLevel.Level3Verification, "Probe", "Test", "LevelX", null, now, now, EngineeringDiagnosticStatus.Passed, []);
            await store.SaveAsync(run, ct);
            EngineeringDiagnosticRun? loaded = await store.GetAsync(run.RunId, ct);
            return loaded?.RunId == run.RunId ? Pass(item, "Isolated run-store round trip succeeded.", "Same RunId", run.RunId.ToString()) : Fail(item, "Isolated run-store round trip failed.", run.RunId.ToString(), loaded?.RunId.ToString() ?? "Missing");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> DiagnosticsCumulativeEngineAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("diag-engine");
        try
        {
            var store = new JsonEngineeringDiagnosticRunStore(Path.Combine(root, "runs.json"));
            var engine = new EngineeringDiagnosticEngine(store);
            EngineeringDiagnosticCheckDefinition[] defs =
            [
                PassedDefinition("probe-l5", EngineeringDiagnosticLevel.Level5Scan),
                PassedDefinition("probe-l4", EngineeringDiagnosticLevel.Level4Analysis),
                PassedDefinition("probe-l3", EngineeringDiagnosticLevel.Level3Verification)
            ];
            EngineeringDiagnosticRun run = await engine.RunAsync(EngineeringDiagnosticLevel.Level3Verification, DiagnosticTarget.EntireControlPlane(), "Probe", "Test", "LevelX", null, defs, ct);
            return run.Checks.Count == 3 ? Pass(item, "Level 3 cumulatively executed Level 5, 4 and 3 checks.", "3 checks", run.Checks.Count.ToString()) : Fail(item, "Cumulative engine execution count is incorrect.", "3 checks", run.Checks.Count.ToString());
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> DiagnosticsFailureContainmentAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("diag-fail");
        try
        {
            var engine = new EngineeringDiagnosticEngine(new JsonEngineeringDiagnosticRunStore(Path.Combine(root, "runs.json")));
            EngineeringDiagnosticRun run = await engine.RunAsync(EngineeringDiagnosticLevel.Level2Repair, DiagnosticTarget.EntireControlPlane(), "Probe", "Test", "LevelX", "isolated", [new("probe-failure", "Probe failure", EngineeringDiagnosticLevel.Level2Repair, _ => throw new InvalidOperationException("isolated probe"))], ct);
            return run.Status == EngineeringDiagnosticStatus.Failed && run.Checks.Count == 1 ? Pass(item, "Throwing check was contained as a failed result.", "Failed run with 1 result", $"{run.Status}/{run.Checks.Count}") : Fail(item, "Engine did not contain an isolated check failure.", "Failed/1", $"{run.Status}/{run.Checks.Count}");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> DiagnosticsWarningAggregationAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("diag-warn");
        try
        {
            var engine = new EngineeringDiagnosticEngine(new JsonEngineeringDiagnosticRunStore(Path.Combine(root, "runs.json")));
            EngineeringDiagnosticRun run = await engine.RunAsync(EngineeringDiagnosticLevel.Level2Repair, DiagnosticTarget.EntireControlPlane(), "Probe", "Test", "LevelX", "isolated", [new("probe-warning", "Probe warning", EngineeringDiagnosticLevel.Level5Scan, _ => Task.FromResult(new EngineeringDiagnosticCheckResult("probe-warning", "Probe warning", EngineeringDiagnosticStatus.Warning, "warning")))], ct);
            return run.Status == EngineeringDiagnosticStatus.InterventionRequired || run.Status == EngineeringDiagnosticStatus.Warning
                ? Pass(item, "Warning/intervention aggregation remains non-success.", "Warning or InterventionRequired", run.Status.ToString())
                : Fail(item, "Warning aggregation unexpectedly passed.", "Warning or InterventionRequired", run.Status.ToString());
        }
        finally { Cleanup(root); }
    }

    private static EngineeringDiagnosticCheckResult DiagnosticsTargetModel(LevelXCatalogueEntry item)
    {
        DiagnosticTarget[] targets =
        [
            DiagnosticTarget.EntireControlPlane(),
            DiagnosticTarget.ComponentTarget(ControlPlaneDiagnosticTargets.Operations),
            DiagnosticTarget.CommonComponent(CommonDiagnosticTargets.Diagnostics),
            DiagnosticTarget.RegisteredApplication("Aegis.Hello", "Production")
        ];
        return targets.Select(x => x.Type).Distinct().Count() == 4 ? Pass(item, "All target types construct with distinct identities.", "4 target types", "4") : Fail(item, "Target model certification failed.", "4 target types", targets.Select(x => x.Type).Distinct().Count().ToString());
    }

    private static EngineeringDiagnosticCheckResult DiagnosticsStatusPrecedence(LevelXCatalogueEntry item)
    {
        EngineeringDiagnosticStatus status = EngineeringDiagnosticPolicy.CalculateStatus(
        [
            new("p", "Passed", EngineeringDiagnosticStatus.Passed, ""),
            new("w", "Warning", EngineeringDiagnosticStatus.Warning, ""),
            new("i", "Intervention", EngineeringDiagnosticStatus.InterventionRequired, ""),
            new("f", "Failed", EngineeringDiagnosticStatus.Failed, "")
        ]);
        return status == EngineeringDiagnosticStatus.Failed ? Pass(item, "Failed correctly has highest aggregate precedence.", "Failed", status.ToString()) : Fail(item, "Result precedence is incorrect.", "Failed", status.ToString());
    }

    private static EngineeringDiagnosticCheckDefinition PassedDefinition(string id, EngineeringDiagnosticLevel level) =>
        new(id, id, level, _ => Task.FromResult(new EngineeringDiagnosticCheckResult(id, id, EngineeringDiagnosticStatus.Passed, "passed")));

    private static async Task<EngineeringDiagnosticCheckResult> RegistrationFirstPendingAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("reg-pending"); string path = Path.Combine(root, "identity.json");
        try
        {
            var handler = new ProbeHandler(_ => Json(HttpStatusCode.OK, new { registrationId = "reg-new", claimToken = "claim", state = "Pending" }));
            var client = new RegistrationLifecycleClient(new HttpClient(handler), new(new Uri("http://127.0.0.1/"), "Aegis.Hello", "LevelX", path));
            RegistrationLifecycleStatus status = await client.StepAsync(cancellationToken: ct);
            return status.State == RegistrationLifecycleState.Pending && status.RegistrationId == "reg-new" ? Pass(item, "First introduction reached Pending.", "Pending/reg-new", $"{status.State}/{status.RegistrationId}") : Fail(item, "First introduction did not reach Pending.", "Pending/reg-new", $"{status.State}/{status.RegistrationId}");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> RegistrationClaimAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("reg-claim"); string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument d = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            await store.SaveAsync(d with { RegistrationId = "reg-1", ClaimToken = "claim" }, ct);
            var handler = new ProbeHandler(_ => Json(HttpStatusCode.OK, new { registrationId = "reg-1", credential = "durable", state = "Registered" }));
            var client = new RegistrationLifecycleClient(new HttpClient(handler), new(new Uri("http://127.0.0.1/"), "Aegis.Hello", "LevelX", path), store);
            RegistrationLifecycleStatus status = await client.StepAsync(cancellationToken: ct);
            RegistrationIdentityDocument persisted = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            return status.State == RegistrationLifecycleState.Registered && persisted.ClaimToken is null && persisted.Credential == "durable" ? Pass(item, "Approved claim produced durable Registered identity.", "Registered; claim consumed", "Registered; claim consumed") : Fail(item, "Approved claim certification failed.", "Registered; claim consumed", status.State.ToString());
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> RegistrationRecoveryAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("reg-recovery"); string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument d = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            await store.SaveAsync(d with { RegistrationId = "reg-1", Credential = "old" }, ct);
            int calls = 0;
            var handler = new ProbeHandler(req =>
            {
                calls++;
                return req.RequestUri!.AbsolutePath.EndsWith("/authenticate", StringComparison.Ordinal)
                    ? Json(HttpStatusCode.Unauthorized, new { error = "invalid" })
                    : Json(HttpStatusCode.OK, new { registrationId = "reg-1", claimToken = "recovery", state = "RecoveryPending" });
            });
            var client = new RegistrationLifecycleClient(new HttpClient(handler), new(new Uri("http://127.0.0.1/"), "Aegis.Hello", "LevelX", path), store);
            RegistrationLifecycleStatus status = await client.StepAsync(cancellationToken: ct);
            return status.State == RegistrationLifecycleState.RecoveryPending && calls == 2 ? Pass(item, "Invalid credential entered explicit recovery.", "RecoveryPending; 2 calls", $"{status.State}; {calls} calls") : Fail(item, "Invalid credential recovery certification failed.", "RecoveryPending; 2 calls", $"{status.State}; {calls} calls");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> RegistrationRevokedAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("reg-revoked"); string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument d = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            await store.SaveAsync(d with { RegistrationId = "reg-1", Credential = "revoked" }, ct);
            int calls = 0;
            var handler = new ProbeHandler(_ => { calls++; return Json(HttpStatusCode.Gone, new { registrationId = "reg-1", error = "revoked" }); });
            var client = new RegistrationLifecycleClient(new HttpClient(handler), new(new Uri("http://127.0.0.1/"), "Aegis.Hello", "LevelX", path), store);
            RegistrationLifecycleStatus status = await client.StepAsync(cancellationToken: ct);
            return status.State == RegistrationLifecycleState.Revoked && calls == 1 ? Pass(item, "Revoked credential remained Revoked without re-registration.", "Revoked; 1 call", $"{status.State}; {calls} call") : Fail(item, "Revocation enforcement failed.", "Revoked; 1 call", $"{status.State}; {calls} calls");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> RegistrationPurgeAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("reg-purge"); string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument d = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            string installation = d.InstallationId;
            await store.SaveAsync(d with { RegistrationId = "old-reg", ClaimToken = "old-claim" }, ct);
            int calls = 0;
            var handler = new ProbeHandler(req =>
            {
                calls++;
                return req.RequestUri!.AbsolutePath.Contains("/old-reg/claim", StringComparison.Ordinal)
                    ? Json(HttpStatusCode.NotFound, new { error = "purged" })
                    : Json(HttpStatusCode.OK, new { registrationId = "new-reg", claimToken = "new-claim", state = "Pending" });
            });
            var client = new RegistrationLifecycleClient(new HttpClient(handler), new(new Uri("http://127.0.0.1/"), "Aegis.Hello", "LevelX", path), store);
            RegistrationLifecycleStatus status = await client.StepAsync(cancellationToken: ct);
            RegistrationIdentityDocument persisted = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            bool ok = status.State == RegistrationLifecycleState.Pending && status.RegistrationId == "new-reg" && persisted.InstallationId == installation && calls == 2;
            return ok ? Pass(item, "Purge forced clean re-introduction while preserving InstallationId.", "Pending/new-reg; same InstallationId", "Passed") : Fail(item, "Purge re-introduction certification failed.", "Pending/new-reg; same InstallationId", $"{status.State}/{status.RegistrationId}; calls={calls}");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> RegistrationConflictAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("reg-conflict"); string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument d = await store.LoadOrCreateAsync("Aegis.Hello", "LevelX", ct);
            await store.SaveAsync(d with { RegistrationId = "reg-1", Credential = "durable" }, ct);
            int calls = 0;
            var handler = new ProbeHandler(_ => { calls++; return Json(HttpStatusCode.Conflict, new { registrationId = "reg-1", state = "IdentityConflict", error = "conflict" }); });
            var client = new RegistrationLifecycleClient(new HttpClient(handler), new(new Uri("http://127.0.0.1/"), "Aegis.Hello", "LevelX", path), store);
            RegistrationLifecycleStatus status = await client.StepAsync(cancellationToken: ct);
            return status.State == RegistrationLifecycleState.IdentityConflict && calls == 1 ? Pass(item, "IdentityConflict was surfaced without self-healing.", "IdentityConflict; 1 call", $"{status.State}; {calls} call") : Fail(item, "IdentityConflict enforcement failed.", "IdentityConflict; 1 call", $"{status.State}; {calls} calls");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecurityGrantedAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore([new RoleDefinition("operator", "Operator", [OperationalPermissions.AlertsResolve])], ["operator"], []);
        AuthorizationDecision d = await new PermissionAuthorizer(store).AuthorizeAsync(new AuthorizationSubject("u", []), OperationalPermissions.AlertsResolve, ct);
        return d.Allowed ? Pass(item, "Explicit capability grant is allowed.", "Allowed", "Allowed") : Fail(item, "Explicit capability grant was denied.", "Allowed", "Denied");
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecurityGroupAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore([new RoleDefinition("group-role", "Group", [OperationalPermissions.HistoryView])], [], ["group-role"]);
        AuthorizationDecision d = await new PermissionAuthorizer(store).AuthorizeAsync(new AuthorizationSubject("u", ["IT"]), OperationalPermissions.HistoryView, ct);
        return d.Allowed ? Pass(item, "Group role capability is allowed.", "Allowed", "Allowed") : Fail(item, "Group role capability was denied.", "Allowed", "Denied");
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecurityWildcardAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore([new RoleDefinition("root", "Root", [PermissionAuthorizer.AllPermissions])], ["root"], []);
        AuthorizationDecision d = await new PermissionAuthorizer(store).AuthorizeAsync(new AuthorizationSubject("u", []), OperationalPermissions.DiagnosticsRun, ct);
        return d.Allowed ? Pass(item, "Wildcard capability grants requested permission.", "Allowed", "Allowed") : Fail(item, "Wildcard capability failed.", "Allowed", "Denied");
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecurityNoRoleAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore([], [], []);
        AuthorizationDecision d = await new PermissionAuthorizer(store).AuthorizeAsync(new AuthorizationSubject("u", []), OperationalPermissions.DiagnosticsRun, ct);
        return !d.Allowed ? Pass(item, "Subject with no roles is denied.", "Denied", "Denied") : Fail(item, "Subject with no roles was allowed.", "Denied", "Allowed");
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecurityPermissionMatrixAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore([new RoleDefinition("all-ops", "All", OperationalPermissions.All)], ["all-ops"], []);
        var authorizer = new PermissionAuthorizer(store);
        foreach (string permission in OperationalPermissions.All)
            if (!(await authorizer.CanAsync(new AuthorizationSubject("u", []), permission, ct))) return Fail(item, "Operational permission matrix failed.", "All permissions allowed by all-ops role", permission + " denied");
        return Pass(item, "Operational permission matrix certified.", $"{OperationalPermissions.All.Count} permissions allowed", OperationalPermissions.All.Count.ToString());
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecurityCaseInsensitiveAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new ProbeAuthorizationStore([new RoleDefinition("operator", "Operator", [OperationalPermissions.DiagnosticsRun.ToUpperInvariant()])], ["operator"], []);
        bool allowed = await new PermissionAuthorizer(store).CanAsync(new AuthorizationSubject("u", []), OperationalPermissions.DiagnosticsRun.ToLowerInvariant(), ct);
        return allowed ? Pass(item, "Permission matching is case-insensitive.", "Allowed", "Allowed") : Fail(item, "Permission matching became case-sensitive.", "Allowed", "Denied");
    }

    private static EngineeringDiagnosticCheckResult SecretsSingleOrder(LevelXCatalogueEntry item)
    {
        IConfiguration c = Config(new() { ["CommonSecrets:Mode"]="Development", ["CommonSecrets:Providers:Only:Type"]="Configuration" });
        var o = c.GetSection("CommonSecrets").Get<CommonSecretsOptions>()!;
        string[] order = CommonSecretsPolicy.ResolveProviderOrder(o, SecretProviderConfiguration.ReadProviders(c));
        return order.SequenceEqual(["Only"]) ? Pass(item, "Single-provider order inference works.", "Only", string.Join(",", order)) : Fail(item, "Single-provider order inference failed.", "Only", string.Join(",", order));
    }

    private static EngineeringDiagnosticCheckResult SecretsMultipleOrder(LevelXCatalogueEntry item)
    {
        IConfiguration c = Config(new() { ["CommonSecrets:Mode"]="Development", ["CommonSecrets:Providers:One:Type"]="Configuration", ["CommonSecrets:Providers:Two:Type"]="Environment" });
        try { _ = CommonSecretsPolicy.ResolveProviderOrder(c.GetSection("CommonSecrets").Get<CommonSecretsOptions>()!, SecretProviderConfiguration.ReadProviders(c)); return Fail(item, "Multiple providers were accepted without explicit order.", "InvalidOperationException", "Accepted"); }
        catch (InvalidOperationException) { return Pass(item, "Multiple providers require explicit order.", "InvalidOperationException", "Rejected"); }
    }

    private static EngineeringDiagnosticCheckResult SecretsProductionProviderPolicy(LevelXCatalogueEntry item)
    {
        IConfiguration c = Config(new() { ["CommonSecrets:Mode"]="Production", ["CommonSecrets:ProviderOrder:0"]="Fallback", ["CommonSecrets:Providers:Fallback:Type"]="Configuration" });
        try { CommonSecretsPolicy.Validate(c.GetSection("CommonSecrets").Get<CommonSecretsOptions>()!, SecretProviderConfiguration.ReadProviders(c)); return Fail(item, "Production accepted a non-production provider.", "Rejected", "Accepted"); }
        catch (InvalidOperationException) { return Pass(item, "Production rejects non-production provider types.", "Rejected", "Rejected"); }
    }

    private static EngineeringDiagnosticCheckResult SecretsProductionHttps(LevelXCatalogueEntry item)
    {
        IConfiguration c = Config(new() { ["CommonSecrets:Mode"]="Production", ["CommonSecrets:ProviderOrder:0"]="Primary", ["CommonSecrets:Providers:Primary:Type"]="OpenBao", ["CommonSecrets:Providers:Primary:Settings:Enabled"]="true", ["CommonSecrets:Providers:Primary:Settings:RequireHttps"]="false", ["CommonSecrets:Providers:Primary:Settings:Address"]="http://openbao.example:8200" });
        try { CommonSecretsPolicy.Validate(c.GetSection("CommonSecrets").Get<CommonSecretsOptions>()!, SecretProviderConfiguration.ReadProviders(c)); return Fail(item, "Production accepted insecure OpenBao transport.", "Rejected", "Accepted"); }
        catch (InvalidOperationException) { return Pass(item, "Production enforces HTTPS for OpenBao.", "Rejected insecure transport", "Rejected"); }
    }

    private static EngineeringDiagnosticCheckResult SecretsOfflineLocality(LevelXCatalogueEntry item)
    {
        IConfiguration c = Config(new() { ["CommonSecrets:Mode"]="OfflineDevelopment", ["CommonSecrets:ProviderOrder:0"]="LocalVault", ["CommonSecrets:Providers:LocalVault:Type"]="OpenBao", ["CommonSecrets:Providers:LocalVault:Settings:Enabled"]="true", ["CommonSecrets:Providers:LocalVault:Settings:RequireHttps"]="false", ["CommonSecrets:Providers:LocalVault:Settings:Address"]="https://remote.example:8200" });
        try { CommonSecretsPolicy.Validate(c.GetSection("CommonSecrets").Get<CommonSecretsOptions>()!, SecretProviderConfiguration.ReadProviders(c)); return Fail(item, "OfflineDevelopment accepted a remote provider.", "Rejected", "Accepted"); }
        catch (InvalidOperationException) { return Pass(item, "OfflineDevelopment enforces local provider policy.", "Rejected remote provider", "Rejected"); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> SecretsFallbackAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var chain = new ChainedSecretProvider([new ProbeSecretProvider(null), new ProbeSecretProvider("present")]);
        string? value = await chain.GetAsync("diagnostic/key", ct);
        return value == "present" ? Pass(item, "Chained provider fallback selected the first non-empty provider.", "Fallback succeeds", "Succeeded") : Fail(item, "Chained provider fallback failed.", "Fallback succeeds", "Missing");
    }

    private static async Task<EngineeringDiagnosticCheckResult> MessagingQueueAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var queue = new InMemoryExternalDeliveryQueue();
        ExternalDeliveryWorkItem work = WorkItem();
        await queue.EnqueueAsync(work, ct);
        ExternalDeliveryQueueHealth health = await queue.CheckHealthAsync(ct);
        await queue.CompleteAsync(work.NotificationId, ct);
        return health.Pending == 1 ? Pass(item, "In-memory queue enqueue/health works.", "Pending=1", health.Pending.ToString()) : Fail(item, "In-memory queue pending metric is incorrect.", "1", health.Pending.ToString());
    }

    private static async Task<EngineeringDiagnosticCheckResult> MessagingIdempotencyAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var store = new InMemoryExternalDeliveryIdempotencyStore(); Guid id = Guid.NewGuid();
        bool before = await store.HasDeliveredAsync(id, "u", MessageChannel.Smtp, ct);
        await store.MarkDeliveredAsync(id, "u", MessageChannel.Smtp, ct);
        bool after = await store.HasDeliveredAsync(id, "u", MessageChannel.Smtp, ct);
        return !before && after ? Pass(item, "In-memory idempotency transitions correctly.", "false -> true", $"{before} -> {after}") : Fail(item, "Idempotency transition failed.", "false -> true", $"{before} -> {after}");
    }

    private static async Task<EngineeringDiagnosticCheckResult> MessagingRetryAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var queue = new InMemoryExternalDeliveryQueue(); ExternalDeliveryWorkItem work = WorkItem();
        await queue.RetryAsync(work, TimeSpan.Zero, ct);
        await using IAsyncEnumerator<ExternalDeliveryWorkItem> e = queue.ReadAllAsync(ct).GetAsyncEnumerator(ct);
        bool moved = await e.MoveNextAsync();
        int attempt = moved ? e.Current.Attempt : -1;
        if (moved) await queue.CompleteAsync(e.Current.NotificationId, ct);
        return attempt == 1 ? Pass(item, "Retry increments Attempt.", "1", attempt.ToString()) : Fail(item, "Retry attempt increment failed.", "1", attempt.ToString());
    }

    private static async Task<EngineeringDiagnosticCheckResult> MessagingDeadLetterAccountingAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        var queue = new InMemoryExternalDeliveryQueue(); ExternalDeliveryWorkItem work = WorkItem();
        await queue.EnqueueAsync(work, ct); await queue.DeadLetterAsync(work, "PROBE", ct);
        ExternalDeliveryQueueHealth h = await queue.CheckHealthAsync(ct);
        return h.Pending == 0 ? Pass(item, "Dead-letter removes work from active pending count.", "0", h.Pending.ToString()) : Fail(item, "Dead-letter accounting failed.", "0", h.Pending.ToString());
    }

    private static async Task<EngineeringDiagnosticCheckResult> MessagingDurableRoundTripAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("msg-file");
        try
        {
            var q = new FileExternalDeliveryQueue(new ExternalDeliveryOptions { DurableQueuePath = root }); ExternalDeliveryWorkItem work = WorkItem();
            await q.EnqueueAsync(work, ct); ExternalDeliveryQueueHealth before = await q.CheckHealthAsync(ct);
            await using IAsyncEnumerator<ExternalDeliveryWorkItem> e = q.ReadAllAsync(ct).GetAsyncEnumerator(ct); bool moved = await e.MoveNextAsync();
            if (moved) await q.CompleteAsync(e.Current.NotificationId, ct);
            ExternalDeliveryQueueHealth after = await q.CheckHealthAsync(ct);
            return before.Pending == 1 && moved && after.Pending == 0 ? Pass(item, "Ephemeral durable queue round trip passed.", "1 -> 0", $"{before.Pending} -> {after.Pending}") : Fail(item, "Ephemeral durable queue round trip failed.", "1 -> 0", $"{before.Pending} -> {after.Pending}");
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> MessagingDeadLetterPersistenceAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root = TempRoot("msg-dead");
        try
        {
            var q = new FileExternalDeliveryQueue(new ExternalDeliveryOptions { DurableQueuePath = root }); ExternalDeliveryWorkItem work = WorkItem();
            await q.EnqueueAsync(work, ct);
            await using IAsyncEnumerator<ExternalDeliveryWorkItem> e = q.ReadAllAsync(ct).GetAsyncEnumerator(ct); bool moved = await e.MoveNextAsync();
            if (!moved) return Fail(item, "Unable to lease isolated work item.", "Leased", "Missing");
            await q.DeadLetterAsync(e.Current, "PROBE", ct);
            IReadOnlyList<ExternalDeliveryDeadLetter> dead = await q.GetDeadLettersAsync(ct);
            return dead.Count == 1 && dead[0].ErrorCode == "PROBE" ? Pass(item, "Ephemeral dead-letter persisted correctly.", "1/PROBE", $"{dead.Count}/{dead[0].ErrorCode}") : Fail(item, "Dead-letter persistence failed.", "1/PROBE", dead.Count.ToString());
        }
        finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> StorageVersionIncrementAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root=TempRoot("sto-version"); try { var s=new LocalFileStorage(root); StoredFile a=await StoreText(s,"k.txt","one",ct); StoredFile b=await StoreText(s,"k.txt","two",ct); return b.Version==a.Version+1?Pass(item,"Version increments correctly.",$"{a.Version+1}",b.Version.ToString()):Fail(item,"Version increment failed.",(a.Version+1).ToString(),b.Version.ToString()); } finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> StorageDeleteAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root=TempRoot("sto-delete"); try { var s=new LocalFileStorage(root); await StoreText(s,"k.txt","one",ct); await s.DeleteAsync("k.txt",ct); StoredFile? m=await s.GetMetadataAsync("k.txt",ct); return m is null || m.Status is StorageStatus.Deleted or StorageStatus.Missing?Pass(item,"Delete semantics are valid.","Deleted or missing",m?.Status.ToString()??"Missing"):Fail(item,"Delete semantics failed.","Deleted or missing",m.Status.ToString()); } finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> StorageCorruptionAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root=TempRoot("sto-corrupt"); try { var s=new LocalFileStorage(root); await StoreText(s,"k.txt","original",ct); await File.WriteAllTextAsync(Path.Combine(root,"k.txt"),"tampered",ct); try { await using Stream _=await s.OpenReadAsync("k.txt",ct); return Fail(item,"Corruption was not detected.","StorageException","Read succeeded"); } catch(StorageException){ return Pass(item,"Corruption is detected.","StorageException","Detected"); } } finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> StorageConcurrentAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root=TempRoot("sto-concurrent"); try { var s=new LocalFileStorage(root); await Task.WhenAll(Enumerable.Range(0,4).Select(i=>StoreText(s,"k.txt","v"+i,ct))); IReadOnlyList<StoredFile> versions=await s.GetVersionsAsync("k.txt",ct); return versions.Count==4?Pass(item,"Concurrent writes serialized into valid versions.","4 versions",versions.Count.ToString()):Fail(item,"Concurrent write serialization failed.","4 versions",versions.Count.ToString()); } finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> StorageHistoryAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root=TempRoot("sto-history"); try { var s=new LocalFileStorage(root); await StoreText(s,"k.txt","one",ct); await StoreText(s,"k.txt","two",ct); await StoreText(s,"k.txt","three",ct); IReadOnlyList<StoredFile> versions=await s.GetVersionsAsync("k.txt",ct); bool ok=versions.Count==3&&versions.Select(x=>x.Version).Distinct().Count()==3; return ok?Pass(item,"Version history is complete and distinct.","3 distinct versions",$"{versions.Count} versions"):Fail(item,"Version history certification failed.","3 distinct versions",$"{versions.Count} versions"); } finally { Cleanup(root); }
    }

    private static async Task<EngineeringDiagnosticCheckResult> StorageMultiObjectAsync(LevelXCatalogueEntry item, CancellationToken ct)
    {
        string root=TempRoot("sto-multi"); try { var s=new LocalFileStorage(root); foreach(string k in new[]{"a.txt","b.txt","c.txt"}) await StoreText(s,k,k,ct); int ok=0; foreach(string k in new[]{"a.txt","b.txt","c.txt"}) { await using Stream st=await s.OpenReadAsync(k,ct); using var rd=new StreamReader(st); if(await rd.ReadToEndAsync(ct)==k) ok++; await s.DeleteAsync(k,ct); } return ok==3?Pass(item,"Multi-object isolated certification passed.","3 verified","3"):Fail(item,"Multi-object isolated certification failed.","3 verified",ok.ToString()); } finally { Cleanup(root); }
    }

    private static async Task<StoredFile> StoreText(LocalFileStorage storage,string key,string text,CancellationToken ct)
    {
        await using var ms=new MemoryStream(Encoding.UTF8.GetBytes(text));
        return await storage.StoreAsync(new StorageWriteRequest(key,ms,"text/plain",Path.GetFileName(key),"LevelX"),ct);
    }

    private static ExternalDeliveryWorkItem WorkItem()
    {
        Guid id=Guid.NewGuid();
        return new ExternalDeliveryWorkItem(id,[new RecipientSnapshot("u","User","u@example.test",null,null,MessageChannel.Smtp)],MessageChannel.Smtp,new MessageRequest{RecipientIds=["u"],Title="LevelX",Body="Isolated"},null,null,DateTimeOffset.UtcNow);
    }

    private static IConfiguration Config(Dictionary<string,string?> values)=>new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static string TempRoot(string name)
    {
        string root=Path.Combine(Path.GetTempPath(),"aegis-levelx-"+name+"-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); return root;
    }
    private static void Cleanup(string root){ try{ if(Directory.Exists(root))Directory.Delete(root,true);}catch{} }

    private static HttpResponseMessage Json(HttpStatusCode status, object body)=>new(status){Content=JsonContent.Create(body)};

    private static EngineeringDiagnosticCheckResult Pass(LevelXCatalogueEntry item,string summary,string expected,string actual)=>new(item.TestId,$"{item.TestId} — {item.Name}",EngineeringDiagnosticStatus.Passed,summary,null,expected,actual);
    private static EngineeringDiagnosticCheckResult Fail(LevelXCatalogueEntry item,string summary,string expected,string actual)=>new(item.TestId,$"{item.TestId} — {item.Name}",EngineeringDiagnosticStatus.Failed,summary,null,expected,actual);

    private sealed class ProbeHandler(Func<HttpRequestMessage,HttpResponseMessage> responder):HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>Task.FromResult(responder(request));
    }

    private sealed class ProbeAuthorizationStore(IReadOnlyCollection<RoleDefinition> roles,IReadOnlyCollection<string> direct,IReadOnlyCollection<string> groups):IAuthorizationStore
    {
        public Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(IReadOnlyCollection<string> roleKeys,CancellationToken cancellationToken=default)=>Task.FromResult<IReadOnlyCollection<RoleDefinition>>(roles.Where(x=>roleKeys.Contains(x.Key,StringComparer.OrdinalIgnoreCase)).ToArray());
        public Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(string subjectId,CancellationToken cancellationToken=default)=>Task.FromResult(direct);
        public Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(IReadOnlyCollection<string> groupNames,CancellationToken cancellationToken=default)=>Task.FromResult(groups);
    }

    private sealed class ProbeSecretProvider(string? value):SecretProviderBase
    {
        public override Task<string?> GetAsync(string name,CancellationToken cancellationToken=default)=>Task.FromResult(value);
    }
}
