using System.Reflection;
using System.Text.Json.Nodes;
using Common.Registration;
using Common.Secrets;

namespace Aegis.Diagnostics;

public sealed class ConfigurationContractPublisher(
    IConfiguration configuration,
    IWebHostEnvironment environment,
    ISecretProvider secrets,
    DiagnosticsOptions options,
    ILogger<ConfigurationContractPublisher> logger) : BackgroundService
{
    private const string ApplicationId = "Aegis.Diagnostics";
    private static readonly TimeSpan publishInterval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? baseUrl = First(configuration["Aegis:Operations:Url"], configuration["AegisOperations:BaseUrl"]);
        if (string.IsNullOrWhiteSpace(baseUrl)) { logger.LogInformation("Application registration is disabled because no Operations URL is configured."); return; }
        string path = configuration["AegisConfiguration:ContractPath"] ?? Path.Combine(environment.ContentRootPath, "configuration", "Aegis.Diagnostics.configuration-contract.json");
        while (!stoppingToken.IsCancellationRequested)
        {
            await TryPublishAsync(baseUrl, path, stoppingToken);
            try { await Task.Delay(publishInterval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }

    private async Task<bool> TryPublishAsync(string baseUrl, string path, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(path)) { logger.LogWarning("Diagnostics configuration contract not found at {ContractPath}; Diagnostics remains operational.", path); return false; }

            JsonObject contract = JsonNode.Parse(await File.ReadAllTextAsync(path, cancellationToken))!.AsObject();
            contract["version"] = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";
            contract["siteId"] = NullIfBlank(configuration["Site:Id"] ?? configuration["Diagnostics:SiteId"]);
            contract["instanceId"] = NullIfBlank(configuration["Service:Identity"] ?? configuration["Diagnostics:InstanceId"] ?? Environment.MachineName);
            contract["runtimeEnvironment"] = DetectedRuntimeEnvironment.Capture(environment.EnvironmentName, environment.ContentRootPath);

            if (contract["diagnostics"] is JsonObject diagnostics)
                diagnostics["secretName"] = options.MachineCredentialSecretName;

            if (contract["requirements"] is JsonArray requirements)
            {
                for (int i = requirements.Count - 1; i >= 0; i--)
                {
                    if (requirements[i] is JsonObject item &&
                        string.Equals(item["id"]?.GetValue<string>(), "configuration-registration-key", StringComparison.OrdinalIgnoreCase))
                        requirements.RemoveAt(i);
                }

                UpdateRequirement(requirements, "public-url", "Aegis:PublicUrl", null, cancellationToken);
                UpdateRequirement(requirements, "configuration-url", "Aegis:Configuration:Url", null, cancellationToken);
                UpdateRequirement(requirements, "run-store", "Diagnostics:RunStorePath", "data/engineering-diagnostic-runs.json", cancellationToken);
                await UpdateSecretRequirementAsync(requirements, "diagnostics-machine-credential", options.MachineCredentialSecretName, cancellationToken);
                AddSecretManagerMetadata(requirements, contract);
            }

            using HttpClient client = new();
            string instanceId =
                contract["instanceId"]?.GetValue<string>()
                ?? Environment.MachineName;

            var registration = new ControlPlaneRegistrationClient(
                client,
                new ControlPlaneRegistrationOptions(
                    new Uri(baseUrl.TrimEnd('/') + "/", UriKind.Absolute),
                    ApplicationId,
                    instanceId,
                    configuration["Aegis:Registration:CredentialFile"]
                        ?? "/var/lib/aegis/diagnostics/registration.key",
                    TimeSpan.FromSeconds(10)),
                logger);

            ControlPlaneRegistrationStatus result =
                await registration.RegisterAsync(contract, cancellationToken);

            if (!result.IsRegistered)
            {
                logger.LogWarning(
                    "Aegis.Diagnostics control-plane registration state is {RegistrationState}: {RegistrationError}; Diagnostics remains operational.",
                    result.State,
                    result.Error ?? "No additional detail.");
                return false;
            }

            logger.LogInformation(
                "Aegis.Diagnostics control-plane registration is valid and its configuration contract was published.");
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { logger.LogWarning(ex, "Unable to publish Diagnostics configuration state; Diagnostics remains operational."); return false; }
    }

    private void UpdateRequirement(JsonArray requirements, string id, string key, string? codeDefault, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        JsonObject? requirement = Find(requirements, id);
        if (requirement is null) return;
        string? value = NullIfBlank(configuration[key]);
        bool configured = value is not null;
        bool hasDefault = codeDefault is not null;
        requirement["isConfigured"] = configured;
        requirement["hasDefault"] = hasDefault;
        requirement["defaultValue"] = codeDefault;
        requirement["effectiveValueAvailable"] = configured || hasDefault;
        requirement["configurationState"] = configured ? "Configured" : hasDefault ? "Default" : "Unresolved";
        requirement["effectiveSource"] = configured ? "Resolved IConfiguration" : hasDefault ? "Runtime/Code Default" : "Unresolved";
        requirement.Remove("safeDisplayValue");
        if (configured || hasDefault) requirement["safeDisplayValue"] = value ?? codeDefault;
    }

    private async Task UpdateSecretRequirementAsync(JsonArray requirements, string id, string secretName, CancellationToken cancellationToken)
    {
        JsonObject? requirement = Find(requirements, id);
        if (requirement is null) return;
        bool? configured = null;
        string verification;
        try
        {
            configured = !string.IsNullOrWhiteSpace(await secrets.GetAsync(secretName, cancellationToken));
            verification = configured.Value ? "Resolved" : "Missing";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Unable to verify secret requirement {RequirementId}; reporting Unknown.", id);
            verification = "VerificationFailed";
        }
        requirement["secretName"] = secretName;
        requirement["sensitive"] = true;
        requirement["isConfigured"] = configured;
        requirement["effectiveValueAvailable"] = configured;
        requirement["configurationState"] = configured == true ? "Configured" : configured == false ? "Unresolved" : "Unknown";
        requirement["effectiveSource"] = "Common.Secrets";
        requirement["verificationStatus"] = verification;
        requirement.Remove("safeDisplayValue");
    }

    private void AddSecretManagerMetadata(JsonArray requirements, JsonObject contract)
    {
        SecretProviderMetadata metadata = SecretProviderMetadataResolver.Resolve(configuration);
        string providerOrder = metadata.ProviderOrder.Count == 0 ? string.Empty : string.Join(" → ", metadata.ProviderOrder);

        UpsertMetadata(requirements, "secret-manager-mode", "Secret Manager Mode", "CommonSecrets:Mode", metadata.Mode.ToString());
        UpsertMetadata(requirements, "secret-manager-provider", "Secret Provider", null, metadata.ActiveProvider);
        UpsertMetadata(requirements, "secret-manager-provider-order", "Secret Provider Order", "CommonSecrets:ProviderOrder", NullIfBlank(providerOrder));
        UpsertMetadata(requirements, "secret-manager-management-url", "Secret Provider Management URL", null, metadata.ManagementUrl);

        contract["secrets"] = new JsonObject
        {
            ["provider"] = metadata.ActiveProvider,
            ["managementUrl"] = metadata.ManagementUrl
        };
    }

    private static void UpsertMetadata(JsonArray requirements, string id, string displayName, string? key, string? value)
    {
        JsonObject? existing = Find(requirements, id);
        JsonObject requirement = existing ?? new JsonObject
        {
            ["id"] = id,
            ["displayName"] = displayName,
            ["kind"] = "Configuration",
            ["required"] = false,
            ["purpose"] = "Safe Common.Secrets capability metadata; no credentials or secret values are published.",
            ["sensitive"] = false
        };
        if (key is not null) requirement["configurationKey"] = key;
        else requirement.Remove("configurationKey");
        if (existing is null) requirements.Add(requirement);
        bool configured = !string.IsNullOrWhiteSpace(value);
        requirement["isConfigured"] = configured;
        requirement["effectiveValueAvailable"] = configured;
        requirement["configurationState"] = configured ? "Configured" : "Unresolved";
        requirement["effectiveSource"] = configured ? "Common.Secrets" : "Unresolved";
        requirement.Remove("safeDisplayValue");
        if (configured) requirement["safeDisplayValue"] = value;
    }

    private static JsonObject? Find(JsonArray requirements, string id)
        => requirements.OfType<JsonObject>().FirstOrDefault(item => string.Equals(item["id"]?.GetValue<string>(), id, StringComparison.OrdinalIgnoreCase));

    private static string? First(params string?[] values) => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
