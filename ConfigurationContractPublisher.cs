using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
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
        string? baseUrl = First(configuration["Aegis:Configuration:Url"], configuration["AegisConfiguration:BaseUrl"]);
        if (string.IsNullOrWhiteSpace(baseUrl)) { logger.LogInformation("Aegis.Configuration publication disabled because no Configuration URL is configured."); return; }
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
            string registrationSecretPath = $"configuration/registration/{ApplicationId}";
            string? key = await secrets.GetAsync(registrationSecretPath, cancellationToken);
            if (string.IsNullOrWhiteSpace(key)) { logger.LogWarning("Aegis.Configuration registration credential unavailable; Diagnostics remains operational."); return false; }

            JsonObject contract = JsonNode.Parse(await File.ReadAllTextAsync(path, cancellationToken))!.AsObject();
            contract["version"] = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";
            contract["siteId"] = NullIfBlank(configuration["Site:Id"] ?? configuration["Diagnostics:SiteId"]);
            contract["instanceId"] = NullIfBlank(configuration["Service:Identity"] ?? configuration["Diagnostics:InstanceId"] ?? Environment.MachineName);
            contract["runtimeEnvironment"] = DetectedRuntimeEnvironment.Capture(environment.EnvironmentName, environment.ContentRootPath);

            if (contract["diagnostics"] is JsonObject diagnostics)
            {
                diagnostics["secretName"] = options.MachineCredentialSecretName;
            }

            if (contract["requirements"] is JsonArray requirements)
            {
                await UpdateRequirementAsync(requirements, "public-url", "Aegis:PublicUrl", null, cancellationToken);
                await UpdateRequirementAsync(requirements, "configuration-url", "Aegis:Configuration:Url", null, cancellationToken);
                await UpdateRequirementAsync(requirements, "run-store", "Diagnostics:RunStorePath", "data/engineering-diagnostic-runs.json", cancellationToken);
                await UpdateSecretRequirementAsync(requirements, "configuration-registration-key", registrationSecretPath, cancellationToken);
                await UpdateSecretRequirementAsync(requirements, "diagnostics-machine-credential", options.MachineCredentialSecretName, cancellationToken);
                AddSecretManagerMetadata(requirements);
            }

            using HttpClient client = new() { Timeout = TimeSpan.FromSeconds(10) };
            using HttpRequestMessage request = new(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/api/contracts/register");
            request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Key", key);
            request.Content = new StringContent(contract.ToJsonString(), Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) { logger.LogWarning("Aegis.Configuration rejected Diagnostics publication with HTTP {StatusCode}; Diagnostics remains operational.", (int)response.StatusCode); return false; }
            logger.LogInformation("Aegis.Diagnostics published its configuration contract heartbeat to Aegis.Configuration.");
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { logger.LogWarning(ex, "Unable to publish Diagnostics configuration state; Diagnostics remains operational."); return false; }
    }

    private async Task UpdateRequirementAsync(JsonArray requirements, string id, string key, string? codeDefault, CancellationToken cancellationToken)
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

    private void AddSecretManagerMetadata(JsonArray requirements)
    {
        string mode = configuration["CommonSecrets:Mode"] ?? "Production";
        string[] order = configuration.GetSection("CommonSecrets:ProviderOrder").Get<string[]>() ?? [];
        string openBaoAddress = configuration["CommonSecrets:OpenBao:Address"] ?? string.Empty;
        bool openBaoEnabled = configuration.GetValue("CommonSecrets:OpenBao:Enabled", false);

        UpsertMetadata(requirements, "secret-manager-mode", "Secret Manager Mode", "CommonSecrets:Mode", mode);
        UpsertMetadata(requirements, "secret-manager-provider-order", "Secret Provider Order", "CommonSecrets:ProviderOrder", order.Length == 0 ? null : string.Join(" → ", order));
        UpsertMetadata(requirements, "openbao-enabled", "OpenBao Enabled", "CommonSecrets:OpenBao:Enabled", openBaoEnabled.ToString());
        UpsertMetadata(requirements, "openbao-address", "OpenBao Address", "CommonSecrets:OpenBao:Address", NullIfBlank(openBaoAddress));
        UpsertMetadata(requirements, "openbao-scope", "OpenBao Endpoint Scope", "CommonSecrets:OpenBao:Address", DescribeEndpointScope(openBaoAddress));
    }

    private static void UpsertMetadata(JsonArray requirements, string id, string displayName, string key, string? value)
    {
        JsonObject requirement = Find(requirements, id) ?? new JsonObject
        {
            ["id"] = id,
            ["displayName"] = displayName,
            ["kind"] = "Configuration",
            ["required"] = false,
            ["purpose"] = "Safe Secret Manager deployment metadata; no credentials or secret values are published.",
            ["configurationKey"] = key,
            ["sensitive"] = false
        };
        if (!requirements.Contains(requirement)) requirements.Add(requirement);
        bool configured = !string.IsNullOrWhiteSpace(value);
        requirement["isConfigured"] = configured;
        requirement["effectiveValueAvailable"] = configured;
        requirement["configurationState"] = configured ? "Configured" : "Unresolved";
        requirement["effectiveSource"] = configured ? "Resolved IConfiguration" : "Unresolved";
        requirement.Remove("safeDisplayValue");
        if (configured) requirement["safeDisplayValue"] = value;
    }

    private static JsonObject? Find(JsonArray requirements, string id)
        => requirements.OfType<JsonObject>().FirstOrDefault(item => string.Equals(item["id"]?.GetValue<string>(), id, StringComparison.OrdinalIgnoreCase));

    private static string DescribeEndpointScope(string? address)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri)) return "Unknown";
        if (uri.IsLoopback) return "Local machine";
        if (System.Net.IPAddress.TryParse(uri.Host, out System.Net.IPAddress? ip))
        {
            byte[] bytes = ip.GetAddressBytes();
            bool privateV4 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168));
            return privateV4 ? "Private network" : "Public/remote address";
        }
        return "DNS endpoint; hosting locality cannot be determined from configuration alone";
    }

    private static string? First(params string?[] values) => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
