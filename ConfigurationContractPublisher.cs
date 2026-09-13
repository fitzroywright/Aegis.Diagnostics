using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using Common.Secrets;

namespace Aegis.Diagnostics;

public sealed class ConfigurationContractPublisher(IConfiguration configuration, IWebHostEnvironment environment, ISecretProvider secrets, ILogger<ConfigurationContractPublisher> logger) : BackgroundService
{
    private static readonly TimeSpan retryDelay = TimeSpan.FromMinutes(5);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? baseUrl = configuration["AegisConfiguration:BaseUrl"];
        if (string.IsNullOrWhiteSpace(baseUrl)) { logger.LogInformation("Aegis.Configuration publication disabled because AegisConfiguration:BaseUrl is not configured."); return; }
        string path = configuration["AegisConfiguration:ContractPath"] ?? Path.Combine(environment.ContentRootPath, "configuration", "Aegis.Diagnostics.configuration-contract.json");
        while (!stoppingToken.IsCancellationRequested)
        {
            if (await TryPublishAsync(baseUrl, path, stoppingToken)) return;
            try { await Task.Delay(retryDelay, stoppingToken); } catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }

    private async Task<bool> TryPublishAsync(string baseUrl, string path, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(path)) { logger.LogWarning("Diagnostics configuration contract not found at {ContractPath}; Diagnostics remains operational.", path); return false; }
            string? key = await secrets.GetAsync("configuration/registration/Aegis.Diagnostics", cancellationToken);
            if (string.IsNullOrWhiteSpace(key)) { logger.LogWarning("Aegis.Configuration registration credential unavailable; Diagnostics remains operational."); return false; }
            JsonObject contract = JsonNode.Parse(await File.ReadAllTextAsync(path, cancellationToken))!.AsObject();
            contract["version"] = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";
            contract["siteId"] = NullIfBlank(configuration["Site:Id"] ?? configuration["Diagnostics:SiteId"]);
            contract["instanceId"] = NullIfBlank(configuration["Service:Identity"] ?? configuration["Diagnostics:InstanceId"] ?? Environment.MachineName);
            if (contract["requirements"] is JsonArray requirements)
            {
                foreach (JsonObject requirement in requirements.OfType<JsonObject>())
                {
                    string id = requirement["id"]?.GetValue<string>() ?? "";
                    bool configured = id switch
                    {
                        "diagnostics-key" => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(configuration["Diagnostics:ApiKeyEnvironmentVariable"] ?? "AEGIS_DIAGNOSTICS_KEY")),
                        "run-store" => HasValue("Diagnostics:RunStorePath"),
                        "requestportal-target" => HasValue("Diagnostics:Targets:0:BaseUrl"),
                        "studio-target" => HasValue("Diagnostics:Targets:1:BaseUrl"),
                        "cafeteria-target" => HasValue("Diagnostics:Targets:2:BaseUrl"),
                        "sensornetwork-target" => HasValue("Diagnostics:Targets:3:BaseUrl"),
                        _ => false
                    };
                    requirement["isConfigured"] = configured;
                    requirement.Remove("safeDisplayValue");
                    if (requirement["sensitive"]?.GetValue<bool>() != true && TrySafeValue(id, out string? safe)) requirement["safeDisplayValue"] = safe;
                }
            }
            using HttpClient client = new() { Timeout = TimeSpan.FromSeconds(10) };
            using HttpRequestMessage request = new(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/api/contracts/register");
            request.Headers.TryAddWithoutValidation("X-Configuration-Registration-Key", key);
            request.Content = new StringContent(contract.ToJsonString(), Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) { logger.LogWarning("Aegis.Configuration rejected Diagnostics publication with HTTP {StatusCode}; Diagnostics remains operational.", (int)response.StatusCode); return false; }
            logger.LogInformation("Aegis.Diagnostics configuration state registered with Aegis.Configuration."); return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { logger.LogWarning(ex, "Unable to publish Diagnostics configuration state; Diagnostics remains operational."); return false; }
    }
    private bool HasValue(string key) => !string.IsNullOrWhiteSpace(configuration[key]);
    private bool TrySafeValue(string id, out string? value) { value = id switch { "run-store" => configuration["Diagnostics:RunStorePath"], "requestportal-target" => configuration["Diagnostics:Targets:0:BaseUrl"], "studio-target" => configuration["Diagnostics:Targets:1:BaseUrl"], "cafeteria-target" => configuration["Diagnostics:Targets:2:BaseUrl"], "sensornetwork-target" => configuration["Diagnostics:Targets:3:BaseUrl"], _ => null }; value = NullIfBlank(value); return value is not null; }
    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
