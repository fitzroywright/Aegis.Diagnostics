using System.Text;
using Common.Secrets;

namespace Aegis.Diagnostics;

public sealed class ConfigurationContractPublisher(
    IConfiguration configuration,
    IWebHostEnvironment environment,
    ISecretProvider secrets,
    ILogger<ConfigurationContractPublisher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? baseUrl = configuration["AegisConfiguration:BaseUrl"];
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            logger.LogInformation("Aegis.Configuration contract publication is disabled because AegisConfiguration:BaseUrl is not configured.");
            return;
        }

        string path = configuration["AegisConfiguration:ContractPath"]
            ?? Path.Combine(environment.ContentRootPath, "configuration", "Aegis.Diagnostics.configuration-contract.json");

        try
        {
            if (!File.Exists(path))
            {
                logger.LogWarning("Diagnostics configuration contract was not found at {ContractPath}; Diagnostics will continue without publishing it.", path);
                return;
            }

            string? key = await secrets.GetAsync("configuration/registration/Aegis.Diagnostics", stoppingToken);
            if (string.IsNullOrWhiteSpace(key))
            {
                logger.LogWarning("Aegis.Configuration registration credential is unavailable; Diagnostics will continue without publishing its contract.");
                return;
            }

            string json = await File.ReadAllTextAsync(path, stoppingToken);
            using HttpClient client = new() { Timeout = TimeSpan.FromSeconds(10) };
            using HttpRequestMessage request = new(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/api/contracts/register");
            request.Headers.TryAddWithoutValidation("X-Aegis-Configuration-Key", key);
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await client.SendAsync(request, stoppingToken);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Aegis.Configuration rejected Diagnostics contract publication with HTTP {StatusCode}; Diagnostics remains operational.", (int)response.StatusCode);
                return;
            }

            logger.LogInformation("Published Aegis.Diagnostics configuration contract to Aegis.Configuration.");
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Unable to publish Aegis.Diagnostics configuration contract; Diagnostics remains operational.");
        }
    }
}
