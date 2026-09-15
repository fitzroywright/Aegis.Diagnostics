using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Common.Secrets;

namespace Aegis.Diagnostics;

public sealed class ConfigurationContractPublisher(IConfiguration configuration, IWebHostEnvironment environment, ISecretProvider secrets, ILogger<ConfigurationContractPublisher> logger) : BackgroundService
{
    private const string ApplicationId = "Aegis.Diagnostics";
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? baseUrl = First(configuration["Aegis:Configuration:Url"], configuration["AegisConfiguration:BaseUrl"]);
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            logger.LogInformation("Aegis.Configuration publication is disabled because no Configuration URL is configured.");
            return;
        }
        while (!stoppingToken.IsCancellationRequested)
        {
            if (await TryPublishAsync(baseUrl, stoppingToken)) return;
            try { await Task.Delay(RetryDelay, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        }
    }

    private async Task<bool> TryPublishAsync(string baseUrl, CancellationToken ct)
    {
        try
        {
            string? registrationKey = await secrets.GetAsync($"configuration/registration/{ApplicationId}", ct);
            if (string.IsNullOrWhiteSpace(registrationKey))
            {
                logger.LogWarning("Aegis.Configuration registration credential unavailable; Diagnostics remains operational.");
                return false;
            }

            string version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";
            string? siteId = First(configuration["Site:Id"], configuration["Diagnostics:SiteId"]);
            string instanceId = First(configuration["Service:Identity"], configuration["Diagnostics:InstanceId"], Environment.MachineName) ?? Environment.MachineName;
            string apiKeyEnvironmentVariable = configuration["Diagnostics:ApiKeyEnvironmentVariable"] ?? "AEGIS_DIAGNOSTICS_KEY";
            bool diagnosticsApiKeyPresent = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(apiKeyEnvironmentVariable));

            List<object> requirements =
            [
                Config("configuration-url", "Aegis:Configuration:Url", "System Configuration URL", false, "Aegis.Configuration endpoint used for contract publication."),
                Config("application-id", "Diagnostics:ApplicationId", "Application ID", false, "Diagnostics application identity.", "Aegis.Diagnostics"),
                Config("application-name", "Diagnostics:ApplicationName", "Application Name", false, "Display/application name used by Diagnostics.", "Aegis.Diagnostics"),
                Config("environment-name", "Diagnostics:EnvironmentName", "Environment Name", false, "Runtime environment label.", "Production"),
                Config("require-api-key", "Diagnostics:RequireApiKey", "Require API Key", false, "Controls machine-to-machine diagnostics authentication.", "true"),
                Config("api-key-header", "Diagnostics:ApiKeyHeader", "Diagnostics API Key Header", false, "HTTP header carrying the diagnostics machine credential.", "X-Aegis-Diagnostics-Key"),
                Config("api-key-env-name", "Diagnostics:ApiKeyEnvironmentVariable", "Diagnostics API Key Environment Variable", false, "Name of the environment variable containing the diagnostics machine credential.", "AEGIS_DIAGNOSTICS_KEY"),
                Secret("diagnostics-key", apiKeyEnvironmentVariable, "Diagnostics Machine Credential", configuration.GetValue("Diagnostics:RequireApiKey", true), "Machine credential accepted by Diagnostics. Value is never published.", diagnosticsApiKeyPresent, apiKeyEnvironmentVariable),
                Config("run-store", "Diagnostics:RunStorePath", "Diagnostic Run Store", true, "Filesystem path holding engineering diagnostic run history.", "data/engineering-diagnostic-runs.json"),
                Config("slack-enabled", "Diagnostics:Notifications:Slack:Enabled", "Slack Notifications Enabled", false, "Enables Slack notification delivery.", "false"),
                Config("slack-secret-name", "Diagnostics:Notifications:Slack:BotTokenSecretName", "Slack Bot Token Secret Name", false, "Logical secret name for Slack authentication."),
                Config("teams-enabled", "Diagnostics:Notifications:Teams:Enabled", "Teams Notifications Enabled", false, "Enables Microsoft Teams notification delivery.", "false"),
                Config("teams-secret-name", "Diagnostics:Notifications:Teams:WebhookSecretName", "Teams Webhook Secret Name", false, "Logical secret name for the Teams webhook."),
                Config("smtp-enabled", "Diagnostics:Notifications:Smtp:Enabled", "SMTP Notifications Enabled", false, "Enables SMTP notification delivery.", "false"),
                Config("smtp-host", "Diagnostics:Notifications:Smtp:Host", "SMTP Host", false, "SMTP server address.", null, "Diagnostics:Notifications:Smtp:Enabled=true"),
                Config("smtp-port", "Diagnostics:Notifications:Smtp:Port", "SMTP Port", false, "SMTP server port.", "25", "Diagnostics:Notifications:Smtp:Enabled=true"),
                Config("smtp-ssl", "Diagnostics:Notifications:Smtp:EnableSsl", "SMTP SSL", false, "Controls SMTP TLS/SSL.", "false", "Diagnostics:Notifications:Smtp:Enabled=true"),
                Config("smtp-from", "Diagnostics:Notifications:Smtp:FromAddress", "SMTP From Address", false, "Sender address for diagnostics notifications.", null, "Diagnostics:Notifications:Smtp:Enabled=true"),
                Config("smtp-user-secret-name", "Diagnostics:Notifications:Smtp:UserNameSecretName", "SMTP Username Secret Name", false, "Logical secret name for SMTP username."),
                Config("smtp-password-secret-name", "Diagnostics:Notifications:Smtp:PasswordSecretName", "SMTP Password Secret Name", false, "Logical secret name for SMTP password."),
                Secret("secret-zero", "Secret0", "OpenBao Secret Zero", true, "Bootstrap material used to establish OpenBao access.", SecretZeroDetected(), "OpenBao bootstrap")
            ];

            List<object> dependencies =
            [
                Dependency("configuration", "Aegis.Configuration", false, "Feature", "Receives Diagnostics operational contracts.", "Diagnostics continues running; Configuration loses visibility into Diagnostics.", "HTTP/HTTPS JSON", "Aegis.Configuration", baseUrl, await ReachableAsync(baseUrl, ct)),
                Dependency("openbao", "OpenBao", true, "Startup", "Provides secret-backed notification and registration credentials through Common.Secrets.", "Secret-backed integrations and registration cannot function.", "OpenBao HTTP API via Common.Secrets", "OpenBao", OpenBaoAddress(), await ReachableAsync(OpenBaoAddress(), ct))
            ];

            foreach (IConfigurationSection target in configuration.GetSection("Diagnostics:Targets").GetChildren())
            {
                string id = target["ApplicationId"] ?? $"target-{target.Key}";
                string name = target["Name"] ?? id;
                string? targetBaseUrl = target["BaseUrl"];
                string prefix = $"Diagnostics:Targets:{target.Key}";
                requirements.Add(Config($"target-{target.Key}-app", $"{prefix}:ApplicationId", $"{name} Application ID", true, "Application identity for this diagnostics target."));
                requirements.Add(Config($"target-{target.Key}-name", $"{prefix}:Name", $"{name} Display Name", true, "Display name for this diagnostics target."));
                requirements.Add(Config($"target-{target.Key}-type", $"{prefix}:ApplicationType", $"{name} Application Type", false, "Application type shown by Diagnostics."));
                requirements.Add(Config($"target-{target.Key}-url", $"{prefix}:BaseUrl", $"{name} Base URL", true, "Base URL used to reach this diagnostics target."));
                requirements.Add(Config($"target-{target.Key}-health", $"{prefix}:HealthPath", $"{name} Health Path", false, "Health endpoint path.", "/health"));
                requirements.Add(Config($"target-{target.Key}-run", $"{prefix}:DiagnosticsRunPath", $"{name} Diagnostic Run Path", false, "Endpoint used to initiate a remote diagnostic run."));
                requirements.Add(Config($"target-{target.Key}-runs", $"{prefix}:DiagnosticsRunsPath", $"{name} Diagnostic Runs Path", false, "Endpoint used to retrieve remote diagnostic runs."));
                requirements.Add(Config($"target-{target.Key}-machine-auth", $"{prefix}:RequireMachineCredential", $"{name} Require Machine Credential", false, "Whether remote diagnostic calls require a machine credential.", "true"));
                requirements.Add(Config($"target-{target.Key}-key-header", $"{prefix}:ApiKeyHeader", $"{name} API Key Header", false, "Credential header expected by the target.", "X-Aegis-Diagnostics-Key"));
                string targetEnvName = target["ApiKeyEnvironmentVariable"] ?? string.Empty;
                requirements.Add(Config($"target-{target.Key}-key-env", $"{prefix}:ApiKeyEnvironmentVariable", $"{name} Credential Environment Variable", false, "Name of the environment variable containing the target machine credential."));
                if (!string.IsNullOrWhiteSpace(targetEnvName))
                    requirements.Add(Secret($"target-{target.Key}-key", targetEnvName, $"{name} Machine Credential", target.GetValue("RequireMachineCredential", true), "Machine credential used for this remote diagnostics target.", !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(targetEnvName)), targetEnvName));
                dependencies.Add(Dependency($"target-{target.Key}", name, false, "Feature", "Remote diagnostics target monitored/orchestrated by Aegis.Diagnostics.", "Other targets and the Diagnostics application remain available; this target cannot be probed or orchestrated.", "HTTP/HTTPS diagnostics API", id, targetBaseUrl, await ReachableAsync(targetBaseUrl, ct)));
            }

            if (configuration.GetValue("Diagnostics:Notifications:Slack:Enabled", false))
            {
                string name = configuration["Diagnostics:Notifications:Slack:BotTokenSecretName"] ?? "aegis/diagnostics/messaging/slack/bot-token";
                requirements.Add(Secret("slack-token", name, "Slack Bot Token", true, "Credential for enabled Slack notification delivery.", HasValue(await secrets.GetAsync(name, ct)), name, "Diagnostics:Notifications:Slack:Enabled=true"));
                dependencies.Add(Dependency("slack", "Slack", false, "Feature", "Diagnostics notification channel.", "Diagnostics continues; Slack notifications are not delivered.", "Slack API", "Slack", null, null));
            }
            if (configuration.GetValue("Diagnostics:Notifications:Teams:Enabled", false))
            {
                string name = configuration["Diagnostics:Notifications:Teams:WebhookSecretName"] ?? "aegis/diagnostics/messaging/teams/webhook-url";
                requirements.Add(Secret("teams-webhook", name, "Teams Webhook", true, "Credential for enabled Teams notification delivery.", HasValue(await secrets.GetAsync(name, ct)), name, "Diagnostics:Notifications:Teams:Enabled=true"));
                dependencies.Add(Dependency("teams", "Microsoft Teams", false, "Feature", "Diagnostics notification channel.", "Diagnostics continues; Teams notifications are not delivered.", "Webhook HTTPS", "Microsoft Teams", null, null));
            }
            if (configuration.GetValue("Diagnostics:Notifications:Smtp:Enabled", false))
            {
                string user = configuration["Diagnostics:Notifications:Smtp:UserNameSecretName"] ?? "aegis/diagnostics/messaging/smtp/username";
                string password = configuration["Diagnostics:Notifications:Smtp:PasswordSecretName"] ?? "aegis/diagnostics/messaging/smtp/password";
                requirements.Add(Secret("smtp-user", user, "SMTP Username", false, "Secret SMTP username.", HasValue(await secrets.GetAsync(user, ct)), user, "Diagnostics:Notifications:Smtp:Enabled=true"));
                requirements.Add(Secret("smtp-password", password, "SMTP Password", true, "Secret SMTP password.", HasValue(await secrets.GetAsync(password, ct)), password, "Diagnostics:Notifications:Smtp:Enabled=true"));
                dependencies.Add(Dependency("smtp", "SMTP Server", false, "Feature", "Diagnostics email notification channel.", "Diagnostics continues; email notifications are not delivered.", "SMTP", "SMTP server", configuration["Diagnostics:Notifications:Smtp:Host"], null));
            }

            object registration = new
            {
                configuration = new { applicationId = ApplicationId, displayName = "Aegis Diagnostics", version, siteId, instanceId, description = "Aegis engineering diagnostics, remote target catalog and orchestration service.", requirements },
                dependencies = new { applicationId = ApplicationId, version, siteId, instanceId, dependencies },
                environment = new { applicationId = ApplicationId, version, siteId, instanceId, environment = await DetectEnvironmentAsync(ct) }
            };

            using HttpClient client = new() { Timeout = TimeSpan.FromSeconds(10) };
            using HttpRequestMessage request = new(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/api/registrations/register");
            request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Key", registrationKey);
            request.Content = new StringContent(JsonSerializer.Serialize(registration), Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Aegis.Configuration rejected Diagnostics registration with HTTP {StatusCode}; Diagnostics remains operational.", (int)response.StatusCode);
                return false;
            }
            logger.LogInformation("Aegis.Diagnostics published configuration, dependency and detected-environment contracts.");
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { logger.LogWarning(ex, "Unable to publish Diagnostics operational contracts; Diagnostics remains operational."); return false; }
    }

    private object Config(string id, string key, string name, bool required, string purpose, string? defaultValue = null, string? condition = null)
    {
        string envKey = key.Replace(":", "__", StringComparison.Ordinal);
        string? envValue = Environment.GetEnvironmentVariable(envKey);
        string? configured = configuration[key];
        string? value = First(envValue, configured, defaultValue);
        return new { id, displayName = name, kind = "Configuration", required, purpose, configurationKey = key, isConfigured = HasValue(value), safeDisplayValue = value, sensitive = false, conditionalOn = condition, allowedSources = new[] { "Environment Variable", $"appsettings.{environment.EnvironmentName}.json", "appsettings.json", "Code Default" }, resolutionOrder = new[] { "Environment Variable", $"appsettings.{environment.EnvironmentName}.json", "appsettings.json", "Code Default" }, effectiveSource = HasValue(envValue) ? $"Environment Variable ({envKey})" : HasValue(configured) ? "Configuration Provider" : defaultValue is not null ? "Code Default" : "Unresolved", hasDefault = defaultValue is not null, defaultValue, redacted = false };
    }

    private static object Secret(string id, string key, string name, bool required, string purpose, bool configured, string secretPath, string? condition = null) => new { id, displayName = name, kind = "Secret", required, purpose, configurationKey = key, isConfigured = configured, safeDisplayValue = (string?)null, sensitive = true, conditionalOn = condition, allowedSources = new[] { "OpenBao", "Environment Variable", "Secret0 bootstrap" }, resolutionOrder = new[] { "OpenBao or explicit machine credential environment variable", "no plaintext fallback" }, effectiveSource = configured ? "Secure runtime source" : "Unresolved", hasDefault = false, defaultValue = (string?)null, secretPath, redacted = true };
    private static object Dependency(string id, string name, bool required, string criticality, string purpose, string degraded, string @interface, string? engine, string? endpoint, bool? reachable) => new { id, displayName = name, required, criticality, purpose, degradedBehavior = degraded, @interface, engine, endpoint, reachable, evidence = "Explicitly declared by Diagnostics configuration/code; no connection-string inference." };

    private async Task<object> DetectEnvironmentAsync(CancellationToken ct)
    {
        Process process = Process.GetCurrentProcess(); GCMemoryInfo memory = GC.GetGCMemoryInfo();
        string runStore = Path.GetFullPath(configuration["Diagnostics:RunStorePath"] ?? "data/engineering-diagnostic-runs.json");
        string runDirectory = Path.GetDirectoryName(runStore) ?? environment.ContentRootPath;
        bool writable = Directory.Exists(runDirectory) && await IsWritableAsync(runDirectory, ct);
        List<object> endpoints = [];
        string? configUrl = First(configuration["Aegis:Configuration:Url"], configuration["AegisConfiguration:BaseUrl"]);
        if (HasValue(configUrl)) endpoints.Add(new { name = "Aegis.Configuration", endpoint = configUrl, reachable = await ReachableAsync(configUrl, ct) });
        foreach (IConfigurationSection target in configuration.GetSection("Diagnostics:Targets").GetChildren()) if (target["BaseUrl"] is { Length: > 0 } endpoint) endpoints.Add(new { name = target["Name"] ?? target["ApplicationId"] ?? target.Key, endpoint, reachable = await ReachableAsync(endpoint, ct) });
        List<object> disks = [];
        try { string root = Path.GetPathRoot(runStore) ?? ""; if (root.Length > 0) { DriveInfo d = new(root); if (d.IsReady) disks.Add(new { path = root, freeBytes = d.AvailableFreeSpace, totalBytes = d.TotalSize }); } } catch { }
        return new { operatingSystem = RuntimeInformation.OSDescription, operatingSystemVersion = Environment.OSVersion.VersionString, cpuArchitecture = RuntimeInformation.ProcessArchitecture.ToString(), processorCount = Environment.ProcessorCount, availableMemoryBytes = memory.TotalAvailableMemoryBytes > 0 ? memory.TotalAvailableMemoryBytes : null, processWorkingSetBytes = process.WorkingSet64, runtimeVersion = RuntimeInformation.FrameworkDescription, networkAvailable = NetworkInterface.GetIsNetworkAvailable(), disks, paths = new[] { new { path = runStore, exists = File.Exists(runStore), writable = (bool?)writable } }, endpoints, hardware = Array.Empty<object>(), detectedAtUtc = DateTimeOffset.UtcNow };
    }

    private string? OpenBaoAddress() => First(configuration["CommonSecrets:OpenBao:Address"], configuration["OpenBao:Address"], Environment.GetEnvironmentVariable("OPENBAO_ADDR"), Environment.GetEnvironmentVariable("VAULT_ADDR"));
    private static bool SecretZeroDetected() => HasAnyValue(Environment.GetEnvironmentVariable("OPENBAO_SECRET_ID"), Environment.GetEnvironmentVariable("OPENBAO_TOKEN"), Environment.GetEnvironmentVariable("VAULT_TOKEN"));
    private static async Task<bool?> ReachableAsync(string? endpoint, CancellationToken ct) { if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || (uri.Scheme != "http" && uri.Scheme != "https")) return null; try { using HttpClient c = new() { Timeout = TimeSpan.FromSeconds(3) }; using HttpResponseMessage _ = await c.SendAsync(new HttpRequestMessage(HttpMethod.Head, uri), ct); return true; } catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; } catch { return false; } }
    private static async Task<bool> IsWritableAsync(string path, CancellationToken ct) { string probe = Path.Combine(path, $".aegis-write-{Guid.NewGuid():N}"); try { await File.WriteAllTextAsync(probe, "", ct); File.Delete(probe); return true; } catch { try { if (File.Exists(probe)) File.Delete(probe); } catch { } return false; } }
    private static bool HasValue(string? value) => !string.IsNullOrWhiteSpace(value);
    private static bool HasAnyValue(params string?[] values) => values.Any(HasValue);
    private static string? First(params string?[] values) => values.FirstOrDefault(HasValue);
}
