namespace Aegis.Diagnostics;

using Common.Messaging;
using Common.Messaging.Channels.Slack;
using Common.Messaging.Channels.Smtp;
using Common.Messaging.Channels.Teams;
using Common.Messaging.Hosting;

public sealed class DiagnosticNotificationRecipientOptions
{
    public string Id { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string? Email { get; init; }
    public string? SlackUserId { get; init; }
    public string? Mobile { get; init; }
}

public sealed class ConfiguredDiagnosticRecipientDirectory(IConfiguration configuration) : IMessageRecipientDirectory
{
    public Task<IReadOnlyList<MessageRecipient>> ResolveAsync(
        IReadOnlyCollection<string> recipientIds,
        CancellationToken cancellationToken = default)
    {
        DiagnosticNotificationRecipientOptions[] configured = configuration
            .GetSection("Diagnostics:Notifications:Recipients")
            .Get<DiagnosticNotificationRecipientOptions[]>() ?? [];

        MessageRecipient[] recipients = configured
            .Where(item => !string.IsNullOrWhiteSpace(item.Id) && recipientIds.Contains(item.Id, StringComparer.OrdinalIgnoreCase))
            .Select(item => new MessageRecipient(
                item.Id.Trim(),
                string.IsNullOrWhiteSpace(item.UserName) ? item.Id.Trim() : item.UserName.Trim(),
                string.IsNullOrWhiteSpace(item.Email) ? null : item.Email.Trim(),
                string.IsNullOrWhiteSpace(item.SlackUserId) ? null : item.SlackUserId.Trim(),
                string.IsNullOrWhiteSpace(item.Mobile) ? null : item.Mobile.Trim()))
            .ToArray();

        return Task.FromResult<IReadOnlyList<MessageRecipient>>(recipients);
    }
}

public static class DiagnosticsMessagingRegistration
{
    public static IServiceCollection AddDiagnosticsMessaging(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddSingleton<IMessageRecipientDirectory, ConfiguredDiagnosticRecipientDirectory>();
        services.AddSingleton<IMessageStore, InMemoryMessageStore>();
        services.AddCommonMessagingQueuedDelivery(durable: true);
        services.AddCommonMessagingDiagnostics();

        IConfigurationSection slack = configuration.GetSection("Diagnostics:Notifications:Slack");
        IConfigurationSection teams = configuration.GetSection("Diagnostics:Notifications:Teams");
        IConfigurationSection smtp = configuration.GetSection("Diagnostics:Notifications:Smtp");

        bool slackEnabled = slack.GetValue("Enabled", false);
        bool teamsEnabled = teams.GetValue("Enabled", false);
        bool smtpEnabled = smtp.GetValue("Enabled", false);

        if (slackEnabled || teamsEnabled || smtpEnabled)
        {
            services.AddCommonMessagingSecrets();
        }

        if (slackEnabled)
        {
            services.AddSlackMessagingChannel(new SlackMessageOptions
            {
                BotToken = slack["BotToken"] ?? string.Empty,
                BotTokenSecretName = slack["BotTokenSecretName"] ?? "aegis/diagnostics/messaging/slack/bot-token"
            });
        }

        if (teamsEnabled)
        {
            services.AddTeamsMessagingChannel(new TeamsMessageOptions
            {
                WebhookUrl = teams["WebhookUrl"] ?? string.Empty,
                WebhookSecretName = teams["WebhookSecretName"] ?? "aegis/diagnostics/messaging/teams/webhook-url"
            });
        }

        if (smtpEnabled)
        {
            services.AddSmtpMessagingChannel(new SmtpMessageOptions
            {
                Host = smtp["Host"] ?? string.Empty,
                Port = smtp.GetValue("Port", 25),
                EnableSsl = smtp.GetValue("EnableSsl", false),
                FromAddress = smtp["FromAddress"] ?? string.Empty,
                UserName = smtp["UserName"] ?? string.Empty,
                Password = smtp["Password"] ?? string.Empty,
                UserNameSecretName = smtp["UserNameSecretName"] ?? "aegis/diagnostics/messaging/smtp/username",
                PasswordSecretName = smtp["PasswordSecretName"] ?? "aegis/diagnostics/messaging/smtp/password"
            });
        }

        return services;
    }
}
