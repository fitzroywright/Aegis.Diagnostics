using Aegis.Diagnostics;
using Common.Diagnostics;
using Common.Secrets;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
DiagnosticsOptions diagnosticsOptions = builder.Configuration.GetSection("Diagnostics").Get<DiagnosticsOptions>() ?? new DiagnosticsOptions();
if (string.IsNullOrWhiteSpace(diagnosticsOptions.EnvironmentName))
{
    diagnosticsOptions.EnvironmentName = builder.Environment.EnvironmentName;
}
builder.Services.AddSingleton(diagnosticsOptions);
builder.Services.AddHttpClient("diagnostics-targets", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHttpClient("configuration-discovery", client => client.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddCommonDiagnostics();
builder.Services.AddCommonSecrets(builder.Configuration);
builder.Services.AddCommonSecretsDiagnostics();
builder.Services.AddHostedService<ConfigurationContractPublisher>();
builder.Services.AddSingleton<ConfigurationDiscoveryCatalog>();
builder.Services.AddSingleton<IDiagnosticTargetCatalog>(services => services.GetRequiredService<ConfigurationDiscoveryCatalog>());
builder.Services.AddHostedService<ConfigurationDiscoveryWorker>();
builder.Services.AddSingleton<ApplicationHealthStateStore>();
builder.Services.AddHostedService<ApplicationHealthMonitor>();
builder.Services.AddDiagnosticsMessaging(builder.Configuration);
builder.Services.AddSingleton<RemoteDiagnosticCatalog>();
builder.Services.AddSingleton<DiagnosticPlaybookCatalog>();
builder.Services.AddSingleton<IncidentCorrelationService>();
builder.Services.AddSingleton<IIncidentNotificationPublisher, CommonMessagingIncidentNotificationPublisher>();
builder.Services.AddSingleton<DiagnosticOrchestrationService>();
builder.Services.AddSuiteSecurity();

WebApplication app = builder.Build();
app.MapSuiteSecurity();
app.UseSuiteSecurity();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseDiagnosticsApiAuthorization(diagnosticsOptions);
app.MapDiagnosticsApi(diagnosticsOptions);
app.Run();
