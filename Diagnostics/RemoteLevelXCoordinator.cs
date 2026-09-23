namespace Aegis.Diagnostics;

using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Common.Diagnostics;
using Common.Secrets;

public sealed record RemoteLevelXDispatchResult(
    bool Accepted,
    LevelXRunAccepted? Acceptance,
    LevelXDeliveryState DeliveryState,
    string? Error = null);

public sealed class RemoteLevelXCoordinator(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    ILogger<RemoteLevelXCoordinator> logger)
{
    private readonly ConcurrentDictionary<Guid, PendingRemoteRun> pending = new();

    public IReadOnlyList<object> Pending => pending.Values
        .OrderByDescending(x => x.AcceptedAtUtc)
        .Select(x => (object)new
        {
            x.RunId,
            x.RequestId,
            x.CorrelationId,
            x.ApplicationId,
            x.InstanceId,
            level = (int)x.Level,
            x.AcceptedAtUtc,
            x.LastUpdatedAtUtc,
            state = x.State.ToString()
        })
        .ToArray();

    public async Task<RemoteLevelXDispatchResult> RequestAsync(
        DiagnosticTargetOptions target,
        EngineeringDiagnosticLevel level,
        string requestedBy,
        string? reason,
        Uri callbackBaseUri,
        CancellationToken cancellationToken)
    {
        if (!target.SupportsRemoteDiagnostics)
            return new(false, null, LevelXDeliveryState.Rejected, "Target does not advertise remote diagnostics.");

        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri))
            return new(false, null, LevelXDeliveryState.NotReachable, "Target public URL is unresolved.");

        string? credential = await ResolveCredentialAsync(target, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(credential))
            return new(false, null, LevelXDeliveryState.Rejected, "Target machine credential is unavailable.");

        Guid requestId = Guid.NewGuid();
        Guid correlationId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Uri callbackUri = new(callbackBaseUri, "/api/engineering/diagnostics/levelx/callback");
        LevelXRunRequest request = new(
            requestId,
            correlationId,
            level,
            requestedBy,
            reason,
            callbackUri.ToString(),
            now,
            now.AddMinutes(2));

        Uri runUri = new(baseUri, target.DiagnosticsRunPath);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(request, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        string timestamp = now.ToString("O");
        string nonce = Guid.NewGuid().ToString("N");
        string signature = LevelXRequestSigning.CreateRunRequestSignature(
            credential,
            runUri.AbsolutePath,
            timestamp,
            nonce,
            request);

        using HttpRequestMessage message = new(HttpMethod.Post, runUri)
        {
            Content = new ByteArrayContent(body)
        };
        message.Content.Headers.ContentType = new("application/json");
        message.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Timestamp", timestamp);
        message.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Nonce", nonce);
        message.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Signature", signature);
        message.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", "Aegis.Diagnostics");

        try
        {
            HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
            using HttpResponseMessage response = await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
                return new(false, null, LevelXDeliveryState.Rejected, "Target already has an active diagnostic run.");
            if (!response.IsSuccessStatusCode)
                return new(false, null, LevelXDeliveryState.Rejected, $"Target rejected the request with HTTP {(int)response.StatusCode}.");

            LevelXRunAccepted? accepted = await response.Content.ReadFromJsonAsync<LevelXRunAccepted>(cancellationToken: cancellationToken).ConfigureAwait(false);
            if (accepted is null)
                return new(false, null, LevelXDeliveryState.Rejected, "Target acknowledgement was unreadable.");

            pending[accepted.RunId] = new(
                accepted.RunId,
                accepted.RequestId,
                accepted.CorrelationId,
                target.ApplicationId,
                target.InstanceId,
                level,
                accepted.AcceptedAtUtc,
                accepted.AcceptedAtUtc,
                LevelXExecutionState.Accepted);

            return new(true, accepted, LevelXDeliveryState.Accepted);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, null, LevelXDeliveryState.NotReachable, "Target did not acknowledge before timeout.");
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "LevelX target unreachable. Application={ApplicationId} Instance={InstanceId}", target.ApplicationId, target.InstanceId);
            return new(false, null, LevelXDeliveryState.NotReachable, "Target could not be reached. Request was not queued.");
        }
    }

    public bool AcceptCallback(LevelXCompletionCallback callback, out string? error)
    {
        if (!pending.TryGetValue(callback.RunId, out PendingRemoteRun? expected))
        {
            error = "Unknown RunId.";
            return false;
        }

        if (callback.RequestId != expected.RequestId || callback.CorrelationId != expected.CorrelationId)
        {
            error = "Run, request and correlation identifiers do not match the accepted request.";
            return false;
        }

        pending.TryRemove(callback.RunId, out _);
        error = null;
        return true;
    }

    public void MarkUnknownAfter(TimeSpan staleAfter)
    {
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - staleAfter;
        foreach ((Guid key, PendingRemoteRun value) in pending)
        {
            if (value.LastUpdatedAtUtc >= cutoff) continue;
            pending[key] = value with { State = LevelXExecutionState.Unknown, LastUpdatedAtUtc = DateTimeOffset.UtcNow };
        }
    }

    private async Task<string?> ResolveCredentialAsync(DiagnosticTargetOptions target, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(target.SecretName)) return null;
        try
        {
            ISecretProvider secrets = CommonSecretProviderFactory.Create(configuration);
            return await secrets.GetAsync(target.SecretName, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
    }

    private sealed record PendingRemoteRun(
        Guid RunId,
        Guid RequestId,
        Guid CorrelationId,
        string ApplicationId,
        string? InstanceId,
        EngineeringDiagnosticLevel Level,
        DateTimeOffset AcceptedAtUtc,
        DateTimeOffset LastUpdatedAtUtc,
        LevelXExecutionState State);
}
