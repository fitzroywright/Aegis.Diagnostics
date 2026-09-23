namespace Aegis.Diagnostics;

using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Common.Diagnostics;
using Common.Secrets;

public sealed record RemoteDiagnosticLevelDispatchResult(
    bool Accepted,
    DiagnosticLevelRunAccepted? Acceptance,
    DiagnosticLevelDeliveryState DeliveryState,
    string? Error = null);

public sealed class RemoteDiagnosticLevelCoordinator(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    DiagnosticLevelNonceCache nonceCache,
    IDiagnosticLevelRunStore runStore,
    ILogger<RemoteDiagnosticLevelCoordinator> logger)
{
    private readonly ConcurrentDictionary<Guid, PendingRemoteRun> pending = new();
    private readonly ConcurrentDictionary<Guid, PendingRemoteRun> completed = new();

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
            state = x.State.ToString(),
            x.CurrentTestId,
            x.CurrentTestName
        })
        .ToArray();

    public async Task<RemoteDiagnosticLevelDispatchResult> RequestAsync(
        DiagnosticTargetOptions target,
        EngineeringDiagnosticLevel level,
        string requestedBy,
        string? reason,
        Uri callbackBaseUri,
        CancellationToken cancellationToken)
    {
        if (!target.SupportsRemoteDiagnostics)
            return new(false, null, DiagnosticLevelDeliveryState.Rejected, "Target does not advertise remote diagnostics.");

        if (!Uri.TryCreate(target.BaseUrl, UriKind.Absolute, out Uri? baseUri))
            return new(false, null, DiagnosticLevelDeliveryState.NotReachable, "Target public URL is unresolved.");

        string? credential = await ResolveCredentialAsync(target, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(credential))
            return new(false, null, DiagnosticLevelDeliveryState.Rejected, "Target machine credential is unavailable.");

        Guid requestId = Guid.NewGuid();
        Guid correlationId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Uri callbackUri = new(callbackBaseUri, "/api/engineering/diagnostics/diagnostic-level/callback");
        DiagnosticLevelRunRequest request = new(
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
        string signature = DiagnosticLevelRequestSigning.CreateRunRequestSignature(
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
                return new(false, null, DiagnosticLevelDeliveryState.Rejected, "Target already has an active diagnostic run.");
            if (!response.IsSuccessStatusCode)
                return new(false, null, DiagnosticLevelDeliveryState.Rejected, $"Target rejected the request with HTTP {(int)response.StatusCode}.");

            DiagnosticLevelRunAccepted? accepted = await response.Content.ReadFromJsonAsync<DiagnosticLevelRunAccepted>(cancellationToken: cancellationToken).ConfigureAwait(false);
            if (accepted is null)
                return new(false, null, DiagnosticLevelDeliveryState.Rejected, "Target acknowledgement was unreadable.");

            pending[accepted.RunId] = new(
                accepted.RunId,
                accepted.RequestId,
                accepted.CorrelationId,
                target.ApplicationId,
                target.InstanceId,
                level,
                accepted.AcceptedAtUtc,
                accepted.AcceptedAtUtc,
                DiagnosticLevelExecutionState.Running,
                target.SecretName,
                target.BaseUrl,
                target.DiagnosticsRunsPath,
                null,
                null);

            var placeholder = new DiagnosticLevelRunRecord(
                accepted.RunId,
                accepted.RequestId,
                accepted.CorrelationId,
                accepted.Application,
                accepted.Component,
                baseUri.Host,
                level,
                DiagnosticLevelExecutionState.Running,
                DiagnosticLevelDeliveryState.Accepted,
                requestedBy,
                request.IssuedAtUtc,
                accepted.AcceptedAtUtc,
                accepted.AcceptedAtUtc,
                null,
                new DiagnosticLevelComponentVersion(
                    accepted.Application,
                    accepted.Component,
                    "Unknown",
                    CatalogVersion: "Unknown"),
                [],
                LastProgressAtUtc: accepted.AcceptedAtUtc);
            await runStore.SaveAsync(placeholder, cancellationToken).ConfigureAwait(false);

            return new(true, accepted, DiagnosticLevelDeliveryState.Accepted);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, null, DiagnosticLevelDeliveryState.NotReachable, "Target did not acknowledge before timeout.");
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "DiagnosticLevel target unreachable. Application={ApplicationId} Instance={InstanceId}", target.ApplicationId, target.InstanceId);
            return new(false, null, DiagnosticLevelDeliveryState.NotReachable, "Target could not be reached. Request was not queued.");
        }
    }

    public async Task<(bool Accepted, bool Duplicate, string? Error)> AuthenticateAndAcceptCallbackAsync(
        DiagnosticLevelCompletionCallback callback,
        string applicationId,
        string? instanceId,
        string path,
        string timestamp,
        string nonce,
        string signature,
        CancellationToken cancellationToken)
    {
        PendingRemoteRun? expected = null;
        bool duplicate = false;

        if (!pending.TryGetValue(callback.RunId, out expected))
        {
            if (!completed.TryGetValue(callback.RunId, out expected))
                return (false, false, "Unknown RunId.");
            duplicate = true;
        }

        if (callback.RequestId != expected.RequestId ||
            callback.CorrelationId != expected.CorrelationId)
            return (false, duplicate, "Run, request and correlation identifiers do not match the accepted request.");

        if (!string.Equals(applicationId, expected.ApplicationId, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrWhiteSpace(expected.InstanceId) &&
             !string.Equals(instanceId, expected.InstanceId, StringComparison.OrdinalIgnoreCase)))
            return (false, duplicate, "Callback application identity does not match the accepted target.");

        if (!DateTimeOffset.TryParse(timestamp, out DateTimeOffset signedAt) ||
            Math.Abs((DateTimeOffset.UtcNow - signedAt).TotalMinutes) > 2)
            return (false, duplicate, "Callback signature timestamp is invalid or stale.");

        if (!nonceCache.TryUse(nonce, DateTimeOffset.UtcNow))
            return (false, duplicate, "Callback nonce was already used.");

        string? credential = await ResolveCredentialAsync(expected.SecretName, cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(credential))
            return (false, duplicate, "Callback credential is unavailable.");

        if (string.IsNullOrWhiteSpace(signature) ||
            !DiagnosticLevelRequestSigning.VerifyCompletionCallback(
                credential,
                path,
                timestamp,
                nonce,
                callback,
                signature))
            return (false, duplicate, "Callback signature is invalid.");

        if (callback.Run.RunId != callback.RunId ||
            callback.Run.RequestId != callback.RequestId ||
            callback.Run.CorrelationId != callback.CorrelationId)
            return (false, duplicate, "Callback envelope identifiers do not match the embedded run.");

        if (!DiagnosticLevelIntegrity.Verify(callback.Run))
            return (false, duplicate, "Callback result integrity verification failed.");

        if (!duplicate)
        {
            pending.TryRemove(callback.RunId, out PendingRemoteRun? removed);
            completed[callback.RunId] = removed ?? expected;
            TrimCompleted();
        }

        return (true, duplicate, null);
    }

    public async Task RefreshPendingProgressAsync(
        CancellationToken cancellationToken = default)
    {
        foreach ((Guid runId, PendingRemoteRun value) in pending.ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Uri.TryCreate(value.BaseUrl, UriKind.Absolute, out Uri? baseUri))
                continue;

            string? credential = await ResolveCredentialAsync(value.SecretName, cancellationToken)
                .ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(credential))
                continue;

            string runsPath = string.IsNullOrWhiteSpace(value.RunsPath)
                ? "/api/engineering/diagnostics/diagnostic-level/runs"
                : value.RunsPath;

            Uri runUri = new(
                baseUri,
                runsPath.TrimEnd('/') + "/" + runId.ToString("D"));

            string timestamp = DateTimeOffset.UtcNow.ToString("O");
            string nonce = Guid.NewGuid().ToString("N");
            string signature = DiagnosticLevelRequestSigning.CreateRequestSignature(
                credential,
                "GET",
                runUri.AbsolutePath,
                timestamp,
                nonce);

            using var request = new HttpRequestMessage(HttpMethod.Get, runUri);
            request.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Timestamp", timestamp);
            request.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Nonce", nonce);
            request.Headers.TryAddWithoutValidation("X-Aegis-Diagnostics-Signature", signature);
            request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", "Aegis.Diagnostics");

            try
            {
                HttpClient client = httpClientFactory.CreateClient("diagnostics-targets");
                using HttpResponseMessage response =
                    await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                    continue;

                DiagnosticLevelRunRecord? run =
                    await response.Content.ReadFromJsonAsync<DiagnosticLevelRunRecord>(
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                if (run is null)
                    continue;

                PendingRemoteRun refreshed = value with
                {
                    State = run.ExecutionState,
                    LastUpdatedAtUtc = run.LastProgressAtUtc ?? DateTimeOffset.UtcNow,
                    CurrentTestId = run.CurrentTestId,
                    CurrentTestName = run.CurrentTestName
                };

                bool terminal = run.ExecutionState is
                    DiagnosticLevelExecutionState.Completed or
                    DiagnosticLevelExecutionState.Cancelled or
                    DiagnosticLevelExecutionState.Interrupted or
                    DiagnosticLevelExecutionState.NotStarted or
                    DiagnosticLevelExecutionState.Unknown;

                if (terminal)
                {
                    pending.TryRemove(runId, out _);
                    completed[runId] = refreshed;
                    TrimCompleted();
                }
                else
                {
                    pending[runId] = refreshed;
                }

                DiagnosticLevelRunRecord? stored =
                    await runStore.GetAsync(runId, cancellationToken).ConfigureAwait(false);
                if (stored is not null)
                {
                    await runStore.SaveAsync(
                        stored with
                        {
                            ExecutionState = run.ExecutionState,
                            StartedAtUtc = run.StartedAtUtc ?? stored.StartedAtUtc,
                            CompletedAtUtc = run.CompletedAtUtc,
                            CurrentTestId = run.CurrentTestId,
                            CurrentTestName = run.CurrentTestName,
                            LastProgressAtUtc = run.LastProgressAtUtc,
                            Tests = run.Tests,
                            Failure = run.Failure
                        },
                        cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                logger.LogDebug(
                    exception,
                    "Unable to refresh live DiagnosticLevel progress. RunId={RunId}",
                    runId);
            }
        }
    }

    public async Task MarkUnknownAfterAsync(
        TimeSpan staleAfter,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset cutoff = now - staleAfter;
        foreach ((Guid key, PendingRemoteRun value) in pending)
        {
            if (value.State == DiagnosticLevelExecutionState.Unknown ||
                value.LastUpdatedAtUtc >= cutoff)
                continue;

            PendingRemoteRun unknown = value with
            {
                State = DiagnosticLevelExecutionState.Unknown,
                LastUpdatedAtUtc = now
            };
            pending[key] = unknown;

            DiagnosticLevelRunRecord? stored =
                await runStore.GetAsync(value.RunId, cancellationToken).ConfigureAwait(false);
            if (stored is not null &&
                stored.ExecutionState is DiagnosticLevelExecutionState.Running or
                    DiagnosticLevelExecutionState.Accepted)
            {
                await runStore.SaveAsync(
                    stored with
                    {
                        ExecutionState = DiagnosticLevelExecutionState.Unknown,
                        Failure = "Remote diagnostic completion is stale; final target state is unknown.",
                        LastProgressAtUtc = value.LastUpdatedAtUtc
                    },
                    cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private Task<string?> ResolveCredentialAsync(
        DiagnosticTargetOptions target,
        CancellationToken cancellationToken) =>
        ResolveCredentialAsync(target.SecretName, cancellationToken);

    private async Task<string?> ResolveCredentialAsync(
        string? secretName,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(secretName)) return null;
        try
        {
            ISecretProvider secrets = CommonSecretProviderFactory.Create(configuration);
            return await secrets.GetAsync(secretName, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
    }

    private void TrimCompleted()
    {
        if (completed.Count <= 512) return;
        foreach (PendingRemoteRun old in completed.Values
                     .OrderBy(x => x.LastUpdatedAtUtc)
                     .Take(completed.Count - 512))
        {
            completed.TryRemove(old.RunId, out _);
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
        DiagnosticLevelExecutionState State,
        string? SecretName,
        string BaseUrl,
        string RunsPath,
        string? CurrentTestId,
        string? CurrentTestName);
}
