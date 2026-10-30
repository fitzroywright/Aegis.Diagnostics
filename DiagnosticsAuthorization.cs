using Aegis.Diagnostics;
using Common.Secrets;
using System.Security.Cryptography;
using System.Text;

internal static class DiagnosticsAuthorization
{
    internal static void UseDiagnosticsApiAuthorization(this WebApplication app, DiagnosticsOptions options)
    {
        app.Use(async (context, next) =>
        {
            if (!RequiresAuthorization(context))
            {
                await next();
                return;
            }

            if (!await IsAuthorizedAsync(context, options, context.RequestAborted))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Unauthorized", context.RequestAborted);
                return;
            }

            await next();
        });
    }

    private static bool RequiresAuthorization(HttpContext context) =>
        context.Request.Path.StartsWithSegments("/api/engineering/diagnostics") &&
        !context.Request.Path.Equals(
            "/api/engineering/diagnostics/levelx/callback",
            StringComparison.OrdinalIgnoreCase);

    private static async Task<bool> IsAuthorizedAsync(HttpContext context, DiagnosticsOptions options, CancellationToken cancellationToken)
    {
        SuiteSecurity suiteSecurity = context.RequestServices.GetRequiredService<SuiteSecurity>();
        SuiteIdentity? operatorIdentity = suiteSecurity.Read(context.Request);
        if (operatorIdentity is not null)
        {
            context.Items["SuiteIdentity"] = operatorIdentity;
            await suiteSecurity.SignInAsync(context, operatorIdentity);
            return true;
        }

        if (!options.RequireApiKey || string.IsNullOrWhiteSpace(options.MachineCredentialSecretName)) return false;

        ISecretProvider secrets = context.RequestServices.GetRequiredService<ISecretProvider>();
        string? expected;
        try { expected = await secrets.GetAsync(options.MachineCredentialSecretName, cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return false; }

        if (string.IsNullOrWhiteSpace(expected)) return false;
        bool authorized = context.Request.Headers.TryGetValue(options.ApiKeyHeader, out var supplied)
            && supplied.Count==1
            && Common.Security.Services.MachineCredentialProof.MatchesSecret(expected, supplied[0]!);
        if (authorized) context.Items["DiagnosticsMachineScopes"] = options.MachineCredentialScopes;
        return authorized;
    }

}
