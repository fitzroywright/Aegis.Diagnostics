using Aegis.Diagnostics;
using System.Security.Cryptography;
using System.Text;

internal static class DiagnosticsAuthorization
{
    internal static void UseDiagnosticsApiAuthorization(this WebApplication app, DiagnosticsOptions options)
    {
        app.Use(async (context, next) =>
        {
            if (!RequiresAuthorization(context, options))
            {
                await next();
                return;
            }

            if (!IsAuthorized(context, options))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Unauthorized");
                return;
            }

            await next();
        });
    }

    private static bool RequiresAuthorization(HttpContext context, DiagnosticsOptions options) =>
        options.RequireApiKey && context.Request.Path.StartsWithSegments("/api");

    private static bool IsAuthorized(HttpContext context, DiagnosticsOptions options)
    {
        string? expected = Environment.GetEnvironmentVariable(options.ApiKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(expected))
            return false;

        return context.Request.Headers.TryGetValue(options.ApiKeyHeader, out var supplied)
            && FixedTimeEquals(expected, supplied.ToString());
    }

    private static bool FixedTimeEquals(string expected, string supplied)
    {
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
        byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
        return expectedBytes.Length == suppliedBytes.Length
            && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes);
    }
}
