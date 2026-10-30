using System.Text.Encodings.Web;
using Common.Security.Hosting;
using Common.Security.Models;
using Common.Secrets;
using Microsoft.Data.Sqlite;
namespace Aegis.Diagnostics;
internal static class SuiteSecurityExtensions
{
    public static IServiceCollection AddSuiteSecurity(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        var definition = new SuiteApplication("Aegis.Diagnostics", "Aegis.Diagnostics.Session", new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Administrator"] = ["Operations.View","Configuration.View","Diagnostics.View","Diagnostics.Run","Diagnostics.Repair","Diagnostics.Critical","Security.Manage"],
            ["Operator"] = ["Diagnostics.View","Diagnostics.Run"],
            ["Reader"] = ["Diagnostics.View"],
            ["Diagnostics"] = ["Diagnostics.View","Diagnostics.Run"]
        });
        return services.AddCommonSuiteSecurity(definition, provider =>
        {
            string? path = configuration["SuiteSecurity:AccountStorePath"];
            if (string.IsNullOrWhiteSpace(path))
            {
                if (!environment.IsDevelopment()) throw new InvalidOperationException("SuiteSecurity:AccountStorePath must point to the same protected identity database for all Control Plane applications.");
                path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Aegis", "ControlPlane", "security.db");
            }
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            return new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, ForeignKeys = true }.ToString());
        }, configuration.GetValue("SuiteSecurity:Entra:Enabled", false) ? provider => SuiteSecurityRegistration.EntraOptions(
            configuration, provider.GetRequiredService<ISecretProvider>().GetRequiredAsync("SuiteSecurity:Entra:ClientSecret").GetAwaiter().GetResult()) : null);
    }

    public static void UseSuiteSecurity(this WebApplication app, string operationsPublicUrl)
    {
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/health") ||
                context.Request.Path.StartsWithSegments("/login") ||
                context.Request.Path.StartsWithSegments("/auth") ||
                context.Request.Path.StartsWithSegments("/api/engineering/diagnostics"))
            {
                await next();
                return;
            }

            SuiteSecurity security = context.RequestServices.GetRequiredService<SuiteSecurity>();
            SuiteIdentity? identity = security.Read(context.Request);
            if (identity is null)
            {
                string returnUrl = context.Request.Path + context.Request.QueryString;
                string sso = operationsPublicUrl.TrimEnd('/') +
                    "/handoff/diagnostics?returnUrl=" +
                    Uri.EscapeDataString(returnUrl);
                context.Response.Redirect(sso);
                return;
            }

            context.Items["SuiteIdentity"] = identity;
            await security.SignInAsync(context,identity);
            await next();
        });
    }

    public static void MapSuiteSecurity(
        this WebApplication app,
        string operationsPublicUrl,
        string configurationPublicUrl)
    {
        app.MapGet("/login", (SuiteSecurity security, string? returnUrl) =>
            Results.Content(SuiteLoginPage.Render("Diagnostics", security.Mode, returnUrl, security.EntraEnabled), "text/html; charset=utf-8"));

        app.MapGet("/auth/sso", (string? returnUrl) =>
        {
            string destination = SafeLocal(returnUrl ?? string.Empty) ? returnUrl! : "/";
            string target = operationsPublicUrl.TrimEnd('/') +
                "/handoff/diagnostics?returnUrl=" +
                Uri.EscapeDataString(destination);
            return Results.Redirect(target);
        });

        app.MapPost("/auth/login", async (HttpContext context, SuiteSecurity security, ILogger<SuiteSecurity> logger) =>
        {
            IFormCollection form = await context.Request.ReadFormAsync();
            string userName = form["username"].ToString();
            string returnUrl = form["returnUrl"].ToString();
            try
            {
                SuiteIdentity? identity = security.Authenticate(userName, form["password"].ToString());
                if (identity is null) return Results.Redirect("/login?error=1");
                await security.SignInAsync(context,identity);
                return Results.Redirect(SafeLocal(returnUrl) ? returnUrl : "/");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Diagnostics authentication backend failed for user {UserName}.", userName);
                return Results.Redirect("/login?error=backend");
            }
        }).RequireRateLimiting(AccountSecurityHosting.LoginRateLimit);

        app.MapPost("/auth/handoff", async (HttpContext context, SuiteSecurity security) =>
        {
            IFormCollection form = await context.Request.ReadFormAsync();
            SuiteIdentity? identity = security.AcceptHandoff(form["token"].ToString());
            if (identity is null) return Results.Redirect("/login?error=handoff");
            await security.SignInAsync(context,identity);
            context.Response.Headers.CacheControl = "no-store";
            string returnUrl = form["returnUrl"].ToString();
            return Results.Redirect(SafeLocal(returnUrl) ? returnUrl : "/");
        });

        app.MapGet("/handoff/{target}", (string target, string? returnUrl, HttpContext context, SuiteSecurity security) =>
        {
            SuiteIdentity? identity = security.Read(context.Request);
            if (identity is null)
                return Results.Redirect("/login?returnUrl=" + Uri.EscapeDataString(context.Request.Path + context.Request.QueryString));

            string audience;
            string url;
            string permission;
            string destination = SafeLocal(returnUrl ?? string.Empty) ? returnUrl! : "/";

            if (target.Equals("operations", StringComparison.OrdinalIgnoreCase))
            {
                audience = "Aegis.Operations";
                url = operationsPublicUrl;
                permission = "Operations.View";
            }
            else if (target.Equals("configuration", StringComparison.OrdinalIgnoreCase))
            {
                audience = "Aegis.Configuration";
                url = configurationPublicUrl;
                permission = "Configuration.View";
            }
            else if (target.Equals("registration", StringComparison.OrdinalIgnoreCase))
            {
                audience = "Aegis.Configuration";
                url = configurationPublicUrl;
                permission = "Configuration.View";
                destination = "/registration-lifecycle";
            }
            else
            {
                return Results.BadRequest();
            }

            if (!identity.Permissions.Contains(permission, StringComparer.OrdinalIgnoreCase))
                return Results.StatusCode(StatusCodes.Status403Forbidden);

            string action = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(url.TrimEnd('/') + "/auth/handoff");
            string token = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(security.CreateHandoff(identity, audience));
            string encodedDestination = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(destination);
            string html = $"""<!doctype html><html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Opening {System.Text.Encodings.Web.HtmlEncoder.Default.Encode(target)}</title></head><body><form id="handoff" method="post" action="{action}"><input type="hidden" name="token" value="{token}"><input type="hidden" name="returnUrl" value="{encodedDestination}"></form><script>history.replaceState(null,'','/');document.getElementById('handoff').submit();</script><noscript><button form="handoff" type="submit">Continue</button></noscript></body></html>""";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            return Results.Content(html, "text/html; charset=utf-8");
        });

        app.MapGet("/auth/me",async(HttpContext context, SuiteSecurity security) =>
        {
            SuiteIdentity? identity = security.Read(context.Request);
            if (identity is null) return Results.Unauthorized();
            await security.SignInAsync(context,identity);
            return Results.Ok(new
            {
                identity.UserName,
                identity.DisplayName,
                identity.Title,
                identity.Permissions,
                clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                idleTimeoutMinutes = security.IdleTimeoutMinutes
            });
        });

        static bool SafeLocal(string value) =>
            !string.IsNullOrWhiteSpace(value) &&
            value.StartsWith('/') &&
            !value.StartsWith("//", StringComparison.Ordinal) &&
            !value.Contains("\\", StringComparison.Ordinal);

        app.MapPost("/auth/logout", async (HttpContext context, SuiteSecurity security) =>
        {
            await security.SignOutAsync(context);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new { signedOut = true });
        });
        app.MapGet("/auth/logout",async(HttpContext context, SuiteSecurity security) =>
        {
            await security.SignOutAsync(context);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Redirect("/login");
        });
    }
}
