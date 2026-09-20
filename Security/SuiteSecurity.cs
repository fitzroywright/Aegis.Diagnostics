using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Common.Security.Authenticators;
using Common.Security.Models;
using Common.Security.Options;
using Microsoft.AspNetCore.WebUtilities;

namespace Aegis.Diagnostics;

internal sealed record SuiteIdentity(string UserName, string DisplayName, string Title, string[] Permissions);
internal sealed record SuiteTicket(string Sub, string Name, string Title, string[] Permissions, string Audience, long Expires, string Nonce);

internal sealed class SuiteSecurity(IConfiguration configuration, IHostEnvironment environment)
{
    private const string Cookie = "Aegis.Diagnostics.Session";
    private const string DevelopmentSigningKey = "Aegis-Suite-Development-Handoff-Key-v1-Operations-Configuration-Diagnostics";
    private readonly byte[] key = Encoding.UTF8.GetBytes(GetSigningKey(configuration, environment));

    public string Mode => configuration["SuiteSecurity:Mode"] ?? "Mock";
    public int IdleTimeoutMinutes => Math.Clamp(configuration.GetValue("SuiteSecurity:IdleTimeoutMinutes", 480), 5, 480);

    private static string GetSigningKey(IConfiguration configuration, IHostEnvironment environment)
    {
        string? configured = configuration["SuiteSecurity:SigningKey"];
        if (!string.IsNullOrWhiteSpace(configured)) return configured;
        if (environment.IsDevelopment()) return DevelopmentSigningKey;
        throw new InvalidOperationException("SuiteSecurity:SigningKey is required outside Development. Supply it through protected deployment configuration/OpenBao.");
    }

    public SuiteIdentity? Authenticate(string userName, string password)
    {
        AuthenticationResult? result = null;
        if (Mode.Equals("ActiveDirectory", StringComparison.OrdinalIgnoreCase))
        {
            var options = new ActiveDirectoryAuthenticationOptions
            {
                Domain = configuration["SuiteSecurity:ActiveDirectory:Domain"] ?? "",
                SearchBase = configuration["SuiteSecurity:ActiveDirectory:SearchBase"] ?? "",
                Servers = configuration.GetSection("SuiteSecurity:ActiveDirectory:Servers").Get<string[]>() ?? []
            };
            result = new ActiveDirectory(options).Authenticate(userName, password);
        }
        else if (Mode.Equals("Mock", StringComparison.OrdinalIgnoreCase) && configuration.GetValue("SuiteSecurity:Mock:Enabled", false))
        {
            var options = new MockAuthenticationOptions
            {
                Password = configuration["SuiteSecurity:Mock:Password"] ?? "",
                AllowAnyUser = configuration.GetValue("SuiteSecurity:Mock:AllowAnyUser", true),
                AllowedUsers = configuration["SuiteSecurity:Mock:AllowedUsers"],
                AdminUsers = configuration["SuiteSecurity:Mock:AdminUsers"]
            };
            result = new MockAuthenticator(options).Authenticate(userName, password);
        }

        if (result?.IsAuthenticated != true) return null;
        string[] permissions = result.IsAdministrative
            ? [
                "Operations.View",
                "Configuration.View",
                "Diagnostics.View",
                "Diagnostics.Run",
                "Diagnostics.Repair",
                "Diagnostics.Critical",
                "Security.Manage"
              ]
            : ["Operations.View", "Configuration.View", "Diagnostics.View"];
        return new SuiteIdentity(userName, result.UserInfo?.DisplayName ?? userName, result.UserInfo?.Title ?? "User", permissions);
    }

    public SuiteIdentity? Read(HttpRequest request) => request.Cookies.TryGetValue(Cookie, out string? value) ? Validate(value) : null;
    public SuiteIdentity? AcceptHandoff(string token) => Validate(token);
    public string CreateHandoff(SuiteIdentity identity, string audience)
    {
        var ticket = new SuiteTicket(
            identity.UserName,
            identity.DisplayName,
            identity.Title,
            identity.Permissions,
            audience,
            DateTimeOffset.UtcNow.AddSeconds(45).ToUnixTimeSeconds(),
            Guid.NewGuid().ToString("N"));
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(ticket);
        using var hmac = new HMACSHA256(key);
        return WebEncoders.Base64UrlEncode(data) + "." + WebEncoders.Base64UrlEncode(hmac.ComputeHash(data));
    }

    public void Set(HttpResponse response, SuiteIdentity identity)
    {
        TimeSpan idleTimeout = TimeSpan.FromMinutes(IdleTimeoutMinutes);
        response.Cookies.Append(Cookie, Session(identity), new CookieOptions
        {
            HttpOnly = true,
            Secure = !environment.IsDevelopment(),
            SameSite = SameSiteMode.Lax,
            MaxAge = idleTimeout,
            IsEssential = true
        });
    }

    public void Clear(HttpResponse response) => response.Cookies.Delete(Cookie, new CookieOptions
    {
        HttpOnly = true,
        Secure = !environment.IsDevelopment(),
        SameSite = SameSiteMode.Lax
    });

    private SuiteIdentity? Validate(string token)
    {
        try
        {
            string[] parts = token.Split('.');
            if (parts.Length != 2) return null;
            byte[] data = WebEncoders.Base64UrlDecode(parts[0]);
            byte[] signature = WebEncoders.Base64UrlDecode(parts[1]);
            using var hmac = new HMACSHA256(key);
            if (!CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(data), signature)) return null;
            var ticket = JsonSerializer.Deserialize<SuiteTicket>(data);
            if (ticket is null || ticket.Audience != "Aegis.Diagnostics" || ticket.Expires < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;
            return new SuiteIdentity(ticket.Sub, ticket.Name, ticket.Title, ticket.Permissions);
        }
        catch
        {
            return null;
        }
    }

    private string Session(SuiteIdentity identity)
    {
        var ticket = new SuiteTicket(
            identity.UserName,
            identity.DisplayName,
            identity.Title,
            identity.Permissions,
            "Aegis.Diagnostics",
            DateTimeOffset.UtcNow.AddMinutes(IdleTimeoutMinutes).ToUnixTimeSeconds(),
            Guid.NewGuid().ToString("N"));
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(ticket);
        using var hmac = new HMACSHA256(key);
        return WebEncoders.Base64UrlEncode(data) + "." + WebEncoders.Base64UrlEncode(hmac.ComputeHash(data));
    }
}

internal static class SuiteSecurityExtensions
{
    public static IServiceCollection AddSuiteSecurity(this IServiceCollection services) => services.AddSingleton<SuiteSecurity>();

    public static void UseSuiteSecurity(this WebApplication app)
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
                context.Response.Redirect("/login?returnUrl=" + Uri.EscapeDataString(context.Request.Path + context.Request.QueryString));
                return;
            }

            context.Items["SuiteIdentity"] = identity;
            security.Set(context.Response, identity);
            await next();
        });
    }

    public static void MapSuiteSecurity(
        this WebApplication app,
        string operationsPublicUrl,
        string configurationPublicUrl)
    {
        app.MapGet("/login", (SuiteSecurity security, string? returnUrl) =>
            Results.Content(SuiteLoginPage.Render("Diagnostics", security.Mode, returnUrl), "text/html; charset=utf-8"));

        app.MapPost("/auth/login", async (HttpContext context, SuiteSecurity security) =>
        {
            IFormCollection form = await context.Request.ReadFormAsync();
            SuiteIdentity? identity = security.Authenticate(form["username"].ToString(), form["password"].ToString());
            if (identity is null) return Results.Redirect("/login?error=1");
            security.Set(context.Response, identity);
            string returnUrl = form["returnUrl"].ToString();
            return Results.Redirect(returnUrl.Length > 0 ? returnUrl : "/");
        });

        app.MapPost("/auth/handoff", async (HttpContext context, SuiteSecurity security) =>
        {
            IFormCollection form = await context.Request.ReadFormAsync();
            SuiteIdentity? identity = security.AcceptHandoff(form["token"].ToString());
            if (identity is null) return Results.Redirect("/login?error=handoff");
            security.Set(context.Response, identity);
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

        app.MapGet("/auth/me", (HttpContext context, SuiteSecurity security) =>
        {
            SuiteIdentity? identity = security.Read(context.Request);
            if (identity is null) return Results.Unauthorized();
            security.Set(context.Response, identity);
            return Results.Ok(new
            {
                identity.UserName,
                identity.DisplayName,
                identity.Title,
                identity.Permissions,
                idleTimeoutMinutes = security.IdleTimeoutMinutes
            });
        });

        static bool SafeLocal(string value) =>
            !string.IsNullOrWhiteSpace(value) &&
            value.StartsWith('/') &&
            !value.StartsWith("//", StringComparison.Ordinal) &&
            !value.Contains("\\", StringComparison.Ordinal);

        app.MapPost("/auth/logout", (HttpContext context, SuiteSecurity security) =>
        {
            security.Clear(context.Response);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new { signedOut = true });
        });
    }
}
