using GJNET.Components;
using GJNET.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;

if (args.Contains("--healthcheck"))
{
    try { using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) }; Environment.Exit((await client.GetAsync("http://127.0.0.1:8080/healthz")).IsSuccessStatusCode ? 0 : 1); } catch { Environment.Exit(1); }
    return;
}
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseStaticWebAssets();
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 1048576);
var data = builder.Configuration["DataPath"] ?? "data";
Directory.CreateDirectory(data);
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(data, "keys")));
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o => { o.LoginPath = "/login"; o.ExpireTimeSpan = TimeSpan.FromHours(12); o.Cookie.SameSite = SameSiteMode.Strict; });
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(o => o.AddPolicy("login", c => RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(1) })));
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Clear(); o.KnownIPNetworks.Clear();
    foreach (var proxy in (builder.Configuration["TrustedProxies"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries)) o.KnownProxies.Add(System.Net.IPAddress.Parse(proxy.Trim()));
});
builder.Services.AddSingleton<InventoryStore>(); builder.Services.AddSingleton<Poller>(); builder.Services.AddHostedService(p => p.GetRequiredService<Poller>());
var app = builder.Build();
if (!app.Environment.IsDevelopment()) app.UseExceptionHandler("/Error", createScopeForErrors: true);
if (!string.IsNullOrWhiteSpace(builder.Configuration["TrustedProxies"])) app.UseForwardedHeaders();
app.UseAuthentication(); app.UseAuthorization(); app.UseRateLimiter(); app.UseAntiforgery(); app.MapStaticAssets();
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.MapPost("/auth/login", async (HttpContext c, Microsoft.AspNetCore.Antiforgery.IAntiforgery csrf) =>
{
    if (!await csrf.IsRequestValidAsync(c)) return Results.BadRequest(); var form = await c.Request.ReadFormAsync(); var expected = builder.Configuration["DashboardPassword"];
    if (string.IsNullOrEmpty(expected) || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(form["password"].ToString())), SHA256.HashData(Encoding.UTF8.GetBytes(expected)))) return Results.Redirect("/login?failed=true");
    await c.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "Owner")], CookieAuthenticationDefaults.AuthenticationScheme))); return Results.Redirect("/dashboard");
}).RequireRateLimiting("login");
app.MapPost("/auth/logout", async (HttpContext c, Microsoft.AspNetCore.Antiforgery.IAntiforgery csrf) => { if (!await csrf.IsRequestValidAsync(c)) return Results.BadRequest(); await c.SignOutAsync(); return Results.Redirect("/"); }).RequireAuthorization();
app.MapMethods("/mcp", ["POST", "GET"], Mcp.Handle);
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
