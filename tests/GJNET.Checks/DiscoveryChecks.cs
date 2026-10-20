using System.Net;
using GJNET.Services;

public static class DiscoveryChecks
{
    public static async Task Run(string directory, Action<bool, string> check)
    {
        Directory.CreateDirectory(directory);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["DataPath"] = directory }).Build();
        var store = new InventoryStore(config);
        var requests = 0; var leakedAuth = false; var leakedCookie = false; var redirected = 0;
        async Task<WebApplication> Server()
        {
            var b = WebApplication.CreateBuilder(); b.Logging.ClearProviders(); b.WebHost.UseUrls("http://127.0.0.1:0");
            var app = b.Build();
            app.Use(async (context, next) => { Interlocked.Increment(ref requests); if (context.Request.Headers.Authorization.Count > 0) leakedAuth = true; if(context.Request.Headers.Cookie.Count > 0) leakedCookie = true; context.Response.Cookies.Append("fixture-session", "fixture"); await next(); });
            app.MapGet("/", () => Results.Content("<html><title>Native Fixture</title></html>", "text/html"));
            app.MapGet("/dashboard/", () => Results.Content("<html><title>Fixture Control</title><body>Dashboard</body></html>", "text/html"));
            app.MapGet("/api/", () => Results.Json(new { healthy = true }));
            app.MapGet("/login/", () => Results.Content("<html><title>Sign in</title></html>", "text/html", statusCode: 401));
            app.MapGet("/redirect/", () => Results.Redirect("/redirect-target/"));
            app.MapGet("/redirect-target/", () => { Interlocked.Increment(ref redirected); return Results.Content("<html>Target</html>", "text/html"); });
            await app.StartAsync(); return app;
        }
        await using var first = await Server(); await using var second = await Server();
        var url = first.Urls.Single().TrimEnd('/'); var movedUrl = second.Urls.Single().TrimEnd('/');
        store.Save(new([new("custom", "Custom section", "My chosen name", url + "/dashboard/", "Keep my notes")], [], [], [new("dock", "Docker", "docker", url, "")], [], new(VmPorts: [])));
        const string sourceKey = "dock:docker:1:stack:web:1";
        Observation Host(string state = "reachable") => new("dock:env:1", "Docker host", "docker-host", state, "127.0.0.1", new(), [], DateTimeOffset.UtcNow, "dock:env:1", "dock:env:1");
        Observation Container(string address, string state = "running", string id = "container-a") => new(id, "web", "service", state, "127.0.0.1", new(), [], DateTimeOffset.UtcNow, sourceKey, "dock:env:1", [new("80/tcp", address + "/dashboard/"), new("api", address + "/api/"), new("auth", address + "/login/"), new("redirect", address + "/redirect/")]);
        var discovery = new ServiceDiscovery(store, config);
        await discovery.Refresh([Host(), Container(url)]);
        var initial = discovery.Read(); var dashboardId = sourceKey + ":80/tcp";
        check(initial.Single(s => s.Id == dashboardId).State == "available", "automatic discovery verifies HTML dashboard");
        check(initial.All(s => s.Id != sourceKey + ":api"), "JSON-only API is not promoted to a dashboard");
        check(initial.Single(s => s.Id == sourceKey + ":auth").State == "authentication required", "protected dashboard remains discoverable");
        check(redirected == 0 && initial.Any(s => s.Id == sourceKey + ":redirect"), "redirect interfaces are recognized without following redirects");
        check(!leakedAuth, "web discovery sends no upstream API credentials");
        var pinned = initial.Single(s => s.ShortcutId == "custom");
        check(pinned.BoundEndpoint == dashboardId && pinned.Name == "My chosen name", "existing curated shortcut binds without renaming it");
        discovery.Hide(dashboardId);
        await discovery.Refresh([Host(), Container(movedUrl, id: "rebuilt-container")]);
        var moved = discovery.Read();
        check(moved.Single(s => s.Id == dashboardId).Url == movedUrl + "/dashboard/" && moved.Count(s => s.Id == dashboardId) == 1, "container replacement and public-port change retain dashboard identity");
        check(moved.Single(s => s.ShortcutId == "custom").Url == movedUrl + "/dashboard/", "bound shortcut follows changed service address");
        check(!leakedCookie, "discovery does not carry service cookies between requests");
        check(store.Read().Shortcuts.Single().Notes == "Keep my notes" && store.Read().Shortcuts.Single().Url == url + "/dashboard/", "discovery preserves manual inventory and notes");
        check(new ServiceDiscovery(store, config).Read().Single(s => s.Id == dashboardId).Hidden, "catalog and hidden choices survive service restart");
        await discovery.Refresh([Host(), Container(movedUrl, "exited")]);
        check(discovery.Read().Single(s => s.Id == dashboardId).State == "stopped", "stopped container changes dashboard status");
        await discovery.Refresh([Host("unknown")]);
        check(discovery.Read().Single(s => s.Id == dashboardId).State == "unknown", "unreachable host retains last-known dashboard as unknown");
        await discovery.Refresh([Host()]);
        check(discovery.Read().Single(s => s.Id == dashboardId).State == "missing", "successful host inventory detects removed service");
        check(discovery.Read().Single(s => s.ShortcutId == "custom").State == "missing", "bound shortcut reports missing source instead of probing obsolete address");
        await discovery.Refresh([Host(), Container(movedUrl)]);
        check(discovery.Read().Single(s => s.Id == dashboardId).State == "available", "reappearing service recovers without a duplicate");
        store.Update(s => s with { Shortcuts = [s.Shortcuts.Single() with { Url = movedUrl + "/login/" }] });
        await discovery.Refresh([Host(), Container(movedUrl)]);
        check(discovery.Read().Single(s => s.ShortcutId == "custom").Url == movedUrl + "/login/" && discovery.Read().Single(s => s.ShortcutId == "custom").BoundEndpoint is null, "manual URL edit overrides automatic address tracking");
        await discovery.Refresh([Host(), Container(url)]);
        check(discovery.Read().Single(s => s.ShortcutId == "custom").Url == movedUrl + "/login/", "manual address override persists across subsequent inventory changes");
        var beforeDisabled = requests;
        store.Update(s => s with { Discovery = new(Enabled: false) });
        await discovery.Refresh([Host(), Container(url)]);
        check(requests == beforeDisabled, "disabling discovery stops HTTP probing");
        store.Update(s => s with { Discovery = new(VmPorts: []), Integrations = [] });
        await discovery.Refresh([]);
        check(discovery.Read().Single(s => s.Id == dashboardId).State == "removed", "removed integration retires discovered dashboards");
        store.Update(s => s with { Shortcuts = [] });
        await discovery.Refresh([]);
        check(discovery.Read().All(s => s.ShortcutId is null), "deleted curated shortcuts leave no ghost monitor");
        var beforeCancel = discovery.Read();
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        try { await discovery.Refresh([Host(), Container(url)], cancelled.Token); } catch (OperationCanceledException) { }
        check(discovery.Read().SequenceEqual(beforeCancel), "cancelled discovery preserves the last complete catalog");

        const string vmId = "pve:qemu/101";
        store.Save(new([new("native","Native","Native app",url+"/dashboard/")],[],[],[new("pve","PVE","proxmox",url,"")],[],new(VmPorts:[new Uri(url).Port],VmHosts:new(){{vmId,["127.0.0.1"]}})));
        Observation Vm(string state="running")=>new(vmId,"Native VM","vm",state,"node",new(),[],DateTimeOffset.UtcNow,vmId,"pve");
        var native = new ServiceDiscovery(store,config);
        await native.Refresh([Vm()]);
        var nativeId=vmId+":port:"+new Uri(url).Port;
        check(native.Read().Single(s=>s.Id==nativeId).State=="available","known VM port sweep discovers a native dashboard");
        store.Update(s=>s with {Discovery=new(VmPorts:[new Uri(url).Port],VmHosts:new(){{vmId,["localhost"]}})});
        await native.Refresh([Vm()]);
        check(new Uri(native.Read().Single(s=>s.Id==nativeId).Url).Host=="localhost","native dashboard follows VM host changes between full sweeps");
        check(new Uri(native.Read().Single(s=>s.ShortcutId=="native").Url).Host=="localhost","curated native link follows VM address changes");
        store.Update(s=>s with {Discovery=new(VmPorts:[])});
        await native.Refresh([Vm()]);
        check(native.Read().Single(s=>s.Id==nativeId).State=="unknown","missing guest address retains native dashboard as unknown");
        await native.Refresh([Vm("stopped")]);
        check(native.Read().Single(s=>s.Id==nativeId).State=="stopped","stopped VM retains native interface with stopped status");
        store.Update(s=>s with {Discovery=new(VmPorts:[new Uri(url).Port],VmHosts:new(){{vmId,["127.0.0.1","localhost"]}})});
        var multipleAddresses = new ServiceDiscovery(store,config);
        await multipleAddresses.Refresh([Vm()]);
        check(multipleAddresses.Read().Any(s=>s.Id==nativeId+":address:1" && s.State=="available"),"VM discovery checks secondary configured interfaces");
    }
}
