using System.Text.Json;
using GJNET.Services;
using Microsoft.Extensions.Logging.Abstractions;

public static class DiscoveryAdapterChecks
{
    public static async Task Run(string directory, Action<bool,string> check)
    {
        Directory.CreateDirectory(directory);
        var b = WebApplication.CreateBuilder(); b.Logging.ClearProviders(); b.WebHost.UseUrls("http://127.0.0.1:0");
        b.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.PropertyNamingPolicy = null);
        await using var app = b.Build(); var rebuilt = false; var filePaths = new List<string>();
        app.MapGet("/", () => Results.Content("<html><title>Adapter Fixture</title></html>", "text/html"));
        app.MapGet("/api2/json/cluster/resources", () => Results.Json(new {data = new object[] {new {id="node/pve",type="node",node="pve",status="online"},new {id="qemu/101",type="qemu",node="pve",vmid=101,name="vm-fixture",status="running"}}}));
        app.MapGet("/api2/json/nodes/pve/qemu/101/agent/network-get-interfaces", () => Results.Text("""
            {"data":{"result":[{"name":"ens18","ip-addresses":[{"ip-address":"192.0.2.81"}]},{"name":"docker0","ip-addresses":[{"ip-address":"172.17.0.1"}]},{"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1"}]}]}}
            """, "application/json"));
        app.MapGet("/api/environments", () => Results.Json(new[] {new {id=1,name="Fixture host",host="127.0.0.1"}}));
        app.MapGet("/api/containers", () => Results.Json(new object[] {
            new {id=rebuilt?"new-container":"old-container",name="web",image="nginx",state="running",labels=new Dictionary<string,string>{{"com.docker.compose.project","fixture"},{"com.docker.compose.service","web"}},ports=new[]{new {IP="0.0.0.0",PublicPort=new Uri(app.Urls.Single()).Port,PrivatePort=80,Type="tcp"}}},
            new {id="proxy",name="proxy",image="jc21/nginx-proxy-manager:latest",state="running",labels=new Dictionary<string,string>(),ports=Array.Empty<object>()}
        }));
        app.MapGet("/api/containers/proxy/files", () => Results.Json(new {entries = new[] {new {name="1.conf"},new {name="../../credentials"}}}));
        app.MapGet("/api/containers/proxy/files/content", (HttpContext context) => {
            filePaths.Add(context.Request.Query["path"].ToString());
            return Results.Json(new {content="listen 443 ssl;\nserver_name fixture.example.invalid;\n"});
        });
        await app.StartAsync(); var url = app.Urls.Single().TrimEnd('/') + "/";
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["DataPath"] = directory, ["TOKEN"] = "fixture" }).Build();
        var store = new InventoryStore(config);
        store.Save(new([],[],[],[new("pve","Cluster","proxmox",url,"TOKEN"),new("docker","Docker","docker",url,"TOKEN")],[],new(VmPorts:[])));
        var discovery = new ServiceDiscovery(store,config); var poller = new Poller(store,config,NullLogger<Poller>.Instance,discovery);
        await poller.Refresh(); var observations = poller.Read();
        var original = observations.Single(o=>o.Kind=="service" && o.Name=="web");
        check(original.SourceKey=="docker:docker:1:fixture:web:1", "Compose metadata creates stable discovery identity");
        check(observations.Single(o=>o.Kind=="vm").Details.GetValueOrDefault("addresses")=="192.0.2.81", "Proxmox guest network discovery excludes loopback and Docker bridges");
        check(original.WebPorts?.Single().Key=="80/tcp", "published endpoint identity uses private port rather than public port");
        var proxy = observations.Single(o=>o.Kind=="service" && o.Name=="proxy");
        check(proxy.WebPorts?.Single().Url=="https://fixture.example.invalid/", "Nginx Proxy Manager routes produce hostname dashboard candidates");
        check(filePaths.All(p=>p=="/data/nginx/proxy_host/1.conf"), "proxy discovery only reads numeric proxy config files");
        rebuilt=true; await poller.Refresh();
        var replacement = poller.Read().Single(o=>o.Kind=="service" && o.Name=="web");
        check(replacement.Id!=original.Id && replacement.SourceKey==original.SourceKey, "adapter preserves service identity when Docker container ID changes");
        check(poller.DiscoveryError is null, "adapter discovery completes without suppressing infrastructure observations");
    }
}
