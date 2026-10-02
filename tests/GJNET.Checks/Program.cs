using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using GJNET.Services;
using Microsoft.Extensions.Logging.Abstractions;

var count=0;
void Check(bool value,string name) { if(!value) throw new Exception("FAILED: "+name); Console.WriteLine("PASS "+name); count++; }
void Reject(Action action,string name) { try { action(); } catch(ArgumentException) {Check(true,name);return;} throw new Exception("Expected rejection: "+name); }
int FreePort() { var l=new TcpListener(IPAddress.Loopback,0); l.Start(); var port=((IPEndPoint)l.LocalEndpoint).Port;l.Stop();return port; }
var temp=Path.Combine(Path.GetTempPath(),"gjnet-checks-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
Process? process=null; WebApplication? mock=null; WebApplication? tlsMock=null;
try {
    var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"DataPath",temp},{"PVE","fixture"},{"DOCKER","fixture"},{"IDRAC","fixture"},{"WRONG","bad"}}).Build();
    var store=new InventoryStore(config);
    var s=new Settings([new("public","Shared","Public link","https://example.invalid","PRIVATE-NOTE"),new("private","Ops","PRIVATE-LINK","https://private.invalid")],[new("wide",["10.0.0.0/8"],["public"]),new("specific",["10.99.0.0/24"],[])],[],[],[]);
    store.Save(s);
    Check(store.Guest(IPAddress.Parse("10.99.0.1"))?.Name=="specific","most specific guest subnet");
    Check(store.Guest(IPAddress.Parse("10.22.0.1"))?.Name=="wide","multiple subnet routing");
    Check(store.Guest(IPAddress.Parse("192.0.2.1")) is null,"unmatched client fails closed");
    Check(InventoryStore.Matches(IPAddress.Parse("::ffff:10.99.0.5"),"10.99.0.0/24"),"IPv4-mapped client");
    Check(!InventoryStore.Matches(IPAddress.IPv6Loopback,"10.0.0.0/8"),"IPv6 fails closed");
    Check(new InventoryStore(config).Read().Shortcuts.Count==2,"persistent inventory survives reload");
    Reject(()=>store.Save(s with {Shortcuts=[new("bad","x","x","javascript:alert(1)")]}),"unsafe shortcut rejected");
    Reject(()=>store.Save(s with {ScanSubnets=["10.0.0.0/16"]}),"large discovery subnet rejected");
    Reject(()=>store.Save(s with {GuestPages=[new("bad",["10.99.0.0/24"],["missing"])]}),"dangling guest shortcut rejected");
    Check(store.Read().Shortcuts.Count==2,"failed validation preserves configuration");
    var detached=store.Read();detached.Shortcuts.Clear();Check(store.Read().Shortcuts.Count==2,"readers cannot mutate stored state");
    var port=FreePort(); var mockUrl=$"http://127.0.0.1:{port}/";
    var b=WebApplication.CreateBuilder(); b.Logging.ClearProviders(); b.Services.ConfigureHttpJsonOptions(o=>o.SerializerOptions.PropertyNamingPolicy=null); b.WebHost.UseUrls(mockUrl); mock=b.Build();
    mock.MapGet("/api2/json/cluster/resources", (HttpContext c)=>c.Request.Headers.Authorization=="PVEAPIToken=fixture"?Results.Json(new {data=new object[]{new {id="node/pve",type="node",node="pve",status="online"},new {id="qemu/101",type="qemu",node="pve",vmid=101,name="vm-one",status="running"}}}):Results.Unauthorized());
    mock.MapGet("/redfish/v1/Systems",()=>Results.Json(new {Members=new[]{new Dictionary<string,string>{{"@odata.id","/redfish/v1/Systems/1"}}}}));
    mock.MapGet("/redfish/v1/Systems/1",()=>Results.Json(new {Id="1",Name="R730",Model="PowerEdge R730",SerialNumber="TEST",PowerState="On",Status=new {Health="OK"}}));
    mock.MapGet("/api/environments",(HttpContext c)=>c.Request.Headers.Authorization=="Bearer fixture"?Results.Json(new[]{new {id=1,name="hawser",host="192.0.2.20"},new {id=2,name="empty",host="192.0.2.21"}}):Results.Unauthorized());
    mock.MapGet("/api/containers",(HttpContext c)=>c.Request.Query["env"]=="1"?Results.Json(new[]{new {id="c1",name="web",image="nginx",state="running",status="Up",labels=new Dictionary<string,string>{{"com.docker.compose.project","media"}},ports=new[]{new {IP="0.0.0.0",PublicPort=8088,PrivatePort=80,Type="tcp"},new {IP="127.0.0.1",PublicPort=9090,PrivatePort=90,Type="tcp"},new {IP="0.0.0.0",PublicPort=53,PrivatePort=53,Type="udp"}}}}):Results.Json(Array.Empty<object>()));
    mock.MapGet("/broken/api2/json/cluster/resources",()=>Results.StatusCode(503));
    await mock.StartAsync();
    s=s with {Devices=[new("manual","Manual device","windows","127.0.0.1",[port],"Local fixture")],Integrations=[new("pve","Cluster","proxmox",mockUrl,"PVE"),new("idrac","iDRAC","redfish",mockUrl,"IDRAC","reader"),new("dock","Dockhand","docker",mockUrl,"DOCKER",HostAddresses:new(){{"1","192.0.2.55"}}),new("broken","Broken","proxmox",mockUrl+"broken/","PVE")]}; store.Save(s);
    var poller=new Poller(store,config,NullLogger<Poller>.Instance); await poller.Refresh(); var observations=poller.Read();
    Check(observations.Any(x=>x.Kind=="proxmox" && x.State=="online"),"Proxmox authenticated node reader");
    Check(observations.Any(x=>x.Kind=="vm" && x.Name=="vm-one" && x.State=="running"),"Proxmox VM reader");
    Check(observations.Any(x=>x.Kind=="hardware" && x.Details["model"]=="PowerEdge R730" && x.State=="OK"),"Redfish health and hardware reader");
    var container=observations.Single(x=>x.Kind=="service");
    Check(container.Links.SequenceEqual(new[]{"http://192.0.2.55:8088/"}),"Dockhand lower-case ports, host override, loopback and UDP exclusion");
    Check(container.Details["stack"]=="media","Dockhand stack association");
    Check(observations.Single(x=>x.Id=="dock:env:2").State=="unknown","empty Dockhand response is unknown");
    Check(observations.Single(x=>x.Id=="broken").State=="unknown","upstream failure is unknown, not down");
    Check(poller.LastPoll is not null,"poll completion timestamp");
    Check(observations.Single(x=>x.Id=="manual").Links.Contains($"http://127.0.0.1:{port}/"),"configured device TCP port probe and link");

    // Exercise the actual TLS handshake with an untrusted self-signed server certificate.
    using var rsa=RSA.Create(2048);
    var certificateRequest=new CertificateRequest("CN=GJNET-TLS-fixture",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    var alternativeNames=new SubjectAlternativeNameBuilder(); alternativeNames.AddIpAddress(IPAddress.Loopback);
    certificateRequest.CertificateExtensions.Add(alternativeNames.Build());
    using var generatedCertificate=certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
    using var certificate=X509CertificateLoader.LoadPkcs12(generatedCertificate.Export(X509ContentType.Pfx),null,X509KeyStorageFlags.Exportable);
    var tlsPort=FreePort(); var tlsUrl=$"https://127.0.0.1:{tlsPort}/";
    var tlsBuilder=WebApplication.CreateBuilder(); tlsBuilder.Logging.ClearProviders();
    tlsBuilder.WebHost.ConfigureKestrel(o=>o.Listen(IPAddress.Loopback,tlsPort,listener=>listener.UseHttps(certificate)));
    tlsMock=tlsBuilder.Build();
    tlsMock.MapGet("/api2/json/cluster/resources",(HttpContext c)=>c.Request.Headers.Authorization=="PVEAPIToken=fixture"?Results.Json(new {data=new[]{new {id="node/tls",type="node",node="tls",status="online"}}}):Results.Unauthorized());
    await tlsMock.StartAsync();
    var legacyTls=JsonSerializer.Deserialize<Integration>(JsonSerializer.Serialize(new {id="tls-default",name="Default TLS",kind="proxmox",url=tlsUrl,secretEnvironmentVariable="PVE"}),InventoryStore.Json)!;
    Check(!legacyTls.ValidateTlsCertificate,"existing integration JSON defaults certificate checks off");
    store.Save(s with {Devices=[],Integrations=[legacyTls,legacyTls with {Id="tls-strict",ValidateTlsCertificate=true},legacyTls with {Id="tls-missing",SecretEnvironmentVariable="MISSING_CREDENTIAL"},legacyTls with {Id="tls-auth",SecretEnvironmentVariable="WRONG"}]});
    await poller.Refresh(); var tlsResults=poller.Read();
    Check(tlsResults.Any(x=>x.Id=="tls-default:node/tls" && x.State=="online"),"default polling accepts self-signed HTTPS certificate");
    Check(tlsResults.Single(x=>x.Id=="tls-strict").Details["error"].Contains("TLS"),"strict opt-in rejects untrusted HTTPS certificate");
    Check(tlsResults.Single(x=>x.Id=="tls-missing").Details["error"].Contains("MISSING_CREDENTIAL"),"missing credential identifies its environment variable");
    Check(tlsResults.Single(x=>x.Id=="tls-auth").Details["error"].Contains("HTTP 401"),"authentication failure identifies HTTP status");
    Check(new InventoryStore(config).Read().Integrations.Single(x=>x.Id=="tls-strict").ValidateTlsCertificate,"strict certificate flag survives persistence");
    using(var ordinaryClient=new HttpClient()) {
        var rejected=false; try { await ordinaryClient.GetAsync(tlsUrl+"api2/json/cluster/resources"); } catch(HttpRequestException) {rejected=true;}
        Check(rejected,"certificate bypass remains scoped to the integration handler");
    }
    await tlsMock.DisposeAsync(); tlsMock=null;
    store.Save(s with {GuestPages=[new("Local guests",["127.0.0.0/8"],["public"])],Integrations=[]});
    var appPort=FreePort(); var root=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../"));
    var publishedIndex=Array.IndexOf(args,"--published");
    var appDirectory=publishedIndex>=0?Path.GetFullPath(args[publishedIndex+1],root):root;
    var start=new ProcessStartInfo("dotnet") {WorkingDirectory=appDirectory,UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
    start.ArgumentList.Add(publishedIndex>=0?Path.Combine(appDirectory,"GJNET.dll"):Path.Combine(root,"bin/Debug/net10.0/GJNET.dll")); start.ArgumentList.Add("--urls");start.ArgumentList.Add($"http://127.0.0.1:{appPort}");
    start.Environment["DataPath"]=temp;start.Environment["DashboardPassword"]="test-owner-password";start.Environment["McpToken"]="test-mcp-token";start.Environment["ASPNETCORE_ENVIRONMENT"]="Production";
    process=Process.Start(start)!; var output=new System.Text.StringBuilder(); process.OutputDataReceived+=(_,e)=>{if(e.Data is not null) lock(output) output.AppendLine(e.Data);};process.ErrorDataReceived+=(_,e)=>{if(e.Data is not null) lock(output) output.AppendLine(e.Data);};process.BeginOutputReadLine();process.BeginErrorReadLine();
    using var handler=new HttpClientHandler {AllowAutoRedirect=false,CookieContainer=new CookieContainer()};using var http=new HttpClient(handler){BaseAddress=new Uri($"http://127.0.0.1:{appPort}"),Timeout=TimeSpan.FromSeconds(5)};
    var ready=false;for(var attempt=0;attempt<50;attempt++){try{ready=(await http.GetAsync("/healthz")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}
    if(!ready) throw new Exception("App did not start: "+output);
    Check(ready,"real app health endpoint");
    var guest=await http.GetStringAsync("/");Check(guest.Contains("Public link") && !guest.Contains("PRIVATE-NOTE") && !guest.Contains("PRIVATE-LINK"),"guest output excludes private shortcuts and notes");
    var blazorScript=Regex.Match(guest,"<script src=\"([^\"]*blazor\\.web[^\"]*\\.js)\"").Groups[1].Value;
    Check(blazorScript.Length>0 && (await http.GetAsync("/"+blazorScript.TrimStart('/'))).IsSuccessStatusCode,"page's actual Blazor script is served in production mode");
    var spoof=new HttpRequestMessage(HttpMethod.Get,"/");spoof.Headers.Add("X-Forwarded-For","10.99.0.1");
    Check((await (await http.SendAsync(spoof)).Content.ReadAsStringAsync()).Contains("Local guests"),"forwarded client IP ignored without explicit proxy trust");
    var privateResponse=await http.GetAsync("/dashboard");var privateHtml=await privateResponse.Content.ReadAsStringAsync();Check(!privateHtml.Contains("PRIVATE-LINK") && (privateResponse.StatusCode==HttpStatusCode.Redirect || privateHtml.Contains("Owner sign in")),"anonymous dashboard isolation");
    var noCsrf=await http.PostAsync("/auth/login",new FormUrlEncodedContent(new Dictionary<string,string>{{"password","test-owner-password"}}));
    if(noCsrf.StatusCode!=HttpStatusCode.BadRequest) Console.WriteLine($"CSRF response: {noCsrf.StatusCode}\n{output}");
    Check(noCsrf.StatusCode==HttpStatusCode.BadRequest,"login requires CSRF token");
    var login=await http.GetStringAsync("/login");var token=Regex.Match(login,"name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value; Check(token.Length>0,"login renders antiforgery token");
    var signedIn=await http.PostAsync("/auth/login",new FormUrlEncodedContent(new Dictionary<string,string>{{"password","test-owner-password"},{"__RequestVerificationToken",WebUtility.HtmlDecode(token)}}));Check(signedIn.StatusCode==HttpStatusCode.Redirect && signedIn.Headers.Location?.ToString()=="/dashboard","password-only cookie login");
    Check((await http.GetStringAsync("/dashboard")).Contains("PRIVATE-LINK"),"authenticated private dashboard");
    async Task<HttpResponseMessage> Rpc(string method,object? parameters=null,bool auth=true) {var request=new HttpRequestMessage(HttpMethod.Post,"/mcp"){Content=JsonContent.Create(new {jsonrpc="2.0",id=1,method,@params=parameters})};if(auth)request.Headers.Authorization=new("Bearer","test-mcp-token");request.Headers.Accept.ParseAdd("application/json, text/event-stream");return await http.SendAsync(request);}
    Check((await Rpc("initialize",auth:false)).StatusCode==HttpStatusCode.Unauthorized,"MCP requires separate bearer token despite owner cookie");
    var initialized=await (await Rpc("initialize")).Content.ReadFromJsonAsync<JsonElement>(); Check(initialized.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString()=="GJNET","MCP initialization");
    var tools=await (await Rpc("tools/list")).Content.ReadFromJsonAsync<JsonElement>();Check(tools.GetProperty("result").GetProperty("tools").GetArrayLength()==3,"MCP tool discovery");
    await Rpc("tools/call",new {name="upsert_shortcut",arguments=new {id="mcp-link",section="Tools",name="Test",url="https://example.invalid/tool"}});
    var inv=await (await Rpc("tools/call",new {name="get_inventory"})).Content.ReadFromJsonAsync<JsonElement>(); Check(inv.ToString().Contains("mcp-link"),"MCP shortcut upsert persists");
    var bad=await (await Rpc("tools/call",new {name="upsert_shortcut",arguments=new {id="bad",section="Tools",name="bad",url="javascript:alert(1)"}})).Content.ReadFromJsonAsync<JsonElement>();Check(bad.GetProperty("result").GetProperty("isError").GetBoolean(),"MCP unsafe URL rejected");
    await Rpc("tools/call",new {name="remove_shortcut",arguments=new {id="public"}}); Check(!File.ReadAllText(Path.Combine(temp,"inventory.json")).Contains("\"public\""),"MCP deletion clears guest references");
    var origin=new HttpRequestMessage(HttpMethod.Post,"/mcp"){Content=JsonContent.Create(new{jsonrpc="2.0",id=1,method="ping"})};origin.Headers.Authorization=new("Bearer","test-mcp-token");origin.Headers.Add("Origin","https://evil.invalid");Check((await http.SendAsync(origin)).StatusCode==HttpStatusCode.Forbidden,"MCP rejects browser Origin");
    var getMcp=new HttpRequestMessage(HttpMethod.Get,"/mcp");getMcp.Headers.Authorization=new("Bearer","test-mcp-token");
    Check((await http.SendAsync(getMcp)).StatusCode==HttpStatusCode.MethodNotAllowed,"MCP non-streaming GET returns 405");
    Console.WriteLine($"{count} checks passed.");
} finally {
    if(process is not null) {if(!process.HasExited){process.Kill(entireProcessTree:true);await process.WaitForExitAsync();}process.Dispose();}
    if(mock is not null) await mock.DisposeAsync();
    if(tlsMock is not null) await tlsMock.DisposeAsync();
    // Only this unique test-owned directory is eligible for recursive cleanup.
    var resolved=Path.GetFullPath(temp); var allowed=Path.GetFullPath(Path.GetTempPath());
    if(resolved.StartsWith(allowed,StringComparison.OrdinalIgnoreCase) && Path.GetFileName(resolved).StartsWith("gjnet-checks-",StringComparison.Ordinal)) Directory.Delete(resolved,true);
}
