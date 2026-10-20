using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
namespace GJNET.Services;

public class Poller(InventoryStore store, IConfiguration config, ILogger<Poller> logger, ServiceDiscovery? serviceDiscovery = null) : BackgroundService
{
    readonly ServiceDiscovery discovery = serviceDiscovery ?? new(store, config);
    readonly SemaphoreSlim gate = new(1);
    Observation[] snapshot = [];
    public Observation[] Read() => Volatile.Read(ref snapshot);
    public DateTimeOffset? LastPoll { get; private set; }
    public string? DiscoveryError { get; private set; }
    protected override async Task ExecuteAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try { await Refresh(token); } catch (OperationCanceledException) when (token.IsCancellationRequested) { break; } catch (Exception e) { logger.LogWarning("Poll failed: {Type}", e.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromSeconds(60), token); } catch (OperationCanceledException) { break; }
        }
    }
    public async Task Refresh(CancellationToken token = default)
    {
        if (!await gate.WaitAsync(0, token)) return;
        try
        {
            var s = store.Read(); var results = new System.Collections.Concurrent.ConcurrentBag<Observation>();
            await Parallel.ForEachAsync(s.Devices, new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = token }, async (d, t) =>
            {
                var open = new List<int>(); foreach (var port in d.Ports) if (await Port(d.Address, port, t)) open.Add(port);
                var alive = open.Count > 0 || await Ping(d.Address);
                results.Add(new(d.Id, d.Name, d.Kind, alive ? "reachable" : "unreachable", d.Address, new() { { "notes", d.Notes }, { "probe", "ICMP / configured TCP ports" } }, open.Select(p => Link(d.Address, p)).ToList(), DateTimeOffset.UtcNow));
            });
            foreach (var i in s.Integrations)
            {
                try { foreach (var item in await PollIntegration(i, token)) results.Add(item); }
                catch (Exception e) when (e is not OperationCanceledException || !token.IsCancellationRequested) { results.Add(new(i.Id, i.Name, i.Kind, "unknown", i.Url, new() { { "error", DescribeFailure(e) } }, [i.Url], DateTimeOffset.UtcNow)); }
            }
            foreach (var subnet in s.ScanSubnets)
            {
                var (n, b) = InventoryStore.Network(subnet); var count = 1UL << (32 - b); var start = (ulong)(n & (b == 0 ? 0 : uint.MaxValue << (32 - b)));
                await Parallel.ForEachAsync(Enumerable.Range(0, (int)count), new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = token }, async (offset, t) =>
                {
                    var number = start + (uint)offset; var address = $"{number >> 24}.{(number >> 16) & 255}.{(number >> 8) & 255}.{number & 255}";
                    if (s.Devices.Any(d => d.Address == address)) return;
                    if (await Ping(address)) results.Add(new("scan:" + address, address, "discovered", "reachable", address, new() { { "subnet", subnet } }, [], DateTimeOffset.UtcNow));
                });
            }
            Volatile.Write(ref snapshot, results.OrderBy(x => x.Kind).ThenBy(x => x.Name).ToArray()); LastPoll = DateTimeOffset.UtcNow;
            try { await discovery.Refresh(Read(), token); DiscoveryError = null; }
            catch (Exception e) when (e is not OperationCanceledException || !token.IsCancellationRequested) { DiscoveryError = "Service discovery failed; showing the last saved catalog."; logger.LogWarning("Service discovery failed: {Type}", e.GetType().Name); }
        }
        finally { gate.Release(); }
    }
    static async Task<bool> Ping(string address) { try { using var ping = new Ping(); return (await ping.SendPingAsync(address, 700, Array.Empty<byte>())).Status == IPStatus.Success; } catch { return false; } }
    static async Task<bool> Port(string address, int port, CancellationToken t) { try { using var client = new TcpClient(); using var timeout = CancellationTokenSource.CreateLinkedTokenSource(t); timeout.CancelAfter(700); await client.ConnectAsync(address, port, timeout.Token); return true; } catch { return false; } }
    public static string Link(string host, int port) => new UriBuilder(port is 443 or 8006 ? "https" : "http", host, port).Uri.AbsoluteUri;
    async Task<List<Observation>> PollIntegration(Integration i, CancellationToken t)
    {
        var discoveryOptions = store.Read().Discovery ?? new();
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (!i.ValidateTlsCertificate)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        using var http = new HttpClient(handler) { BaseAddress = new Uri(i.Url.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(15) };
        var secret = config[i.SecretEnvironmentVariable];
        if (!string.IsNullOrWhiteSpace(i.SecretEnvironmentVariable) && string.IsNullOrEmpty(secret)) throw new MissingCredentialException(i.SecretEnvironmentVariable);
        if (i.Kind == "proxmox") http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "PVEAPIToken=" + secret);
        else if (i.Kind == "redfish") http.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(i.Username + ":" + secret)));
        else if (!string.IsNullOrEmpty(secret)) http.DefaultRequestHeaders.Authorization = new("Bearer", secret);
        var list = new List<Observation>();
        async Task<JsonElement> Get(string path) { using var response = await http.GetAsync(path, t); response.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(t)); return doc.RootElement.Clone(); }
        void Add(string id, string name, string kind, string state, string address, Dictionary<string, string> details, List<string> links) => list.Add(new(i.Id + ":" + id, name, kind, state, address, details, links, DateTimeOffset.UtcNow));
        if (i.Kind == "proxmox")
        {
            var data = (await Get("api2/json/cluster/resources")).GetProperty("data");
            foreach (var r in data.EnumerateArray())
            {
                var type = Text(r, "type"); if (type is not ("node" or "qemu" or "lxc")) continue;
                var node = Text(r, "node"); var name = type == "node" ? node : Text(r, "name", Text(r, "vmid"));
                Add(Text(r, "id"), name, type == "node" ? "proxmox" : "vm", Text(r, "status", "unknown"), node, new() { { "node", node }, { "type", type }, { "vmid", Text(r, "vmid") }, { "cpu", Text(r, "cpu") }, { "memory bytes", Text(r, "mem") } }, [i.Url]);
                list[^1] = list[^1] with { SourceKey = i.Id + ":" + Text(r, "id"), Scope = i.Id };
            }
            if (discoveryOptions.Enabled)
            {
                var enriched = new System.Collections.Concurrent.ConcurrentDictionary<string, Observation>();
                await Parallel.ForEachAsync(list.Where(o => o.Kind == "vm" && o.State == "running"), new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = t }, async (vm, ct) =>
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    var details = new Dictionary<string, string>(vm.Details);
                    try
                    {
                        var prefix = "api2/json/nodes/" + Uri.EscapeDataString(details["node"]) + "/" + details["type"] + "/" + Uri.EscapeDataString(details["vmid"]);
                        using var response = await http.GetAsync(prefix + (details["type"] == "lxc" ? "/interfaces" : "/agent/network-get-interfaces"), timeout.Token);
                        response.EnsureSuccessStatusCode();
                        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token));
                        var network = doc.RootElement.GetProperty("data");
                        if (network.ValueKind == JsonValueKind.Object && network.TryGetProperty("result", out var interfaces)) network = interfaces;
                        var addresses = new List<string>();
                        if (network.ValueKind == JsonValueKind.Array) foreach (var nic in network.EnumerateArray())
                        {
                            var nicName = Text(nic, "name");
                            if (nicName == "lo" || nicName.StartsWith("veth") || nicName.StartsWith("docker") || nicName.StartsWith("br-")) continue;
                            if (nic.TryGetProperty("ip-addresses", out var ips)) foreach (var entry in ips.EnumerateArray())
                                if (IPAddress.TryParse(Text(entry, "ip-address"), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any) && !ip.ToString().StartsWith("169.254.")) addresses.Add(ip.ToString());
                        }
                        details["addresses"] = string.Join(',', addresses.Distinct());
                    }
                    catch (Exception e) when (e is HttpRequestException or JsonException or OperationCanceledException or InvalidOperationException)
                    { ct.ThrowIfCancellationRequested(); details["address discovery"] = "Guest network information unavailable; configure discovery.vmHosts for this VM."; }
                    enriched[vm.Id] = vm with { Details = details };
                });
                list = list.Select(vm => enriched.GetValueOrDefault(vm.Id, vm)).ToList();
            }
        }
        else if (i.Kind == "redfish")
        {
            var systems = await Get("redfish/v1/Systems");
            foreach (var member in systems.GetProperty("Members").EnumerateArray())
            {
                var path = member.GetProperty("@odata.id").GetString()!;
                if (!path.StartsWith("/redfish/v1/Systems/", StringComparison.Ordinal)) throw new ArgumentException("Unexpected system path");
                var r = await Get(path.TrimStart('/')); var health = r.TryGetProperty("Status", out var status) ? Text(status, "Health", "unknown") : "unknown";
                Add(Text(r, "Id"), Text(r, "Name", i.Name), "hardware", health, i.Url, new() { { "model", Text(r, "Model") }, { "power", Text(r, "PowerState") }, { "service tag", Text(r, "SerialNumber") }, { "manufacturer", Text(r, "Manufacturer") } }, [i.Url]);
            }
        }
        else
        {
            var environments = await Get("api/environments");
            foreach (var env in environments.EnumerateArray())
            {
                var envId = Text(env, "id"); var host = i.HostAddresses?.GetValueOrDefault(envId) ?? i.HostAddress;
                if (string.IsNullOrWhiteSpace(host)) host = Text(env, "publicIp");
                if (string.IsNullOrWhiteSpace(host)) host = Text(env, "connectionType") == "socket" ? http.BaseAddress.Host : Text(env, "host");
                // Hawser's edge-agent marker is a connection mode, not a routable hostname.
                if (host == "edge-agent") host = "";
                if (Uri.TryCreate(host, UriKind.Absolute, out var hostUri)) host = hostUri.Host;
                Add("env:" + envId, Text(env, "name"), "docker-host", "unknown", host, new() { { "environment", envId }, { "note", "Reachability is represented by the container API result." } }, [i.Url]);
                list[^1] = list[^1] with { SourceKey = i.Id + ":env:" + envId, Scope = i.Id + ":env:" + envId };
                try
                {
                    var containers = await Get("api/containers?env=" + Uri.EscapeDataString(envId));
                    foreach (var r in containers.EnumerateArray())
                    {
                        var id = Text(r, "Id", Text(r, "id")); var name = Text(r, "name");
                        if (r.TryGetProperty("Names", out var names)) name = names.EnumerateArray().FirstOrDefault().GetString()?.TrimStart('/') ?? id;
                        var links = new List<string>();
                        var webPorts = new List<ServicePort>();
                        if ((r.TryGetProperty("ports", out var ports) || r.TryGetProperty("Ports", out ports)) && ports.ValueKind == JsonValueKind.Array && Uri.CheckHostName(host) != UriHostNameType.Unknown) foreach (var p in ports.EnumerateArray())
                        {
                            if (p.TryGetProperty("PublicPort", out var publicPort) && Text(p, "Type", "tcp") == "tcp")
                            {
                                var bind = Text(p, "IP"); if (bind is "127.0.0.1" or "::1") continue;
                                var address = !string.IsNullOrWhiteSpace(bind) && bind is not ("0.0.0.0" or "::") ? bind : host;
                                var link = Link(address, publicPort.GetInt32());
                                if (!links.Contains(link)) links.Add(link);
                                var key = Text(p, "PrivatePort", publicPort.ToString()) + "/tcp";
                                if (!webPorts.Any(p => p.Key == key)) webPorts.Add(new(key, link));
                            }
                        }
                        var stack = (r.TryGetProperty("labels", out var labels) || r.TryGetProperty("Labels", out labels)) ? Text(labels, "com.docker.compose.project") : "";
                        var composeService = Text(labels, "com.docker.compose.service");
                        var identity = stack.Length > 0 && composeService.Length > 0 ? Uri.EscapeDataString(stack) + ":" + Uri.EscapeDataString(composeService) + ":" + Text(labels, "com.docker.compose.container-number", "1") : Uri.EscapeDataString(name);
                        var declaredUrl = Text(labels, "gjnet.url", Text(labels, "homepage.href"));
                        if (InventoryStore.WebUrl(declaredUrl)) webPorts.Add(new("label", declaredUrl));
                        string? proxyError = null;
                        var image = Text(r, "Image", Text(r, "image"));
                        if (discoveryOptions.Enabled && discoveryOptions.ReadProxyHosts && image.Contains("nginx-proxy-manager", StringComparison.OrdinalIgnoreCase) && Text(r, "State", Text(r, "state")) == "running")
                        {
                            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(t); timeout.CancelAfter(TimeSpan.FromSeconds(8));
                            try
                            {
                                var fileBase = "api/containers/" + Uri.EscapeDataString(id) + "/files";
                                async Task<JsonElement> ReadFileApi(string path)
                                {
                                    using var response = await http.GetAsync(path, timeout.Token); response.EnsureSuccessStatusCode();
                                    using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token)); return doc.RootElement.Clone();
                                }
                                var files = await ReadFileApi(fileBase + "?env=" + envId + "&path=%2Fdata%2Fnginx%2Fproxy_host&simpleLs=true");
                                foreach (var file in files.GetProperty("entries").EnumerateArray().Take(128))
                                {
                                    var fileName = Text(file, "name");
                                    if (!System.Text.RegularExpressions.Regex.IsMatch(fileName, @"^\d+\.conf$")) continue;
                                    var content = Text(await ReadFileApi(fileBase + "/content?env=" + envId + "&path=" + Uri.EscapeDataString("/data/nginx/proxy_host/" + fileName)), "content");
                                    var scheme = System.Text.RegularExpressions.Regex.IsMatch(content, @"(?m)^\s*listen\s+[^;]*\bssl\b") ? "https" : "http";
                                    var domains = System.Text.RegularExpressions.Regex.Match(content, @"(?m)^\s*server_name\s+([^;]+);").Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                                    for (var n = 0; n < domains.Length && n < 16; n++)
                                        if (domains[n].Contains('.') && Uri.CheckHostName(domains[n]) == UriHostNameType.Dns && InventoryStore.WebUrl(scheme + "://" + domains[n] + "/")) webPorts.Add(new("proxy:" + fileName + ":" + n, scheme + "://" + domains[n] + "/"));
                                }
                            }
                            catch (Exception e) when (e is HttpRequestException or JsonException or OperationCanceledException or InvalidOperationException or KeyNotFoundException)
                            { t.ThrowIfCancellationRequested(); proxyError = "Proxy route discovery unavailable. Check Dockhand file-read permission or disable discovery.readProxyHosts."; }
                        }
                        if (Text(labels, "gjnet.discover") == "false") webPorts.Clear();
                        Add(envId + ":" + id, name, "service", Text(r, "State", Text(r, "state", "unknown")), host, new() { { "host", Text(env, "name") }, { "stack", stack }, { "image", Text(r, "Image", Text(r, "image")) }, { "status", Text(r, "Status", Text(r, "status")) }, { "health", Text(r, "health") } }, links);
                        list[^1] = list[^1] with { SourceKey = i.Id + ":docker:" + envId + ":" + identity, Scope = i.Id + ":env:" + envId, WebPorts = webPorts.ToArray() };
                        if (proxyError is not null) list[^1].Details["proxy discovery"] = proxyError;
                    }
                    var index = list.FindIndex(x => x.Id == i.Id + ":env:" + envId); list[index] = list[index] with { State = containers.GetArrayLength() > 0 ? "reachable" : "unknown" };
                }
                catch (HttpRequestException e) { var index = list.FindIndex(x => x.Id == i.Id + ":env:" + envId); list[index] = list[index] with { State = "unknown", Details = new() { { "error", DescribeFailure(e) } } }; }
            }
        }
        return list;
    }
    public static string Text(JsonElement e, string key, string fallback = "") => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var value) ? value.ToString() : fallback;
    sealed class MissingCredentialException(string variable) : Exception
    {
        public string Variable { get; } = variable;
    }
    static string DescribeFailure(Exception error) => error switch
    {
        MissingCredentialException missing => $"Missing credential: set {missing.Variable} in the container environment.",
        HttpRequestException { StatusCode: HttpStatusCode.Unauthorized } => "API returned HTTP 401: check the configured username, password, or API token.",
        HttpRequestException { StatusCode: HttpStatusCode.Forbidden } => "API returned HTTP 403: the configured credential lacks permission.",
        HttpRequestException { StatusCode: not null } http => $"API returned HTTP {(int)http.StatusCode.Value} ({http.StatusCode}).",
        HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError } => "TLS handshake or certificate validation failed. Check the certificate setting and server TLS support.",
        HttpRequestException { HttpRequestError: HttpRequestError.NameResolutionError } => "Host name could not be resolved.",
        HttpRequestException { HttpRequestError: HttpRequestError.ConnectionError } => "Could not connect to the configured host and port.",
        OperationCanceledException => "API request timed out.",
        JsonException => "API response was not valid JSON.",
        _ => "API configuration or response could not be read."
    };
}
