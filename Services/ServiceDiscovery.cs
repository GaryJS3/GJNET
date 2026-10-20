using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace GJNET.Services;

public record DiscoveredService(string Id, string SourceId, string Scope, string SourceName, string Name, string Url,
    string State, string Title, DateTimeOffset CheckedAt, DateTimeOffset LastSeenAt, bool Hidden = false,
    string? ShortcutId = null, string? ConfiguredUrl = null, string? BoundEndpoint = null, bool ManualOverride = false);

public class ServiceDiscovery
{
    public static readonly int[] DefaultPorts = [80,443,3000,3001,3080,5000,6052,7778,7860,8000,8006,8080,8081,8122,8188,8200,8443,8768,8888,9000,9090,9443,11443];
    readonly InventoryStore store;
    readonly string path;
    readonly object gate = new();
    DiscoveredService[] snapshot;
    DateTimeOffset lastScan;
    public ServiceDiscovery(InventoryStore store, IConfiguration config)
    {
        this.store = store;
        path = Path.Combine(config["DataPath"] ?? "data", "discovered-services.json");
        snapshot = File.Exists(path) ? JsonSerializer.Deserialize<DiscoveredService[]>(File.ReadAllText(path), InventoryStore.Json) ?? [] : [];
    }
    public DiscoveredService[] Read() { lock (gate) return snapshot.ToArray(); }
    public void Hide(string id, bool hidden = true)
    {
        lock (gate) { snapshot = snapshot.Select(s => s.Id == id ? s with { Hidden = hidden } : s).ToArray(); Save(); }
    }
    void Save()
    {
        File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(snapshot, InventoryStore.Json));
        File.Move(path + ".tmp", path, true);
    }
    sealed record Target(string Id, string SourceId, string Scope, string SourceName, string Name, string Url,
        string SourceState, bool Strict, string? ShortcutId = null, string? ConfiguredUrl = null, string? BoundEndpoint = null, bool ManualOverride = false);
    sealed record Probe(bool Dashboard, string Url, string State, string Title);
    public async Task Refresh(Observation[] observations, CancellationToken token = default)
    {
        var settings = store.Read(); var options = settings.Discovery ?? new();
        if (!options.Enabled) return;
        var now = DateTimeOffset.UtcNow; var previous = Read().ToDictionary(s => s.Id);
        var sources = observations.Where(o => o.SourceKey is not null).GroupBy(o => o.SourceKey!).ToDictionary(g => g.Key, g => g.First());
        var healthyScopes = observations.Where(o => o.Scope is not null && (o.Kind == "vm" || o.Kind == "proxmox" || (o.Kind == "docker-host" && o.State == "reachable"))).Select(o => o.Scope!).ToHashSet();
        bool Strict(Observation o) => settings.Integrations.FirstOrDefault(i => o.Scope == i.Id || o.Scope?.StartsWith(i.Id + ":env:", StringComparison.Ordinal) == true)?.ValidateTlsCertificate ?? false;
        var targets = new Dictionary<string, Target>();
        foreach (var source in sources.Values)
            foreach (var endpoint in source.WebPorts ?? [])
            {
                var id = source.SourceKey + ":" + endpoint.Key;
                targets[id] = new(id, source.SourceKey!, source.Scope ?? "", source.Name, source.Name, endpoint.Url, source.State, Strict(source));
            }
        // Scan only known VM/Docker host addresses, never arbitrary subnets. New container ports are checked on every poll.
        var sweep = now - lastScan >= TimeSpan.FromSeconds(options.ScanIntervalSeconds);
        if (sweep)
        {
            foreach (var source in sources.Values.Where(o => o.Kind is "vm" or "docker-host" && o.State is "running" or "reachable"))
            {
                var hosts = options.VmHosts?.GetValueOrDefault(source.SourceKey!) ?? source.Details.GetValueOrDefault("addresses", "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (hosts.Length == 0 && source.Kind == "docker-host" && ValidHost(source.Address)) hosts = [source.Address];
                var candidates = hosts.Take(8).Where(ValidHost).ToArray();
                for (var hostIndex = 0; hostIndex < candidates.Length; hostIndex++)
                    foreach (var port in options.VmPorts ?? DefaultPorts)
                    {
                        var url = Poller.Link(candidates[hostIndex], port); var id = source.SourceKey + ":port:" + port + (hostIndex == 0 ? "" : ":address:" + hostIndex);
                        // Published Docker ports have a stronger identity (Compose service and private port).
                        if (targets.Values.Any(t => SameEndpoint(t.Url, url)) || observations.Where(o => o.Kind == "service").Any(o => o.Links.Any(link => SameEndpoint(link, url)))) continue;
                        targets.TryAdd(id, new(id, source.SourceKey!, source.Scope ?? "", source.Name, source.Name, url, source.State, Strict(source)));
                    }
            }
        }
        // Retest known endpoints between full sweeps and retain identity when metadata temporarily disappears.
        foreach (var old in previous.Values)
        {
            if (old.ShortcutId is null && !targets.ContainsKey(old.Id) && old.Id.Contains(":proxy:", StringComparison.Ordinal) && sources.TryGetValue(old.SourceId, out var proxy) && (!options.ReadProxyHosts || proxy.Details.ContainsKey("proxy discovery")))
                targets[old.Id] = new(old.Id, old.SourceId, old.Scope, proxy.Name, old.Name, old.Url, "unknown", Strict(proxy));
            var endpointId = old.ShortcutId is null ? old.Id : old.BoundEndpoint;
            if (endpointId is not null && !targets.ContainsKey(endpointId) && sources.TryGetValue(old.SourceId, out var source) && endpointId.StartsWith(old.SourceId + ":port:", StringComparison.Ordinal))
            {
                var hosts = options.VmHosts?.GetValueOrDefault(source.SourceKey!) ?? source.Details.GetValueOrDefault("addresses", "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (hosts.Length == 0 && source.Kind == "docker-host" && ValidHost(source.Address)) hosts = [source.Address];
                var indexMatch = Regex.Match(endpointId, @":address:(\d+)$");
                var addressIndex = indexMatch.Success ? int.Parse(indexMatch.Groups[1].Value) : 0;
                var host = hosts.Contains(new Uri(old.Url).Host) ? new Uri(old.Url).Host : hosts.Where(ValidHost).ElementAtOrDefault(addressIndex);
                var url = host is null ? old.Url : new UriBuilder(old.Url) { Host = host }.Uri.AbsoluteUri;
                var state = source.State is "running" or "reachable" && host is null ? "unknown" : source.State;
                targets[endpointId] = new(endpointId, old.SourceId, old.Scope, source.Name, source.Name, url, state, Strict(source));
            }
        }
        foreach (var shortcut in settings.Shortcuts)
        {
            var id = "shortcut:" + shortcut.Id; previous.TryGetValue(id, out var old);
            var manualOverride = old?.ManualOverride == true || old is not null && old.ConfiguredUrl != shortcut.Url;
            var bound = !manualOverride && old?.ConfiguredUrl == shortcut.Url && old.BoundEndpoint is not null ? targets.GetValueOrDefault(old.BoundEndpoint) : null;
            if (!manualOverride) bound ??= targets.Values.FirstOrDefault(t => t.ShortcutId is null && SameEndpoint(t.Url, shortcut.Url));
            var url = bound is null ? shortcut.Url : new UriBuilder(bound.Url) { Path = new Uri(shortcut.Url).AbsolutePath, Query = new Uri(shortcut.Url).Query.TrimStart('?'), Fragment = new Uri(shortcut.Url).Fragment.TrimStart('#') }.Uri.AbsoluteUri;
            var boundId = bound?.Id ?? (old?.ConfiguredUrl == shortcut.Url ? old.BoundEndpoint : null);
            var sourceId = bound?.SourceId ?? (boundId is not null ? old!.SourceId : id);
            var integrationExists = settings.Integrations.Any(i => old?.Scope == i.Id || old?.Scope.StartsWith(i.Id + ":env:", StringComparison.Ordinal) == true);
            var sourceState = bound?.SourceState ?? (boundId is null ? "running" : !integrationExists ? "removed" : sources.ContainsKey(sourceId) || healthyScopes.Contains(old?.Scope ?? "") ? "missing" : "unknown");
            var strictShortcut = settings.Integrations.FirstOrDefault(i => SameEndpoint(i.Url, shortcut.Url))?.ValidateTlsCertificate ?? false;
            targets[id] = new(id, sourceId, bound?.Scope ?? old?.Scope ?? "", bound?.SourceName ?? shortcut.Section, shortcut.Name, url, sourceState, bound?.Strict ?? strictShortcut, shortcut.Id, shortcut.Url, boundId, manualOverride);
        }
        using var permissiveHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        using var strictHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
        using var permissive = new HttpClient(permissiveHandler); using var strict = new HttpClient(strictHandler);
        var next = new System.Collections.Concurrent.ConcurrentDictionary<string, DiscoveredService>();
        var probes = new System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<Task<Probe>>>();
        await Parallel.ForEachAsync(targets.Values.OrderByDescending(t => t.ShortcutId is not null).Take(4096), new ParallelOptions { MaxDegreeOfParallelism = 24, CancellationToken = token }, async (target, ct) =>
        {
            previous.TryGetValue(target.Id, out var old);
            if (target.SourceState is not ("running" or "reachable" or "online"))
            {
                if (old is not null || target.ShortcutId is not null)
                    next[target.Id] = Make(target, old, target.SourceState is "stopped" or "exited" or "dead" or "created" ? "stopped" : target.SourceState is "missing" or "removed" ? target.SourceState : "unknown", old?.Title ?? "", target.Url, now, false);
                return;
            }
            var key = target.Strict + ":" + target.Url;
            var result = await probes.GetOrAdd(key, _ => new Lazy<Task<Probe>>(() => ProbeUrl(target.Url, target.Strict ? strict : permissive, ct))).Value;
            if (result.Dashboard || old is not null || target.ShortcutId is not null)
                next[target.Id] = Make(target, old, !result.Dashboard && result.State == "available" && target.ShortcutId is null ? "not a dashboard" : result.State, result.Title.Length > 0 ? result.Title : old?.Title ?? "", result.Url, now, result.Dashboard);
        });
        foreach (var old in previous.Values.Where(s => s.ShortcutId is null && !next.ContainsKey(s.Id)))
        {
            var state = !settings.Integrations.Any(i => old.Scope == i.Id || old.Scope.StartsWith(i.Id + ":env:", StringComparison.Ordinal)) ? "removed"
                : healthyScopes.Contains(old.Scope) ? "missing" : "unknown";
            next[old.Id] = old with { State = state, CheckedAt = now };
        }
        token.ThrowIfCancellationRequested();
        lock (gate)
        {
            // Preserve a Hide action that arrived while HTTP requests were in flight.
            var hidden = snapshot.ToDictionary(s => s.Id, s => s.Hidden);
            snapshot = next.Values.Select(s => s with { Hidden = hidden.GetValueOrDefault(s.Id, s.Hidden) }).OrderBy(s => s.Name).ThenBy(s => s.Id).ToArray();
            Save();
        }
        if (sweep) lastScan = now;
    }
    static DiscoveredService Make(Target t, DiscoveredService? old, string state, string title, string url, DateTimeOffset now, bool seen) =>
        new(t.Id, t.SourceId, t.Scope, t.SourceName, t.ShortcutId is null && title.Length > 0 ? title : t.Name, url, state, title, now, seen ? now : old?.LastSeenAt ?? now, old?.Hidden ?? false, t.ShortcutId, t.ConfiguredUrl, t.BoundEndpoint, t.ManualOverride);
    public static bool SameEndpoint(string a, string b) => Uri.TryCreate(a, UriKind.Absolute, out var left) && Uri.TryCreate(b, UriKind.Absolute, out var right) && left.Host.Equals(right.Host, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port;
    static bool ValidHost(string host) => Uri.CheckHostName(host) != UriHostNameType.Unknown && host != "edge-agent" && (!IPAddress.TryParse(host, out var ip) || (!ip.IsIPv6LinkLocal && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any)));
    static async Task<Probe> ProbeUrl(string url, HttpClient http, CancellationToken token)
    {
        if (!InventoryStore.WebUrl(url)) return new(false, url, "unavailable", "");
        var uri = new Uri(url);
        // A short TCP check avoids holding every sweep slot for non-HTTP/closed ports.
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            timeout.CancelAfter(TimeSpan.FromMilliseconds(650));
            try
            {
                var addresses = IPAddress.TryParse(uri.Host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(uri.Host, timeout.Token);
                var connected = false;
                foreach (var address in addresses.OrderBy(ip => ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1))
                {
                    using var tcp = new TcpClient(address.AddressFamily);
                    try { await tcp.ConnectAsync(address, uri.Port, timeout.Token); connected = true; break; }
                    catch (SocketException) { }
                }
                if (!connected) return new(false, url, "unavailable", "");
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException) { token.ThrowIfCancellationRequested(); return new(false, url, "unavailable", ""); }
        }
        var first = await Request(uri, http, token);
        if (first.State != "unavailable" && first.State != "http 400") return first;
        // HTTPS is not reliably identified by port number (including homelab port 8006).
        var alternate = new UriBuilder(uri) { Scheme = uri.Scheme == "https" ? "http" : "https", Port = uri.Port }.Uri;
        var second = await Request(alternate, http, token);
        return second.Dashboard ? second : first;
    }
    static async Task<Probe> Request(Uri uri, HttpClient http, CancellationToken token, int redirectsLeft = 2)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri); request.Headers.UserAgent.ParseAdd("GJNET-Discovery/1.0");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            var buffer = new byte[65536]; var length = 0;
            while (length < buffer.Length) { var n = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token); if (n == 0) break; length += n; }
            var body = System.Text.Encoding.UTF8.GetString(buffer, 0, length);
            var title = WebUtility.HtmlDecode(Regex.Match(body, @"<title\b[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline).Groups[1].Value);
            title = Regex.Replace(Regex.Replace(title, "<[^>]*>", ""), @"\s+", " ").Trim(); if (title.Length > 120) title = title[..120];
            var status = (int)response.StatusCode;
            var html = response.Content.Headers.ContentType?.MediaType == "text/html" || Regex.IsMatch(body, @"<!doctype\s+html|<html\b", RegexOptions.IgnoreCase);
            var redirect = status is >= 300 and < 400 && response.Headers.Location is { } location && (!location.IsAbsoluteUri || location.Scheme is "http" or "https");
            if (redirect && redirectsLeft > 0)
            {
                var destination = new Uri(uri, response.Headers.Location!);
                if (InventoryStore.WebUrl(destination.AbsoluteUri) && destination.Host.Equals(uri.Host, StringComparison.OrdinalIgnoreCase) && destination.Query.Length == 0)
                    return await Request(destination, http, token, redirectsLeft - 1);
            }
            return new((status is >= 200 and < 300 && html) || (status is 401 or 403 && html) || redirect, uri.AbsoluteUri,
                status is 401 or 403 ? "authentication required" : redirect ? "redirect" : status is >= 200 and < 300 ? "available" : "http " + status, title);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException)
        { token.ThrowIfCancellationRequested(); return new(false, uri.AbsoluteUri, "unavailable", ""); }
    }
}
