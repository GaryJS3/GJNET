using System.Net;
using System.Text.Json;
namespace GJNET.Services;

public record Shortcut(string Id, string Section, string Name, string Url, string Notes = "");
public record GuestPage(string Name, string[] Subnets, string[] ShortcutIds);
public record Device(string Id, string Name, string Kind, string Address, int[] Ports, string Notes = "");
public record Integration(string Id, string Name, string Kind, string Url, string SecretEnvironmentVariable, string Username = "", string? HostAddress = null, Dictionary<string, string>? HostAddresses = null, bool ValidateTlsCertificate = false);
public record Settings(List<Shortcut> Shortcuts, List<GuestPage> GuestPages, List<Device> Devices, List<Integration> Integrations, List<string> ScanSubnets);
public record Observation(string Id, string Name, string Kind, string State, string Address, Dictionary<string, string> Details, List<string> Links, DateTimeOffset CheckedAt);
public class InventoryStore
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    readonly string path; readonly object gate = new(); Settings settings;
    public InventoryStore(IConfiguration config) { path = Path.Combine(config["DataPath"] ?? "data", "inventory.json"); settings = File.Exists(path) ? JsonSerializer.Deserialize<Settings>(File.ReadAllText(path), Json)! : new([], [], [], [], []); Validate(settings); }
    public Settings Read() { lock (gate) return JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(settings, Json), Json)!; }
    public void Update(Func<Settings, Settings> update) { lock (gate) Save(update(Read())); }
    public void Save(Settings value) { Validate(value); lock (gate) { var text = JsonSerializer.Serialize(value, Json); File.WriteAllText(path + ".tmp", text); File.Move(path + ".tmp", path, true); settings = JsonSerializer.Deserialize<Settings>(text, Json)!; } }
    public static bool WebUrl(string value) => Uri.TryCreate(value, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https") && string.IsNullOrEmpty(u.UserInfo);
    public static void Validate(Settings s)
    {
        if (s.Shortcuts is null || s.GuestPages is null || s.Devices is null || s.Integrations is null || s.ScanSubnets is null) throw new ArgumentException("All collections are required.");
        if (s.Shortcuts.Any(x => !WebUrl(x.Url))) throw new ArgumentException("Shortcut URLs must use HTTP(S) without credentials.");
        if (s.Shortcuts.Select(x => x.Id).Distinct().Count() != s.Shortcuts.Count) throw new ArgumentException("Shortcut IDs must be unique.");
        foreach (var g in s.GuestPages) { foreach (var n in g.Subnets) _ = Network(n); if (g.ShortcutIds.Any(id => !s.Shortcuts.Any(x => x.Id == id))) throw new ArgumentException("Guest shortcut ID does not exist."); }
        foreach (var n in s.ScanSubnets) { var (_, bits) = Network(n); if (bits < 24) throw new ArgumentException("Discovery is limited to /24 or smaller IPv4 networks."); }
        if (s.Devices.Any(x => x.Ports.Any(p => p < 1 || p > 65535) || Uri.CheckHostName(x.Address) == UriHostNameType.Unknown)) throw new ArgumentException("Device hostnames/IPs and valid ports are required.");
        if (s.Integrations.Any(x => (x.HostAddress is not null && Uri.CheckHostName(x.HostAddress) == UriHostNameType.Unknown) || (x.HostAddresses?.Values.Any(h => Uri.CheckHostName(h) == UriHostNameType.Unknown) ?? false))) throw new ArgumentException("Host overrides must be hostnames or IP addresses.");
        if (s.Integrations.Any(x => !WebUrl(x.Url) || !new[] { "proxmox", "redfish", "docker" }.Contains(x.Kind))) throw new ArgumentException("Integrations support proxmox, redfish, docker and HTTP(S) URLs.");
        if (s.Integrations.Select(x => x.Id).Distinct().Count() != s.Integrations.Count || s.Devices.Select(x => x.Id).Distinct().Count() != s.Devices.Count) throw new ArgumentException("Device and integration IDs must be unique.");
    }
    public static (uint Address, int Bits) Network(string cidr)
    {
        var p = cidr.Split('/'); if (p.Length != 2 || !IPAddress.TryParse(p[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || !int.TryParse(p[1], out var bits) || bits < 0 || bits > 32) throw new ArgumentException($"Invalid IPv4 subnet: {cidr}"); return (Number(ip), bits);
    }
    public static uint Number(IPAddress ip) { var b = ip.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
    public static bool Matches(IPAddress? ip, string subnet) { if (ip is null) return false; if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4(); if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false; var (n, b) = Network(subnet); uint mask = b == 0 ? 0 : uint.MaxValue << (32 - b); return (Number(ip) & mask) == (n & mask); }
    public GuestPage? Guest(IPAddress? ip) => Read().GuestPages.SelectMany(g => g.Subnets.Select(n => (Page: g, Subnet: n))).Where(x => Matches(ip, x.Subnet)).OrderByDescending(x => Network(x.Subnet).Bits).Select(x => x.Page).FirstOrDefault();
}
