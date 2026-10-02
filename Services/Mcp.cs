using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace GJNET.Services;

public static class Mcp
{
    public static async Task<IResult> Handle(HttpContext context, IConfiguration config, InventoryStore store, Poller poller)
    {
        var expected = config["McpToken"]; var supplied = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(expected) || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes("Bearer " + expected)), SHA256.HashData(Encoding.UTF8.GetBytes(supplied)))) return Results.Unauthorized();
        if (context.Request.Headers.ContainsKey("Origin")) return Results.StatusCode(403);
        if (context.Request.Method == "GET") return Results.StatusCode(405);
        if (context.Request.ContentLength > 1048576) return Results.StatusCode(413);
        JsonDocument doc;
        try { doc = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted); } catch (JsonException) { return Results.Json(new { jsonrpc = "2.0", id = (object?)null, error = new { code = -32700, message = "Parse error" } }); }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || Poller.Text(root, "jsonrpc") != "2.0") return Results.Json(new { jsonrpc = "2.0", id = (object?)null, error = new { code = -32600, message = "Invalid request" } });
            var hasId = root.TryGetProperty("id", out var id); if (!hasId) return Results.Accepted();
            id = id.Clone();
            IResult Reply(object result) => Results.Json(new { jsonrpc = "2.0", id, result });
            IResult Error(int code, string message) => Results.Json(new { jsonrpc = "2.0", id, error = new { code, message } });
            switch (Poller.Text(root, "method"))
            {
                case "initialize": return Reply(new { protocolVersion = "2025-03-26", capabilities = new { tools = new { } }, serverInfo = new { name = "GJNET", version = "0.1.0" } });
                case "ping": return Reply(new { });
                case "tools/list":
                    return Reply(new
                    {
                        tools = new object[]{
                    new {name="get_inventory",description="Read private inventory, shortcuts, guest routing, and current observations. No credentials are returned.",inputSchema=new {type="object",properties=new {},additionalProperties=false}},
                    new {name="upsert_shortcut",description="Add or update one shortcut. Guest visibility is unchanged. HTTP(S) links only.",inputSchema=new {type="object",properties=new {id=new {type="string"},section=new {type="string"},name=new {type="string"},url=new {type="string"},notes=new {type="string"}},required=new[]{"id","section","name","url"},additionalProperties=false}},
                    new {name="remove_shortcut",description="Delete a shortcut and remove its guest-page references.",inputSchema=new {type="object",properties=new {id=new {type="string"}},required=new[]{"id"},additionalProperties=false}}
                }
                    });
                case "tools/call":
                    try
                    {
                        var p = root.GetProperty("params"); var name = Poller.Text(p, "name"); object value;
                        if (name == "get_inventory") value = new { settings = store.Read(), observations = poller.Read(), lastPoll = poller.LastPoll };
                        else
                        {
                            var args = p.GetProperty("arguments"); var shortcutId = args.GetProperty("id").GetString()!;
                            if (string.IsNullOrWhiteSpace(shortcutId)) throw new ArgumentException("ID is required");
                            // Each mutation reads and writes within the same store lock to avoid lost updates.
                            if (name == "upsert_shortcut") store.Update(s =>
                            {
                                var item = new Shortcut(shortcutId, args.GetProperty("section").GetString()!, args.GetProperty("name").GetString()!, args.GetProperty("url").GetString()!, Poller.Text(args, "notes"));
                                s.Shortcuts.RemoveAll(x => x.Id == shortcutId); s.Shortcuts.Add(item); return s;
                            });
                            else if (name == "remove_shortcut") store.Update(s => { s.Shortcuts.RemoveAll(x => x.Id == shortcutId); return s with { GuestPages = s.GuestPages.Select(g => g with { ShortcutIds = g.ShortcutIds.Where(x => x != shortcutId).ToArray() }).ToList() }; });
                            else return Error(-32602, "Unknown tool");
                            value = new { saved = true };
                        }
                        return Reply(new { content = new[] { new { type = "text", text = JsonSerializer.Serialize(value, InventoryStore.Json) } } });
                    }
                    catch (Exception e) when (e is ArgumentException or JsonException or KeyNotFoundException or InvalidOperationException) { return Reply(new { isError = true, content = new[] { new { type = "text", text = "Invalid arguments. Supply all required fields and a valid HTTP(S) URL." } } }); }
                default: return Error(-32601, "Method not found");
            }
        }
    }
}
