# GJNET

A personal, internally hosted network dashboard in C# / .NET 10 / Blazor Server. Public source, private network configuration. No cloud service, external fonts, default password, sample live statuses, or Docker socket mount.

## Current features

- Password-only owner access with persistent cookie keys, CSRF protection, and login rate limiting.
- Guest landing pages selected by IPv4 subnet. Most specific rule wins, then document order. Unmatched clients see no shared links. Only explicitly assigned shortcuts are public; notes and inventory stay private.
- Add, edit, delete, and group shortcuts; notes on links and devices. Rename or remove sections through configuration (sections are shortcut group names).
- Proxmox node and VM/LXC state through cluster resources; management link to the cluster console.
- Dockhand environments (including Hawser), container states, images, stack labels, health strings, and published TCP ports. Per-environment host overrides support Hawser edge and local socket environments whose actual address is not exposed by Dockhand.
- iDRAC Redfish system model, serial, health, power, and management links.
- Manual Windows, firewall, switch/AP, and embedded-device inventory with ICMP/TCP reachability. Explicit /24-or-smaller IPv4 ICMP discovery. Native Windows, OPNsense, UniFi, and embedded telemetry adapters remain future work.
- Polls every 60 seconds; private page refreshes its snapshot every 10 seconds. Results show check time and become stale after three minutes. Unknown API status is never reported as down. Reachability does not imply application health.
- Authenticated stateless MCP endpoint with inventory read, shortcut upsert, and shortcut removal. No infrastructure power/start/stop controls.
- Automatic private dashboard discovery with live HTTP status, persistent identities, VM guest-address lookup, Nginx Proxy Manager routes, and tracking across Docker rebuilds and changed published ports.

## Automatic service discovery

Discovery is enabled by default. Each polling cycle checks published container ports, declared dashboard URLs, existing shortcuts, and previously discovered interfaces. Every five minutes it also probes a configurable list of common web ports on known Docker hosts and running VM addresses. Proxmox guest network lookup uses the read-only QEMU guest-agent or LXC interfaces endpoint; absent guest-agent access does not break VM state polling. Native VM discovery needs guest network information or an explicit host override.

The owner dashboard shows new interfaces under **Discovered dashboards**. HTML interfaces, HTTP login pages, and redirects are recognized; ordinary JSON APIs and raw TCP listeners do not create dashboard cards. Probes use bounded concurrency, short timeouts, a 64 KiB response limit, no cookies, no upstream credentials, and no redirect following. HTTP/HTTPS fallback handles unusual homelab ports. Integration certificate-validation settings also apply to discovered interfaces.

Docker identities use environment + Compose project/service/replica + private port, falling back to container name when Compose labels are absent. Recreated container IDs and changed published ports update existing entries. Native interfaces use VM identity + port. A different native listen port creates a new entry; the previous one remains unavailable until hidden. VM address changes follow guest-agent data. Custom/reverse-proxy paths are retained on bound shortcuts.

Existing curated shortcuts acquire live status. When their host/port matches a discovery candidate, their displayed URL follows that service without changing the saved shortcut name, section, notes, or guest-page URL. Editing a shortcut's configured URL replaces that automatic binding. Hostname aliases continue to resolve through DNS. Unavailable, stopped, missing, and unknown are distinct: an upstream inventory failure retains last-known interfaces as unknown rather than deleting them. Hidden choices and the last catalog persist in `/data/discovered-services.json`; results older than three minutes show stale. Discovered services are never added to guest pages.

Pin an automatic entry to give it a custom shortcut name and section; hide unwanted entries and use **Show hidden services** to restore them. Search matches curated shortcuts, automatic dashboards, and inventory. Discovery does not start containers/VMs, run SSH commands, or mutate upstream configuration.

Optional private configuration (omit `vmPorts` to use the built-in list):

```json
"discovery": {
  "enabled": true,
  "scanIntervalSeconds": 300,
  "readProxyHosts": true,
  "vmHosts": { "pve:qemu/101": ["192.0.2.20"] }
}
```

`vmHosts` keys are observation `sourceKey` values returned by MCP. Entries override guest-provided addresses; they need updating when a VM without a guest agent changes address. `vmPorts` accepts at most 64 ports. An empty list disables new common-port sweeps; saved interfaces and shortcuts continue being checked. Discovery only visits configured/observed hosts; IPv4 subnet ICMP discovery remains separate and does not trigger broad web scanning.

Nginx Proxy Manager route discovery reads only `/data/nginx/proxy_host/<number>.conf` through Dockhand's GET file APIs. Dockhand currently requires its container file-read/exec permission for those reads. A denied or timed-out read leaves prior routes unknown and exposes a diagnostic on that container; it does not block container inventory. Set `readProxyHosts` false to disable route reads. Other reverse proxies can advertise dashboards using `gjnet.url` or `homepage.href` container labels. `gjnet.discover=false` suppresses that container's metadata candidates. Common-host port sweeps are independent of labels; control those using `vmPorts`.

## Local development

Install the .NET 10 SDK. In PowerShell:

```powershell
$env:DashboardPassword = 'your-long-private-password'
$env:McpToken = 'a-separate-long-random-token'
dotnet run --no-launch-profile --urls http://127.0.0.1:5080
```

Open `/login`, then `/settings`. Copy and customize `examples/inventory.example.json` in the configuration editor, or add shortcuts from the dashboard. The initial inventory is empty. Set discovery targets yourself; no networks are scanned by default. Runtime configuration and auth keys are stored in `data/` (ignored by Git).

Credentials are referenced by environment-variable name, never stored in inventory. Supply `PROXMOX_TOKEN` (value `user@realm!token=secret`), `DOCKHAND_TOKEN`, and separate `SERVER2_IDRAC_PASSWORD` / `SERVER3_IDRAC_PASSWORD` values as appropriate. The Docker Compose file forwards both iDRAC credentials into the app container. Use read-only monitoring credentials.

HTTPS integration polling accepts self-signed certificates by default. Set `"validateTlsCertificate": true` on an individual integration to enforce certificate trust, expiry, and host-name checks. Omitted or false keeps certificate checks off for that integration; HTTPS still encrypts the connection. Existing inventories use the same default automatically. Request failures distinguish missing credentials, HTTP authentication/permission errors, TLS errors, and connectivity failures.

## Docker / Dockhand Git stack

The Compose file contains JSON syntax (valid YAML 1.2), while keeping Dockhand's required `compose.yaml` filename:

```powershell
Copy-Item .env.example .env
# Edit .env privately, then:
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d --build
```

Create a Dockhand Git stack pointing at your public GitHub repository, choose `compose.yaml` as the compose path, supply private environment overrides, and enable Git auto-sync with rebuilding. Keep the `gjnet-data` named volume across deployments. Default binding is loopback; set `GJNET_BIND` to the Docker host's LAN address to expose it internally. Do not publish it through your WAN firewall. Use HTTPS through your internal reverse proxy for password and token traffic.

When proxying, set `GJNET_TRUSTED_PROXIES` to a comma-separated list of **exact proxy IP addresses**, configure the proxy to overwrite forwarded headers, and prevent direct access that bypasses it. Otherwise guest routing uses the socket's actual client IP. NAT may hide the originating subnet. This initial version accepts one forwarded hop; do not enable blanket forwarded-header trust. Docker Desktop may hide source addresses; verify guest selection from real clients after deployment.

`/healthz` checks app availability, not upstream integration health. After each Git deployment, verify the rebuilt container revision, persistent volume, app health, and real API observations. The development checks run without a Docker daemon; live container verification is a separate deployment step.

Configure `hostAddresses` on a Dockhand integration as an environment-ID-to-address object, for example `{"1":"192.0.2.20","2":"192.0.2.21"}`. Without an override, advertised Dockhand `publicIp` values supply Hawser host addresses, and local socket environments use the Dockhand URL hostname. The `edge-agent` marker is never treated as an address. Missing host addresses suppress port links. Duplicate IPv4/IPv6 port mappings produce one link. Loopback bindings and UDP ports are omitted. HTTP is assumed except ports 443/8006; arbitrary published TCP ports might not run a web interface. Add manual shortcuts to override protocol/path. Empty Dockhand container responses produce unknown host state because Dockhand can hide connection failures as empty arrays.

## MCP

Use the internally reachable `/mcp` URL with `Authorization: Bearer <McpToken>`. The endpoint returns JSON responses over Streamable HTTP with protocol version `2025-03-26`, no sessions, and no SSE stream (GET returns 405). It supports initialize, initialized notifications, ping, tools/list, and tools/call. Token access grants private inventory reading and shortcut mutation; use a separate secret from the dashboard password. Browser Origin requests are rejected. An unset token disables access. No OAuth discovery or legacy SSE transport is provided. Client interoperability needs verification with your chosen MCP client after deployment.

Tools: `get_inventory`, `upsert_shortcut` (id, section, name, url, optional notes), `remove_shortcut` (id), and `configure_discovery` (optional enabled, scanIntervalSeconds, vmPorts, vmHosts, readProxyHosts). `get_inventory` includes the discovered catalog and effective URLs/statuses in `services`. Discovery configuration updates preserve omitted settings and merge supplied `vmHosts` entries by source ID. Token access also grants these private discovery configuration changes. Deleting a shortcut also removes guest-page references. Upserting does not publish it to a guest page.

## Verification

```powershell
dotnet build -c Release
dotnet run --project tests/GJNET.Checks
dotnet publish GJNET.csproj -c Release -o data/publish-check
dotnet run --project tests/GJNET.Checks -- --published data/publish-check
git diff --check
```

The C# checks cover subnet precedence and isolation, persistence, validation, mocked API responses and failure status, published-port mappings, login/CSRF/private-route isolation, and MCP authorization/mutations. They require no access to your actual network.

The published check follows the script URL emitted by the actual HTML, including fingerprinted names. The Docker build restores after copying Razor components, because .NET 10 omits its framework-asset dependency when no Razor files exist at restore time. The build also requires the published Blazor script to exist before producing an image.

Browser verification also covered login, interactive shortcut creation/editing, and persistence after reload. The container installs `iputils-ping` for unprivileged .NET ICMP probes; actual container networking still needs live verification. Linux ping behavior follows [Microsoft's guidance](https://learn.microsoft.com/en-us/dotnet/core/compatibility/networking/7.0/ping-custom-payload-linux).

API references: [Proxmox API](https://pve.proxmox.com/wiki/Proxmox_VE_API), [Dockhand manual](https://dockhand.pro/manual/), [Dockhand container adapter](https://github.com/Finsys/dockhand/blob/main/src/lib/server/docker.ts), [Redfish](https://www.dmtf.org/standards/redfish), [MCP HTTP transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports).

Before publishing, review staged files; never commit `.env`, `data/`, logs, credentials, or private configuration.
