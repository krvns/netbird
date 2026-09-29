### 1. Executive Verdict: `HIGH RISK`

* **Rationale:** The repository contains legitimate, well-structured open-source overlay networking software without embedded malicious backdoors or obfuscated binary payloads. However, bare-metal local execution requires UID 0 (`root`) privileges and systematically mutates host-level network configurations (kernel routing tables, firewall rulesets, and DNS resolvers), while exposing remote-controlled attack surfaces including an embedded SSH server, management-triggered diagnostic bundle exfiltration, and auto-update binary execution.

---

### 2. Network Egress Inventory

| Destination Endpoint | Protocol / Transport | Trigger Condition | Payload Data & Serialization |
| :--- | :--- | :--- | :--- |
| `https://api.netbird.io:443` | HTTPS / gRPC over HTTP/2 | Default management endpoint contacted on `netbird up` / `login` | Protobuf (`SyncRequest`, `LoginRequest`). Serializes hardware serial numbers (`ioreg -l` / DMI), machine hostname, CPU core count, OS/kernel versions, all local IPv4/IPv6 CIDRs, all NIC MAC addresses (`client/system/network_addr.go`), and process/file presence posture verification results (`client/system/process.go`). |
| `https://app.netbird.io:443` | HTTPS | Interactive SSO login flow (`netbird login`) | OAuth2 / OIDC PKCE authentication requests and browser callback tokens. |
| `signal.netbird.io:10000` / `:443` | gRPC over TLS | Peer discovery during handshake negotiation | Protobuf signaling frames. Exposes WireGuard public keys and local/reflexive WebRTC ICE candidates (IP addresses and UDP ports). |
| `stun.netbird.io:3468` / `:443` / `:5555` | STUN over UDP | NAT traversal discovery | RFC 5389 STUN Binding Requests (no client authentication payload; reflects external public IP:port mapping). |
| `turn.netbird.io:443` / `stun.netbird.io:3468` | TURN over TLS / TCP / UDP | Fallback relay when direct peer P2P fails | Relayed WireGuard ciphertext packets between peer endpoints. |
| `https://relay.netbird.io:443` | NetBird Relay / WebSockets / TLS | Fallback overlay relay | WireGuard ciphertext frames encapsulated in NetBird relay datagrams. |
| `https://upload.debug.netbird.io:443` | HTTPS (GET presigned URL + PUT) | CLI invocation (`netbird debug bundle -U`) OR remote management dispatch (`JobRequest_Bundle`) | Formatted ZIP archive (`debug.go`) containing system routes (`routes.txt`), interface configurations (`interfaces.txt`), active firewall tables (`nftables.txt`/`iptables.txt`/`pf`), DNS resolver settings (`resolv.conf`, `scutil --dns`), system profile metrics, client logs (`client.log`), and raw network packet captures (`capture.pcap` if active). |
| `https://ingest.netbird.io:443` | HTTPS | Client metrics enabled via management OR `NB_METRICS_PUSH_ENABLED=true` | Gzip-compressed InfluxDB Line Protocol (`influxdb.go`) containing `deployment_type`, `version`, `os`, `arch`, `peer_id`, `connection_pair_id`, `connection_type`, and connection timing metrics (`signaling_to_connection_seconds`, `connection_to_wg_handshake_seconds`, `sync_duration`). Remote push config fetched from `https://ingest.netbird.io/config`. |
| `https://pkgs.netbird.io:443` | HTTPS | Background update check (30-minute interval) | HTTP GET queries to `https://pkgs.netbird.io/releases/latest/version` and architecture-specific paths (`/macos/arm64`, `/macos/amd64`). Sends User-Agent header `NetBird agent installer/<version>`. |
| `https://publickeys.netbird.io:443` | HTTPS | Auto-update verification | HTTP GET requests retrieving `revocation-list.json`, `revocation-list.json.sig`, and `artifact-key-pub.pem` for verifying update payloads. |
| `https://github.com/netbirdio/netbird/releases/download/...` | HTTPS | Auto-update artifact download | Binary installer payload download (`.pkg` on macOS, `.msi`/`.exe` on Windows). |

---

### 3. High-Severity Findings Table

| Severity | Audit Vector | File & Line | Code Snippet / Mechanism | Exploitation / Risk Analysis |
| :--- | :--- | :--- | :--- | :--- |
| **High** | Dynamic Execution / Supply Chain | [installer_run_darwin.go:148-155](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/client/internal/updater/installer/installer_run_darwin.go#L148-L155) | `exec.CommandContext(ctx, "installer", "-pkg", path, "-target", volume)` | Root daemon downloads remote `.pkg` files from GitHub and executes `/usr/sbin/installer -pkg` with root privileges. While cryptographically gated via embedded root certificates (`certs/root-pub.pem`), compromise of the signing key infrastructure allows full remote root execution on client endpoints. |
| **High** | Dynamic Execution / Privilege Escalation | [executor_unix.go:234-237](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/client/ssh/server/executor_unix.go#L234-L237) | `exec.CommandContext(ctx, config.Shell, "-c", config.Command)` | NetBird includes an embedded SSH server listening on port 22022. While privilege dropping (`setuid`/`setgid`) is enforced by default, enabling `--enable-ssh-root` allows authorized network peers (or compromised management control plane) to execute arbitrary commands as UID 0. |
| **High** | Data Exfiltration / Remote Control | [engine.go:1342-1361](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/client/internal/engine.go#L1342-L1361) | `case *mgmProto.JobRequest_Bundle: bundleResult, err := e.handleBundle(params.Bundle)` | The management server can remotely command the running root daemon to execute a debug bundle dump and exfiltrate host diagnostic data (routing tables, firewall rules, local interface IPs, and decrypted logs) to `upload.debug.netbird.io` without requiring local user confirmation. |
| **Med** | Egress / Host Fingerprinting | [info.go:47-64](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/client/system/info.go#L47-L64), [network_addr.go:10-42](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/client/system/network_addr.go#L10-L42), [process.go:44-68](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/client/system/process.go#L44-L68) | `NetworkAddresses: addrs, SystemSerialNumber: si.SystemSerialNumber ... checkFileAndProcess(ctx, processCheckPaths)` | The client continuously queries system identifiers (hardware serial number via `ioreg -l`, physical MAC addresses of all interfaces, active local IP prefixes) and verifies the existence of arbitrary files and running process paths commanded by the management server for posture checks. |
| **Med** | Supply Chain Integrity | [go.mod:338-347](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/go.mod#L338-L347) | `replace github.com/kardianos/service => github.com/netbirdio/service ... replace golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go ...` | Replaces 9 core upstream dependencies (`wireguard-go`, `pion/ice`, `dex`, `service`, `systray`, `wails/v3`, `circl`, `easyjson`) with custom forks hosted under `github.com/netbirdio/`. Bypasses upstream supply-chain integrity controls and ties security strictly to fork maintainers. |
| **Med** | Blind Pipeline Execution | [README.md:101](file:///Users/pavkry/Documents/_projects/git/hub/krvns/netbird/README.md#L101) | `curl -fsSL https://github.com/netbirdio/netbird/releases/latest/download/getting-started.sh \| bash` | Documentation instructs users to pipe unhashed remote shell scripts directly into `bash` for deployment, leaving systems vulnerable to CDN manipulation, MITM, or repository takeover. |

---

### 4. Filesystem & System Footprint

#### A. Filesystem Paths Modified Outside Repository Root
* **Configuration:** `/etc/netbird/config.json` (macOS/Linux), `/var/db/netbird/config.json` (FreeBSD), `%PROGRAMDATA%\Netbird\config.json` (Windows).
* **State & Databases:** `/var/lib/netbird/` (daemon state files, DNS recovery state), `/var/db/netbird/` (FreeBSD), `%PROGRAMDATA%\Netbird\` (Windows).
* **IPC Control Sockets:** `/var/run/netbird.sock` (UNIX domain socket, mode 0660 or 0600), `\\.\pipe\netbird` (Windows Named Pipe).
* **System Logging:** `/var/log/netbird/client.log`, `/var/log/netbird/netbird.out`, `/var/log/netbird/netbird.err`, `%PROGRAMDATA%\Netbird\client.log`.
* **Temporary Directories:** `/var/lib/netbird/tmp-install/`, `%PROGRAMDATA%\Netbird\tmp-install\`.
* **Operating System Networking State:**
  * Network Interfaces: Creates virtual network interfaces (`wt0`, `utunX`).
  * Routing Tables: Modifies kernel routing entries via netlink (`ip route`) or BSD `route`.
  * Packet Filters: Installs NetBird filter chains in `nftables`, `iptables`, macOS `pf`, or Windows Filtering Platform (WFP).
  * Host Resolver: Modifies `/etc/resolv.conf`, sends D-Bus commands to `systemd-resolved`, sets macOS DynamicStore DNS keys (`scutil --dns`), or provisions Windows Name Resolution Policy Table (NRPT) rules.

#### B. Subprocesses Spawned
* **macOS:** `/usr/sbin/ioreg`, `sw_vers`, `ifconfig`, `route`, `stat -f %Su /dev/console`, `launchctl asuser <uid> sudo -u <user> -H open -a /Applications/NetBird.app`, `/usr/sbin/installer`, `sudo -u <user> /path/to/brew`.
* **Linux:** `iptables`, `iptables-save`, `ip6tables`, `nft`, `ipset`, `firewall-cmd`, `su`, `login`, `pkexec`.
* **Windows:** `netsh`, `powershell.exe`.
* **Internal Spawn:** `netbird ssh exec --uid <uid> --gid <gid> --shell <shell> --cmd <cmd>` for SSH session privilege separation.

#### C. Primary Environment Variables Read
* **Daemon Configuration:** `NB_CONFIG`, `NB_STATE_DIR`, `NB_DAEMON_ADDR`, `NB_LOG_FILE`, `NB_LOG_LEVEL`, `NB_MANAGEMENT_URL`, `NB_ADMIN_URL`.
* **Networking Controls:** `NB_USE_NETSTACK_MODE`, `NB_ENABLE_NETSTACK_LOCAL_FORWARDING`, `NB_DISABLE_DNS`, `NB_DISABLE_FIREWALL`, `NB_WG_KERNEL_DISABLED`, `NB_FORCE_USERS_FIREWALL`, `NB_DISABLE_ROUTE_CACHE`, `NB_DNS_STATE_FILE`.
* **Telemetry & Metrics:** `NB_METRICS_PUSH_ENABLED`, `NB_METRICS_CONFIG_URL`, `NB_METRICS_SERVER_URL`, `NB_METRICS_INTERVAL`, `NB_METRICS_FORCE_SENDING`.
* **Auto-Update & Testing:** `NB_AUTO_UPDATE_DRY_RUN`, `NB_ENABLE_CAPTURE`, `DOCKER_CI`, `DOCKER_HOST`, `PRIV_PKGS`, `PRIV_RUN`.

---

### 5. Runtime Isolation Prescription

Depending on your security boundary and networking requirements, select one of the following containment tiers:

#### Tier 1: Zero-Trust Host Isolation (Rootless Netstack Container - Recommended)
Runs completely unprivileged without `root`, without host capabilities, without `/dev/net/tun`, and without touching host routing tables or `/etc/resolv.conf`. All WireGuard encapsulation and TCP/UDP routing happen strictly in userspace via gVisor netstack.

```bash
docker run --rm -it \
  --name netbird-isolated \
  --user 10001:10001 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /var/lib/netbird:rw,noexec,nosuid,size=128m \
  -e NB_USE_NETSTACK_MODE=true \
  -e NB_DISABLE_DNS=true \
  -e NB_METRICS_PUSH_ENABLED=false \
  -e NB_MANAGEMENT_URL="https://api.netbird.io:443" \
  -e NB_SETUP_KEY="<YOUR_SETUP_KEY>" \
  netbirdio/netbird:latest
```

#### Tier 2: Isolated Development VM (For Testing Host Integration / TUN / Routing)
If evaluating host integration (TUN devices, firewall rule manipulation, or DNS management), do **not** run on your workstation:
* Deploy a disposable, ephemeral virtual machine (e.g., Lima on macOS or Vagrant/QEMU on Linux).
* Take a snapshot prior to executing `sudo ./client/netbird up`.
* Always teardown via `sudo ./client/netbird down` to revert firewall and DNS table alterations before discarding the VM.