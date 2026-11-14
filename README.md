# Wazuh in Docker over Tailscale, with Ansible

Deploys a hardened single-node **Wazuh 4.14.8** stack (manager, indexer, dashboard) in Docker on an
existing Ubuntu/Debian VM, enrolls agents on LAN and tailnet hosts, and can optionally serve a
read-only MCP endpoint over the tailnet for local LLM clients.

| What | Where it listens | How you reach it |
|---|---|---|
| Dashboard | `127.0.0.1:5601` | `https://<magicdns-name>` via `tailscale serve` (valid certificate) |
| Agent traffic (1514) and enrollment (1515) | server LAN IP and Tailscale IP | agents connect directly |
| Syslog 514/udp (optional) | server LAN IP | `wazuh_enable_syslog: true` |
| Manager API (55000), indexer (9200) | not published | only inside the Docker network |
| MCP endpoint (optional) | `127.0.0.1:3000` | `https://<magicdns-name>:8443/mcp` via `tailscale serve` |

There is no nginx or other reverse proxy: Tailscale provides identity, TLS and ACLs.

`IMPLEMENTATION_PLAN.md` is the design this repo implements. `VERIFY.md` lists the checks to run
after deploying.

## How it works

- Upstream [`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker) is cloned at
  `v{{ wazuh_version }}` into `/opt/wazuh/wazuh-docker` and **never edited** (re-runs reset it).
- Everything this repo owns lives in `/opt/wazuh/deploy/`: rendered config, rule files,
  `authd.pass`, and `docker-compose.override.yml`. Compose runs with upstream's file plus the override.
- The override replaces every published port (`ports: !override`, Compose ≥ 2.24), swaps in the
  vault passwords, sets the indexer heap, and remounts the config files.
- Secrets come only from an `ansible-vault` file. The playbook refuses to run if a secret is
  missing or still equals an upstream default.
- ISM policies delete `wazuh-alerts-*` indices after `wazuh_retention_days` (90) and
  `wazuh-archives-*` after `wazuh_archives_retention_days` (30). Archives are only written if you
  turn on `logall_json`, but they grow far faster than alerts, so their policy is in place first.

## Prerequisites

Control node:

- Ansible (ansible-core ≥ 2.16) and this repo.
- `ansible-galaxy collection install -r requirements.yml`

Wazuh server (built by you, not by this repo):

- Ubuntu 22.04/24.04 or Debian 12/13. Sized for 4 vCPU / 16 GB RAM / 256 GB disk.
- Tailscale installed and enrolled, HTTPS certificates enabled for the tailnet.
- A user Ansible can SSH in as, with sudo.

## Deploy: checklist in run order

Steps marked 🧑 are manual.

1. 🧑 **Build the VM.** Proxmox: 4 vCPU, 16 GB, 256 GB thin disk on the SSD lvm-thin pool, VirtIO
   SCSI single, IO thread on, cache none, Discard on; Ubuntu 24.04 on ext4.
   - After install, run `sudo vgs`. If space is unallocated:
     `sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv`.
   - `sudo systemctl enable --now fstrim.timer`, install `qemu-guest-agent`, and enable the QEMU
     Guest Agent option in Proxmox.
   - Take a Proxmox snapshot before the first playbook run.
2. 🧑 **Enroll the server in Tailscale** with a tagged, pre-authorized auth key:
   ```
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up --authkey=<key> --advertise-tags=tag:wazuh
   ```
   Note its `100.x` address and MagicDNS name. In the admin console turn on **DNS → HTTPS
   Certificates**. The certificate puts the machine's MagicDNS name in public Certificate
   Transparency logs, so pick a hostname you don't mind being visible.
3. 🧑 **Tailscale policy.** Merge `tailscale/acl-snippet.hujson` into the tailnet policy file
   (review it against your existing rules first: a bad policy can lock you out), and tag every
   tailnet host that will run an agent with `tag:wazuh-agent`. Remove or narrow the default
   allow-all rule, or the snippet restricts nothing. See [Tailscale ACLs](#tailscale-acls).
4. 🧑 **Secrets.** Choose passwords, then generate bcrypt hashes for the indexer `admin` and
   `kibanaserver` passwords (run once per password):
   ```
   docker run --rm -it wazuh/wazuh-indexer:4.14.8 \
     bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
   ```
   - Indexer passwords: at least 8 characters with upper, lower, digit and symbol.
   - API password: 8–64 characters with upper, lower, digit and symbol.
   ```
   cp inventory/group_vars/vault.example.yml inventory/group_vars/vault.yml
   $EDITOR inventory/group_vars/vault.yml
   ansible-vault encrypt inventory/group_vars/vault.yml
   ```
   **Never commit the unencrypted file.** `vault.yml` is git-ignored as a safeguard. Keep the
   vault password somewhere outside the VM: a restore needs it.
5. 🧑 **Inventory.**
   ```
   cp inventory/hosts.example.yml inventory/hosts.yml
   ```
   Fill in the hosts, then set in `inventory/group_vars/`:
   - `all.yml`: `wazuh_server_magicdns`, `wazuh_bind_lan_ip`
   - `wazuh_server.yml`: `wazuh_bind_ts_ip` (must be inside `100.64.0.0/10`)
6. 🧑 **Windows hosts** (if any): enable OpenSSH Server or WinRM and put the credentials in the
   vault. See [Windows agents](#windows-agents).
7. 🧑 **Old data.** This deploys a fresh install. If a 4.7 deployment's data must be kept, stop
   here: migration is not covered.
8. **Run it**, then work through `VERIFY.md`:
   ```
   ansible-galaxy collection install -r requirements.yml
   ansible wazuh_server -m ansible.builtin.ping
   ansible-playbook playbooks/site.yml --ask-vault-pass
   ```
   `playbooks/server.yml` and `playbooks/agents.yml` can also be run on their own.
9. 🧑 After about a week, review the 60107 noisy-process list ([Local rules](#local-rules)).
10. 🧑 Set up the nightly Proxmox vzdump job ([Backups and upgrades](#backups-and-upgrades)).
11. 🧑 *(MCP, optional)* Generate and vault the four MCP secrets, decide how the clients connect,
    then set `wazuh_mcp_enabled: true` ([MCP endpoint](#mcp-endpoint-optional)).
12. 🧑 *(MCP, optional)* Run `sudo scripts/mcp-log-samples.sh` on the Wazuh host to confirm the
    provisional MCP rules against real log lines.

## Tailscale ACLs

`tailscale/acl-snippet.hujson` contains entries to merge into your policy file:

- `tag:wazuh-agent` → `tag:wazuh` on `tcp:1514` and `tcp:1515`
- your admin devices → `tag:wazuh` on `tcp:443` (and `tcp:22` unless you use Tailscale SSH)
- `tag:wazuh-mcp-client` → `tag:wazuh` on `tcp:8443` (MCP only)
- an optional `ssh` block for Tailscale SSH as the deploy user

**Tailnet agent hosts must carry `tag:wazuh-agent`**, or the grant does not apply and the agent
cannot reach the manager:

```
sudo tailscale up --advertise-tags=tag:wazuh-agent
```

Tagging a device removes its user ownership. LAN agents talk to the server's LAN IP directly and
need no tag; a LAN device that must reach the server from elsewhere needs a subnet router, which
this repo does not set up.

The snippet uses `autogroup:admin` and `"deploy"` as placeholders. Replace them before pasting.

> **Remove the default allow-all rule.** The snippet only *adds* grants. Tailscale's default
> policy contains an allow-all grant (`"src": ["*"], "dst": ["*"], "ip": ["*"]`, or `"*:*"` in an
> older `acls` section); while it is there, every tailnet device can reach 1514/1515, the dashboard
> and the MCP endpoint, and the snippet restricts nothing. Delete or narrow it when you merge,
> after adding grants for anything else on the tailnet that depended on it. Then check from a
> device that should *not* have access (see [VERIFY.md](VERIFY.md), Phase 5/7).

## Agents

### Add an agent

1. Add the host to `inventory/hosts.yml` under `agents_tailnet`, `agents_lan` or `agents_windows`.
2. For a tailnet host, tag it `tag:wazuh-agent`.
3. `ansible-playbook playbooks/agents.yml --ask-vault-pass --limit <host>`

| Inventory group | Manager address | Wazuh group |
|---|---|---|
| `agents_tailnet` | `wazuh_server_magicdns` | `tailnet` |
| `agents_lan` | `wazuh_bind_lan_ip` | `lan` |
| `agents_windows` | `wazuh_bind_lan_ip` (override per host) | `windows` |
| the Wazuh server itself | `wazuh_bind_lan_ip` | `wazuh-host` |

The agent package is pinned to `wazuh_version` and held (`dpkg hold` on Debian/Ubuntu; on
RHEL-family the Wazuh repo is left disabled), so an OS upgrade cannot move an agent ahead of the
manager. A host that already has a non-empty `client.keys` is not re-registered.

### Windows agents

The role downloads the 4.14.8 MSI and installs it with `win_package` (no Chocolatey).

- **OpenSSH (default).** Enable *OpenSSH Server* on the host and add your key to
  `administrators_authorized_keys`. `agents_windows.yml` sets `ansible_shell_type: powershell`,
  so make PowerShell the SSH default shell, or change the variable to `cmd`.
- **WinRM.** Uncomment the WinRM block in `inventory/group_vars/agents_windows.yml`, install
  `pywinrm` on the control node, and put the password in the vault.

The Windows audit policy drives the volume of event 60107; choosing it is up to you.

### The agent on the Wazuh host

With `wazuh_host_agent_enabled: true` (default), the server also runs an ordinary agent named
`<inventory_hostname>-host` in group `wazuh-host`. The manager's built-in agent 000 only sees
inside its container; this one gives the Docker host itself FIM, SCA and auth-log monitoring, plus:

- **Disk usage.** `df -P /` every 5 minutes. Rule 100110 (level 7) fires at ≥ 80% and 100111
  (level 12) at ≥ 90%. The indexer goes read-only at its 95% flood-stage watermark. The command is
  in the agent's own `ossec.conf` (`wazuh_agent_local_commands`), not the group's `agent.conf`:
  `logcollector.remote_commands` stays off on every agent, because it would let anyone who
  controls the manager (or a dashboard admin) run commands as root on the agent's host.
- **MCP container logs**, when the MCP endpoint is enabled.

## Local rules

`roles/wazuh_server/templates/local_rules.xml.j2` holds rule 100008, which quietens Windows event
60107 for a list of noisy processes. The list is `wazuh_60107_noisy_processes`:

```yaml
wazuh_60107_noisy_processes:
  - 1Password.exe
  - msedge.exe
  - chrome.exe
  - RuntimeBroker.exe
```

`lsass.exe`, `svchost.exe` and `explorer.exe` were removed from the old list: excluding them hides
credential-theft signals. Don't add them back.

## Demo indexer users

Upstream's `internal_users.yml` ships demo users (`kibanaro`, `logstash`, `readall`,
`snapshotrestore`) whose passwords are public, and who could log in to the dashboard. They are
**removed by default** (`wazuh_indexer_remove_demo_users: true`); `admin` and `kibanaserver` get
their hashes from the vault and the rest of upstream's file is unchanged. Set the variable to
`false` to keep upstream's file as is.

On a fresh install the security index is created without them. On a stack that was already
deployed with them, they stay in the security index until `securityadmin.sh` is re-run
(see `roles/wazuh_server/tasks/stack.yml` for the command).

## MCP endpoint (optional)

`wazuh_mcp_enabled: true` adds
[`gensecaihq/Wazuh-MCP-Server`](https://github.com/gensecaihq/Wazuh-MCP-Server) `5.0.0` as a fourth
container in the same Compose project. It is read-only and tailnet-only.

- It reaches `wazuh.manager:55000` and `wazuh.indexer:9200` over the internal Docker network, so
  neither port is published.
- It uses two least-privilege accounts that Ansible creates: a manager API user `mcp-readonly`
  (read actions only, no `active-response:command` or `agent:restart`) and an indexer user
  `mcp-readonly` (`read`/`search` on `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`).
- `tailscale serve` terminates TLS on 8443. Funnel is never enabled.
- **Compatibility is not confirmed.** Upstream supports Wazuh 4.8.0–4.14.7 and this repo deploys
  4.14.8. The smoke test in `VERIFY.md` is what confirms it.
- **TLS inside the Docker network.** The indexer is verified against the stack's `root-ca.pem`.
  The stock manager API certificate (CN=wazuh.com, no SAN) cannot be verified, so
  `WAZUH_ALLOW_SELF_SIGNED=true` is set. That is acceptable only because the hop never leaves the
  Docker network.

### Enable it

1. 🧑 Add to the vault:
   - `vault_mcp_auth_secret`: `openssl rand -hex 32`
   - `vault_mcp_api_key`: `python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"`
   - `vault_mcp_api_password`, `vault_mcp_indexer_password`: same rules as the other passwords,
     and no single quote
2. 🧑 Tag the client hosts (the Ollama server and the Code North host) `tag:wazuh-mcp-client`, or
   put their tailnet IPs in the 8443 grant in the ACL snippet.
3. Set `wazuh_mcp_enabled: true` in `inventory/group_vars/all.yml` and re-run `playbooks/server.yml`.

### Connect a client

| Setting | Value |
|---|---|
| URL | `https://<wazuh-magicdns>:8443/mcp` |
| Transport | Streamable HTTP |
| Header | `Authorization: Bearer <token>` |

Get a token by exchanging the API key:

```
curl -s -X POST https://<wazuh-magicdns>:8443/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"api_key": "wazuh_..."}'
# {"access_token": "...", "token_type": "bearer", "expires_in": 86400}
```

A client that only speaks stdio needs a local stdio↔HTTP bridge on the client host. This repo does
not install one, and it does not configure the clients.

If a client sends an `Origin` header, add that origin to `wazuh_mcp_allowed_origins`; unlisted
origins get `403`. Requests without an `Origin` header are accepted.

### Token lifetime

Tokens last `wazuh_mcp_token_lifetime_hours` (default 24, maximum 8760), which breaks an unattended
client once a day. Two options, your choice:

- raise the lifetime for the read-only key (upstream's local-LLM docs describe this for a
  read-only service token), or
- have the client mint a new token from the API key when the old one expires.

Rotating `vault_mcp_api_key` invalidates the tokens minted from it.

### Tool count for local models

The server exposes about 55 tools, roughly 6.6k tokens of schema on every request. Restrict the
list to what you need. Server-side, by upstream toolset name:

```yaml
wazuh_mcp_tools_allowlist: [alerts, agents, vulnerabilities]   # empty = all toolsets
wazuh_mcp_disabled_tools: []                                   # individual tool names
```

Toolsets: `alerts`, `agents`, `vulnerabilities`, `analysis`, `web_search`, `compliance`, `system`,
`response`. `web_search` is the only one that sends data off the box. Hidden tools are removed from
`tools/list` and refused by `tools/call`. You can also restrict the list on the client side.

### MCP activity in Wazuh

Two sources feed the rules. Filter the dashboard on `rule.groups: wazuh_mcp`.

- **The MCP container's own log.** It logs to journald with tag `wazuh-mcp`; the host agent
  collects only that tag.
- **The manager API's request log** (`api.log`), which the manager reads itself when MCP is
  enabled. It shows what the `mcp-readonly` account actually asked Wazuh for.

| Rule | Level | Source | Meaning |
|---|---|---|---|
| 100100 | 3 | MCP log | any event from the MCP container |
| 100101 | 3 | MCP log | MCP request served |
| 100102 | 8 | MCP log | audit-logger entry: a write tool got past the scope and confirmation gates |
| 100103 | 10 | MCP log | that write tool then failed (for example denied by Wazuh RBAC) |
| 100104 | 10 | MCP log | 5 or more authentication failures in 60 s from one client |
| 100105 | 12 | MCP log | a write tool succeeded; should never fire while write tools are off |
| 100106 | 0 | MCP log | health/readiness/metrics probes (ignored) |
| 100107 | 5 | MCP log | single authentication failure (HTTP 401) |
| 100109 | 0 | API log | the service account's own API logins (ignored) |
| 100112 | 3 | API log | API request by `mcp-readonly`, with method, endpoint and status |
| 100113 | 12 | API log | `mcp-readonly` sent a state-changing request; should never fire |
| 100114 | 10 | API log | the API denied `mcp-readonly` (HTTP 403) |

**These rules are provisional.** They were written from the upstream sources (MCP server v5.0.0,
Wazuh v4.14.8), not from a running system. Run `sudo scripts/mcp-log-samples.sh` on the Wazuh host
to check them against real lines.

**What is and isn't covered** (MCP server 5.0.0 at `LOG_LEVEL=INFO`):

- *Read tool calls.* The MCP server logs no tool name or principal, only `POST /mcp` (100101).
  Rule 100112 adds the Wazuh API endpoint each call hit. Tools that only query the indexer
  (alerts, vulnerabilities) leave no trace in `api.log`.
- *A write call refused by scope or by the confirmation gate* is returned to the client as a tool
  error and **logged nowhere**: the request never leaves the MCP server. No rule can see it. Only
  an upstream change would fix that. What the rules do guarantee is that any write call that gets
  *past* those gates is caught twice: 100102/100103/100105 from the audit logger and 100113/100114
  from the API log.
- *Client address.* The compose network has a fixed subnet (`wazuh_docker_subnet`, default
  `172.30.30.0/24`), and the MCP server trusts `X-Forwarded-For` only from its gateway
  (`wazuh_mcp_forwarded_allow_ips: "{{ wazuh_docker_gateway }}"`), the address `tailscale serve`
  traffic arrives from. uvicorn then takes the right-most entry, which `tailscale serve` appended,
  so a client cannot choose the address that 100104 counts by. Set it to `""` to turn it off;
  100104 then counts all clients together. Change the subnet if it clashes with a LAN or VPN route.
  A stack deployed before the subnet was pinned stops the playbook with a message: run
  `sudo docker compose down` (no `-v`; volumes are kept) in `/opt/wazuh/wazuh-docker/single-node`
  once, then re-run.
- Rules 100109 and 100112–100114 match the user name `mcp-readonly` literally. Change
  `roles/wazuh_mcp/files/mcp_rules.xml` too if you change `wazuh_mcp_api_user`.

## Bump `wazuh_version`

1. Read Wazuh's [Docker upgrade guide](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html)
   and the release notes for the target version. Stay on 4.14.x; 5.0 is a separate migration.
2. Take a Proxmox snapshot.
3. Change `wazuh_version` in `inventory/group_vars/all.yml`.
4. Compare upstream's `single-node/config/` at the new tag with the three templates copied from it
   (`internal_users.yml.j2`, `wazuh.yml.j2`, `wazuh_manager.conf.j2`) and carry over any changes.
5. `ansible-playbook playbooks/site.yml --ask-vault-pass`. The server is upgraded first, then the
   agents are moved to the same version.
6. If the upgrade fails, roll the snapshot back.

## Backups and upgrades

There is no backup tooling in this repo. Backups are Proxmox vzdump jobs to the Unraid share,
configured in Proxmox (snapshot mode, zstd, about 7 daily and 4 weekly). They cover the Docker
volumes, `/opt/wazuh/deploy` and the certificates.

- Before bumping `wazuh_version`: snapshot, run the playbook, roll back if it fails.
- Restoring also needs the vault password. Keep it somewhere outside the VM.

## SSH hardening on the server

Use keys, then disable password logins with a drop-in (not `ssh_config`, which is the client
config):

```
# /etc/ssh/sshd_config.d/00-hardening.conf
PasswordAuthentication no
PermitRootLogin no
```

```
sudo sshd -t && sudo systemctl reload ssh
```

The file name matters: `sshd` uses the first value it reads, and `00-` sorts before cloud-init's
`50-cloud-init.conf`. Leave `UsePAM` at its default (`yes`).

Instead of a separate service account with its own key, you can use **Tailscale SSH**: run
`sudo tailscale set --ssh` on the server and keep the `ssh` block from the ACL snippet. Access is
then governed by the tailnet policy and no SSH port needs to be reachable.

If you do create a dedicated Ansible account, give it key-only login and passwordless sudo, and
lock it when you're not deploying (`sudo usermod -s /usr/sbin/nologin <user>`).

## Troubleshooting

**Agent not connecting**

- *ACL*: a tailnet agent host must carry `tag:wazuh-agent`, and the grant for `tcp:1514,1515` must
  be in the policy. Test from the agent: `nc -vz <magicdns-name> 1514`.
- *Bind IP*: on the server, `sudo ss -tlnp | grep -E ':151[45]'` must show the LAN and Tailscale
  addresses. `wazuh_bind_ts_ip` must be the server's current `tailscale ip -4`.
- *Enrollment password*: `vault_agent_enrollment_password` must match `/opt/wazuh/deploy/authd.pass`.
  On the agent, look at `/var/ossec/logs/ossec.log` for "Invalid password".
- *Version*: an agent newer than the manager is rejected. Agents are pinned to `wazuh_version`.

**Containers don't come back after a reboot**

Publishing on the Tailscale IP fails if Docker starts before `tailscaled` has the address. The
`docker` role sets `net.ipv4.ip_nonlocal_bind=1` / `net.ipv6.ip_nonlocal_bind=1` (the actual fix)
and orders `docker.service` after `tailscaled.service`. Check with
`sysctl net.ipv4.ip_nonlocal_bind` and `systemctl cat docker`.

**Dashboard shows a certificate warning or does not load**

Check that tailnet HTTPS certificates are on and that `sudo tailscale serve status` maps 443 to
`https+insecure://127.0.0.1:5601`. Use the MagicDNS name, not the IP.

**Dashboard login fails with the vault password**

The security index was initialised with other hashes. The playbook detects this (HTTP 401 for
`admin`) and runs `securityadmin.sh`; re-run `playbooks/server.yml`. Check that the hash in the
vault was generated from the same password.

**The playbook stops in "Preflight checks"**

A vault variable is missing, still `CHANGEME`, or equal to an upstream default, or one of
`wazuh_bind_ts_ip`, `wazuh_bind_lan_ip`, `wazuh_server_magicdns` is unset.
