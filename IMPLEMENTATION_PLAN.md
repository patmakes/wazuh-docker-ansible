# Implementation Plan: wazuh-docker-ansible 2026 refresh

**Repo:** `patmakes/wazuh-docker-ansible`
**Goal:** Update the repo so it deploys a hardened single-node Wazuh **4.14.8** stack in Docker over Tailscale, enrolls agents on both LAN hosts and tailnet hosts, and optionally serves a read-only MCP endpoint over the tailnet for Pat's local LLM clients (Ollama, Code North), all from Ansible.
**Audience:** Claude Code implements the work. Steps marked **🧑 MANUAL** must be done by Pat, because they need secrets, an admin console, or a judgment call. Claude Code must not fake or skip them: it should stop, list what is needed, and carry on with work that doesn't depend on them.

**Scope for Claude Code: repo changes only.** Claude Code's only deliverable is changes to this repo: Ansible playbooks, roles, templates, rule files, inventory examples, and docs. It does **not** provision or configure the VM, run playbooks against Pat's hosts, or touch Proxmox, Tailscale, Unraid, or any client. Pat does the VM setup (§0a) and runs the playbooks.

The **Post-deploy checks** under each phase are verification steps for **Pat** to run after deploying. Claude Code copies them, grouped by phase, into a `VERIFY.md` at the repo root. Claude Code's own acceptance bar is the static validation in §4. Never claim a post-deploy check passed.

---

## 0a. Target host (provisioned by Pat, not by this repo)

The playbooks target an existing Ubuntu VM that Pat builds by hand on Proxmox. Claude Code writes **no** tasks for anything in this section. The facts are here so defaults and docs match the host:

| Setting | Value |
|---|---|
| Hypervisor | Proxmox VE |
| Storage | lvm-thin pool on a dedicated 1 TB WD SSD |
| vCPU / RAM | 4 vCPU / 16 GB (Wazuh's 4.14 quickstart for 1–25 agents is 4 vCPU / 8 GiB / 50 GB at 90-day retention; the extra RAM covers Docker, the indexer heap and the MCP container) |
| Disk | **256 GB** virtual disk (thin, so it only consumes what's written), VirtIO SCSI single, IO thread on, cache none, **Discard on** |
| Guest OS | Ubuntu 24.04 LTS, ext4 (no ZFS in the guest) |
| Guest agent | `qemu-guest-agent` installed in the guest and enabled in Proxmox |
| Backups | Proxmox vzdump (snapshot mode, zstd) to an **Unraid** share, scheduled by Pat in Proxmox |

What this means for the repo:
- Default `wazuh_indexer_heap: "4g"`, sized for 16 GB RAM.
- **No backup tooling in the repo.** The VM-level backups cover the Docker volumes, `/opt/wazuh/deploy`, and the certs.
- The host agent (Phase 8) alerts on disk usage, since the indexer goes read-only at its 95% flood-stage watermark.

## 0. Context for the implementer

What the repo has today (last commit Jan 2024):

| File | Problem |
|---|---|
| `git-build-install-docker-wazuh.yml` | Pins `v4.7.0`. Uses the removed `docker_compose` module. Builds images locally for no reason. Hard-codes `/etc/ansible/...` paths and `remote_user: waz`. Uses `recreate: always`. |
| `install-docker.sh` | Vendored 2023 get.docker.com script. Also installs Compose v1 from apt and `curl`s a v2.12.2 binary. **Delete it.** |
| `rules/local_rules.xml` | Suppresses 60107 for `lsass.exe`/`svchost.exe`/`explorer.exe`, which hides credential-theft signals. The description says 30s but `timeframe` is 120. The playbook never deploys the file. |
| `README.md` | Out of date: v4.7.0, SSH hardening errors, and no agent coverage. |

Upstream facts, checked against `wazuh/wazuh-docker` tag `v4.14.8`:

- `single-node/docker-compose.yml` uses images `wazuh/wazuh-{manager,indexer,dashboard}:4.14.8` from Docker Hub. No local build is needed.
- Certs come from `single-node/generate-indexer-certs.yml` (`wazuh/wazuh-certs-generator:0.0.4`, `CERT_TOOL_VERSION=4.14`). It writes to `config/wazuh_indexer_ssl_certs/`.
- Default secrets live in four places:
  - compose env: `INDEXER_PASSWORD=SecretPassword`, `API_PASSWORD=MyS3cr37P450r.*-`, `DASHBOARD_PASSWORD=kibanaserver`
  - `config/wazuh_indexer/internal_users.yml` (bcrypt hashes for `admin` and `kibanaserver`)
  - `config/wazuh_dashboard/wazuh.yml` (API password)
- The manager config is mounted from `config/wazuh_cluster/wazuh_manager.conf` to `/wazuh-config-mount/etc/ossec.conf`. Upstream ships `<auth><use_password>no</use_password>`.
- All ports are published on `0.0.0.0`: 1514, 1515, 514/udp, 55000, 9200, 443→5601. Docker's iptables rules bypass UFW.
- Indexer heap is `-Xms1g -Xmx1g`.
- `v5.0.0` is at rc1 as of 2026-10-10. **Stay on 4.14.x.**

---

## 1. Design decisions (implement as stated)

1. **Never edit the upstream clone.** Clone `wazuh-docker` at `{{ wazuh_version }}` into `/opt/wazuh/wazuh-docker` (`force: true`, so re-runs are clean). Put everything we own in `/opt/wazuh/deploy/`:
   - templated config files
   - `docker-compose.override.yml`
   - `local_rules.xml`, `authd.pass`

   Run compose with both files: `files: [docker-compose.yml, /opt/wazuh/deploy/docker-compose.override.yml]`, `project_src: /opt/wazuh/wazuh-docker/single-node`.
2. **The override replaces mounts and ports.** Compose merges `volumes` by container path, so overriding a mount target swaps in our file. Compose **appends** `ports` lists, so every `ports:` key in the override must use the `!override` tag (Compose ≥ 2.24). Assert the Compose version in the playbook.
3. **Port exposure:**
   - `wazuh.manager`:
     - `{{ wazuh_bind_lan_ip }}:1514`, `:1515`, `:514/udp`
     - `{{ wazuh_bind_ts_ip }}:1514`, `:1515`
     - `55000` is **not published**.
   - `wazuh.indexer`: **no ports published**.
   - `wazuh.dashboard`: `127.0.0.1:5601:5601` only. It is **not** bound to the TS IP. Users reach it through `tailscale serve` on 443, which gives a valid MagicDNS certificate; see §1.10.
   - LAN syslog (514/udp) is optional, behind `wazuh_enable_syslog: true`.
4. **Secrets come from `ansible-vault` only.** No defaults ship in the repo. The playbook fails fast if any vault var is undefined, or if any vault var still equals an upstream default.
5. **Docker install uses native tasks:** Docker's apt repo plus `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, and `docker-compose-plugin`. Do not pull in the `geerlingguy.docker` role, to keep dependencies minimal.
6. **Idempotent re-runs.** A second run with no changes must report `changed=0`. Use `recreate: auto` and `pull: missing`, never `recreate: always`.
7. **Use FQCNs everywhere.** Collections are pinned in `requirements.yml` (`community.docker`, `ansible.posix`).
8. **The MCP server lives on the Wazuh host, and only there.** It joins the Wazuh compose network and reaches `wazuh.manager:55000` and `wazuh.indexer:9200` internally, so neither port is ever published. Its listener binds `127.0.0.1:3000`, and users reach it through `tailscale serve` on 8443. `wazuh_mcp_enabled` (default `false`) turns it on. There is no remote or dedicated-host mode: Pat's MCP gateway (NGX003 → MCP001) is a separate system and is **out of scope** for this repo. Don't add playbooks, inventory groups or ports for it.
9. **The Wazuh host monitors its own MCP server.** MCP activity goes into Wazuh itself (Phase 8) rather than to an external log pipeline.
10. **Web UIs live on localhost behind `tailscale serve`; only raw TCP binds to the TS IP.**
    - The dashboard and the MCP listener bind `127.0.0.1`, and `tailscale serve` terminates TLS in front of them: 443 → dashboard, 8443 → MCP.
    - Only the agent ports (1514/1515) bind directly to `{{ wazuh_bind_ts_ip }}`. Agents need a real TCP listener, and those ports aren't HTTP.
    - **Boot-order fix:** if Docker starts before `tailscaled` has assigned the 100.x address, publishing to that IP fails and the containers don't come up. Set the sysctls `net.ipv4.ip_nonlocal_bind=1` and `net.ipv6.ip_nonlocal_bind=1`, so the bind succeeds before the address exists. Also add a systemd drop-in `/etc/systemd/system/docker.service.d/10-after-tailscale.conf` with `After=tailscaled.service` and `Wants=tailscaled.service`. The sysctl is the actual fix; the drop-in just makes the ordering tidy.
    - **No nginx or other reverse proxy.** This was considered and rejected: one admin, all admin devices on the tailnet, and Tailscale already provides identity, TLS and ACLs. Revisit only if SSO/2FA in front of Wazuh or LAN break-glass access becomes a requirement.

---

## 2. Target repo layout

```
.
├── README.md                      # rewritten (Phase 6)
├── IMPLEMENTATION_PLAN.md         # this file
├── ansible.cfg                    # inventory path, roles_path, vault prompt off by default
├── requirements.yml               # community.docker, ansible.posix (pinned)
├── inventory/
│   ├── hosts.example.yml          # groups: wazuh_server, agents_tailnet, agents_lan, agents_windows
│   └── group_vars/
│       ├── all.yml                # wazuh_version: "4.14.8", wazuh_server_magicdns, etc.
│       ├── wazuh_server.yml       # bind IPs, heap size, retention days
│       └── vault.example.yml      # every secret var name, placeholder values, NOT encrypted
├── playbooks/
│   ├── site.yml                   # imports server.yml then agents.yml
│   ├── server.yml
│   └── agents.yml
├── roles/
│   ├── docker/                    # apt repo + packages + daemon enabled
│   ├── wazuh_server/
│   │   ├── tasks/main.yml
│   │   ├── templates/
│   │   │   ├── docker-compose.override.yml.j2
│   │   │   ├── internal_users.yml.j2
│   │   │   ├── wazuh.yml.j2       # dashboard → API creds
│   │   │   ├── wazuh_manager.conf.j2  # upstream copy with use_password=yes
│   │   │   └── ism-retention.json.j2
│   │   ├── files/local_rules.xml  # moved from rules/
│   │   └── handlers/main.yml      # restart manager container
│   ├── wazuh_agent/
│   │   ├── tasks/{main,debian,redhat,windows}.yml
│   │   └── defaults/main.yml
│   └── wazuh_mcp/                 # Phases 7–8, behind wazuh_mcp_enabled
│       ├── tasks/main.yml         # read-only API + indexer users, container, tailscale serve
│       ├── templates/{mcp.env.j2,docker-compose.mcp.yml.j2}
│       ├── files/{mcp_decoders.xml,mcp_rules.xml}
│       └── defaults/main.yml
├── tailscale/
│   └── acl-snippet.hujson         # grants + tagOwners for Pat to paste (Phase 5)
├── scripts/
│   └── mcp-log-samples.sh         # Phase 8 helper Pat runs post-deploy to capture MCP log lines + run wazuh-logtest
└── VERIFY.md                      # post-deploy checks for Pat, collected from every phase
```

Delete `install-docker.sh`, `git-build-install-docker-wazuh.yml`, and the `rules/` dir (its content moves to the role).

---

## 3. Phases

### Phase 1: Scaffolding and Docker role

- [ ] Create `ansible.cfg`, `requirements.yml`, the inventory examples, and `group_vars` as described in §2.
- [ ] `roles/docker`:
  - add Docker's GPG key to `/etc/apt/keyrings/docker.asc`
  - add the deb822 source for `{{ ansible_distribution | lower }}` and `{{ ansible_distribution_release }}`
  - install the packages listed in §1.5
  - enable and start `docker`
  - remove the `docker-compose` (v1) apt package and `/usr/local/bin/docker-compose` if present
- [ ] Assert `docker compose version` ≥ 2.24.
- [ ] Set `vm.max_map_count=262144` with `ansible.posix.sysctl` (persisted).
- [ ] Apply the boot-order fix from §1.10: the `ip_nonlocal_bind` sysctls (persisted) and the `docker.service` drop-in, followed by `systemd daemon-reload`. Put this in `roles/docker` behind `docker_after_tailscale: true` (default true), so the MCP host gets it too.
- [ ] Support Ubuntu 22.04/24.04 and Debian 12/13. Fail clearly on anything else.

**Post-deploy checks (Pat runs these; Claude Code copies them into `VERIFY.md`):**
- `ansible-lint` passes on the profile `production`, or any remaining warnings are listed in the PR description.
- Running the role twice gives `changed=0` on the second run.

### Phase 2: Wazuh server role

- [ ] Clone upstream at `{{ wazuh_version }}` into `/opt/wazuh/wazuh-docker`.
- [ ] Generate certs only if `config/wazuh_indexer_ssl_certs/root-ca.pem` is missing. Use `docker_compose_v2` with `files: [generate-indexer-certs.yml]`, then `state: absent` for the generator.
- [ ] Render the templates into `/opt/wazuh/deploy/` with mode `0600`, owner root:
  - `internal_users.yml.j2`: `admin` and `kibanaserver` hashes from vault vars `vault_indexer_admin_hash` and `vault_dashboard_kibanaserver_hash`. Hashes are generated by Pat; see Phase 2 MANUAL below. Keep the rest of upstream's file unchanged. Copy it from the cloned tag as the template base rather than hand-writing it.
  - `wazuh.yml.j2`: API password from `vault_wazuh_api_password`.
  - `wazuh_manager.conf.j2`: upstream file with `<use_password>yes</use_password>`.
  - `authd.pass`: contents are `vault_agent_enrollment_password`.
  - `local_rules.xml`: from `files/`, with the fixes in Phase 2b.
- [ ] `docker-compose.override.yml.j2` must:
  - override env vars `INDEXER_PASSWORD`, `API_PASSWORD`, and `DASHBOARD_PASSWORD` from vault plaintext vars
  - set `OPENSEARCH_JAVA_OPTS=-Xms{{ wazuh_indexer_heap }} -Xmx{{ wazuh_indexer_heap }}` (default `"4g"`, sized for the 16 GB VM in §0a)
  - remap mounts for `internal_users.yml`, `wazuh.yml`, and `ossec.conf` to the `/opt/wazuh/deploy/` copies
  - mount `authd.pass` → `/wazuh-config-mount/etc/authd.pass`
  - mount `local_rules.xml` → `/wazuh-config-mount/etc/rules/local_rules.xml`
  - **Verify against the 4.14.8 manager image entrypoint** that files under `/wazuh-config-mount/` get copied into `/var/ossec/`. If they don't, fall back to `docker cp` plus a handler, and note this in the PR.
  - set ports per §1.3, using `!override`
- [ ] Preflight: fail if any vault var is undefined, or if any equals `SecretPassword`, `MyS3cr37P450r.*-`, or `kibanaserver`. Also fail if `wazuh_bind_ts_ip` is not in `100.64.0.0/10`.
- [ ] Bring the stack up with `docker_compose_v2` (`state: present`, `pull: missing`, `recreate: auto`, `wait: true`).
- [ ] Publish the dashboard on the tailnet with `tailscale serve --bg --https=443 https+insecure://127.0.0.1:5601`. `https+insecure` is fine here because the backend hop is loopback-only, to the dashboard's self-signed cert. Make it idempotent: read `tailscale serve status --json` and only change it if the 443 mapping differs. Add a small `tailscale_serve` task file (in `roles/wazuh_server` or a shared `roles/tailscale_serve`) and reuse it for the MCP 8443 mapping in Phase 7.
- [ ] Post-start check: run `securityadmin.sh` inside the indexer only if `curl -u admin:{{ vault_indexer_admin_password }} https://localhost:9200` (exec'd inside the container) returns 401. That would mean the security index was initialized with stale hashes, for example on a pre-existing volume.
- [ ] Apply an ISM policy that deletes `wazuh-alerts-*` older than `{{ wazuh_retention_days }}` (default 90). Use `uri` from inside the indexer container (`docker exec ... curl`), not a published port. Attach it to existing indices too.
- [ ] Handler: restart `wazuh.manager` when `local_rules.xml`, `ossec.conf`, or `authd.pass` changes.

**Post-deploy checks (Pat runs these; Claude Code copies them into `VERIFY.md`):**
- From the server, `ss -tlnp` shows no listener on `0.0.0.0` for 9200 or 55000, and 5601 only on `127.0.0.1`. Docker publishes nothing on 443; that port belongs to `tailscaled`.
- The dashboard loads at `https://<magicdns-name>` **with no certificate warning**, using the vault admin password. Logging in with `admin/SecretPassword` fails.
- **Reboot test:** after `sudo reboot`, all three containers come back healthy without manual intervention, the dashboard loads, and test agents reconnect on the TS IP. If no live target is available, state that this test was not run.
- `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest` loads `local_rules.xml` without errors.
- A second run reports `changed=0`.

#### 🧑 MANUAL (Pat), Phase 2

1. Build the VM as described in §0a: 4 vCPU, 16 GB, a 256 GB thin disk on the SSD lvm-thin pool, with Discard, VirtIO SCSI single, IO thread on, and cache none.
   - After installing Ubuntu, run `sudo vgs`. The installer often leaves space unallocated; if so, run `sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv`.
   - Enable `fstrim.timer`, install `qemu-guest-agent`, and turn on the QEMU Guest Agent option in Proxmox.
   - Set up the nightly vzdump job to Unraid.
   - Take a Proxmox snapshot before the first playbook run.
2. Install Tailscale on the server and enroll it **with a tagged, pre-authorized auth key**: `tailscale up --authkey=<key> --advertise-tags=tag:wazuh`. Note the `100.x` IP and MagicDNS name for the inventory.
2a. Enable HTTPS certificates for your tailnet in the Tailscale admin console (DNS → HTTPS Certificates) if they're not already on. The dashboard's `tailscale serve` mapping needs this. Note that the cert puts the machine's MagicDNS name in public Certificate Transparency logs, so pick a hostname you don't mind being visible.
3. Choose passwords. The indexer admin password needs ≥ 8 characters with upper, lower, digit, and symbol. The API password follows Wazuh's API policy: 8–64 chars with upper, lower, digit, and symbol.
4. Generate bcrypt hashes for the indexer `admin` and `kibanaserver` passwords:
   ```
   docker run --rm -it wazuh/wazuh-indexer:4.14.8 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
   ```
5. Copy `vault.example.yml` → `inventory/group_vars/vault.yml`, fill it in, then run `ansible-vault encrypt inventory/group_vars/vault.yml`. **Never commit the unencrypted file.** Claude Code adds it to `.gitignore` as a safeguard.
6. If you have an existing 4.7 deployment whose data you want to keep, tell Claude Code before Phase 2 runs. The default plan assumes a fresh install.

### Phase 2b: Fix `local_rules.xml`

- [ ] Remove `lsass.exe`, `svchost.exe`, and `explorer.exe` from the exclusion regex. Keep `1Password.exe`, `msedge.exe`, and `chrome.exe`. Make the process list a role var, `wazuh_60107_noisy_processes`, rendered into the regex so Pat can extend it.
- [ ] Fix the description so it matches `timeframe="120"` (or change the timeframe to 30 and update both). Keep `frequency`, `timeframe`, and the description consistent.
- [ ] Keep rule ID 100008 and the MITRE/compliance tags.

#### 🧑 MANUAL (Pat), Phase 2b

- Confirm the final noisy-process list after a week of real data. Claude Code should not guess additions.

### Phase 3: Agent role (Linux)

- [ ] Add the Wazuh apt/yum repo (GPG key + source), then install `wazuh-agent` pinned to `{{ wazuh_version }}-1`, with env vars:
  - `WAZUH_MANAGER={{ wazuh_manager_address }}`
  - `WAZUH_REGISTRATION_PASSWORD={{ vault_agent_enrollment_password }}`
  - `WAZUH_AGENT_GROUP={{ wazuh_agent_group }}`
  - `WAZUH_AGENT_NAME={{ inventory_hostname }}`
- [ ] Per-group defaults:
  - `agents_tailnet`: `wazuh_manager_address: "{{ wazuh_server_magicdns }}"`, `wazuh_agent_group: tailnet`
  - `agents_lan`: `wazuh_manager_address: "{{ wazuh_bind_lan_ip }}"`, `wazuh_agent_group: lan`
- [ ] Hold the package (`dpkg_selections: hold` / versionlock) so an OS upgrade can't move the agent ahead of the manager.
- [ ] Enable and start `wazuh-agent`. Skip enrollment if `/var/ossec/etc/client.keys` is non-empty, so re-runs don't re-register.
- [ ] Create the `tailnet` and `lan` agent groups on the manager (`docker exec ... /var/ossec/bin/agent_groups -a -g <name> -q`) before agents enroll.

**Post-deploy checks (Pat runs these; Claude Code copies them into `VERIFY.md`):**
- A test host in each group shows as **Active** in the dashboard and in the correct group.
- Re-running gives `changed=0`.

### Phase 4: Agent role (Windows)

- [ ] Use `ansible.windows`/`chocolatey`-free MSI install: `win_get_url` for the 4.14.8 MSI, then `win_package` with `WAZUH_MANAGER`, `WAZUH_REGISTRATION_PASSWORD`, and `WAZUH_AGENT_GROUP=windows`. Start the `WazuhSvc` service.
- [ ] Inventory group `agents_windows`, connected over WinRM or OpenSSH. Document both and default to OpenSSH.

#### 🧑 MANUAL (Pat), Phase 4

- Enable OpenSSH Server (or WinRM) on each Windows host and add its key or credentials to the vault.
- Confirm the Windows audit policy you want, since it drives 60107 volume. Out of scope for automation.

### Phase 5: Tailscale ACL snippet

- [ ] Write `tailscale/acl-snippet.hujson` with:
  - `tagOwners`: `tag:wazuh` and `tag:wazuh-agent` owned by Pat's account/group
  - `grants`:
    - `tag:wazuh-agent` → `tag:wazuh` on `tcp:1514,tcp:1515`
    - Pat's admin devices/group → `tag:wazuh` on `tcp:443` (and `tcp:22` if not using Tailscale SSH)
  - optional `ssh` block allowing Pat's devices to Tailscale-SSH into `tag:wazuh` as the deploy user
- [ ] Add a README section explaining that tailnet agent hosts must carry `tag:wazuh-agent`.

#### 🧑 MANUAL (Pat), Phase 5

1. Merge the snippet into your tailnet policy file in the Tailscale admin console. Review it against your existing grants first, because a bad policy can lock you out.
2. Tag existing tailnet hosts that should report (`tailscale up --advertise-tags=tag:wazuh-agent ...` or the admin console). Note that tagging a device removes its user ownership.
3. For LAN devices that can't run Tailscale but need to reach the server from elsewhere, decide whether a subnet router is needed. The default assumes LAN agents talk to the server's LAN IP directly.

### Phase 6: README and cleanup

- [ ] Rewrite `README.md`:
  - prerequisites
  - the MANUAL checklist from this plan, in order
  - `ansible-galaxy collection install -r requirements.yml`
  - `ansible-playbook playbooks/site.yml --ask-vault-pass`
  - how to add an agent
  - how to bump `wazuh_version`, with a pointer to Wazuh's Docker upgrade docs
  - troubleshooting: agent not connecting → check ACL, bind IP, and enrollment password
- [ ] Fix the SSH hardening section:
  - `PasswordAuthentication no` goes in a drop-in `/etc/ssh/sshd_config.d/00-hardening.conf`, not `ssh_config`
  - remove `UsePAM no`
  - keep `PermitRootLogin no`
  - mention Tailscale SSH as an alternative to the separate service account
- [ ] README "Backups and upgrades" section, documentation only. Backups are Proxmox vzdump jobs to Unraid, configured by Pat outside this repo. Before bumping `wazuh_version`, take a Proxmox snapshot, run the playbook, and roll back the snapshot if the upgrade fails. Restoring also needs the vault password, so keep it somewhere outside the VM. **Do not** add a backup script or backup playbook.
- [ ] Delete the old files listed in §2. Add `.gitignore` entries for `vault.yml`, `*.retry`, and the certs dir.

#### 🧑 MANUAL (Pat), Phase 6

- Configure the Proxmox vzdump job to the Unraid share (decided: snapshot mode, zstd, about 7 daily and 4 weekly). Store the vault password somewhere outside the VM.

### Phase 7: MCP endpoint on the Wazuh host (`wazuh_mcp_enabled: true`)

Use [`gensecaihq/Wazuh-MCP-Server`](https://github.com/gensecaihq/Wazuh-MCP-Server), pinned to image `ghcr.io/gensecaihq/wazuh-mcp-server:5.0.0` (var `wazuh_mcp_version`). It is the most actively maintained option (last release Sept 2026), serves Streamable HTTP at `/mcp`, and supports bearer/OAuth auth plus read-only scopes.

Facts from its docs that shape this phase:
- It needs the Manager API (`WAZUH_HOST/USER/PASS`) and the Indexer (`WAZUH_INDEXER_*`). Without the Indexer, the alert and vulnerability tools return errors.
- **Its supported range is Wazuh 4.8.0–4.14.7.** We deploy 4.14.8. Patch releases shouldn't change the API endpoints it calls, but the acceptance smoke test below must confirm this. Do not claim compatibility untested.
- The stock Wazuh API cert (CN=wazuh.com, no SAN) fails its TLS verification. Mount the stack's `root-ca.pem` as `WAZUH_CA_BUNDLE` for the Indexer. For the Manager API, set `WAZUH_ALLOW_SELF_SIGNED=true`; that is acceptable here only because traffic stays on the internal Docker network. Note this in the README.
- Its own compose file binds to `127.0.0.1:3000` and serves plain HTTP. TLS must come from a proxy in front.

Tasks:
- [ ] **Least-privilege Wazuh accounts**, created by Ansible after the stack is healthy:
  - A Manager API user `mcp-readonly` with a custom policy containing only the read actions from upstream's `WAZUH_COMPATIBILITY.md`: `agent:read`, `group:read`, `syscollector:read`, `syscheck:read`, `sca:read`, `rules:read`, `manager:read`, `cluster:read`. **No** `active-response:command` or `agent:restart`. Use the API via `docker exec wazuh.manager curl -k https://localhost:55000/...` with the admin API creds from the vault.
  - An Indexer user `mcp-readonly` with a role that grants `read` and `search` on `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*` only. Add it via the security REST API from inside the indexer container (not by editing `internal_users.yml`, to avoid a `securityadmin` re-run).
  - Both passwords come from the vault (`vault_mcp_api_password`, `vault_mcp_indexer_password`). Make it idempotent: GET first, and create or update only on a mismatch.
- [ ] Render `/opt/wazuh/deploy/mcp.env` (mode `0600`) with:
  - `WAZUH_HOST=wazuh.manager`, `WAZUH_INDEXER_HOST=wazuh.indexer`, and the `mcp-readonly` creds
  - `AUTH_MODE=bearer`
  - `AUTH_SECRET_KEY={{ vault_mcp_auth_secret }}`, `MCP_API_KEY={{ vault_mcp_api_key }}`, `MCP_API_KEY_SCOPES=wazuh:read`
  - `WAZUH_CA_BUNDLE=/app/certs/ca.pem`, `WAZUH_ALLOW_SELF_SIGNED=true`
- [ ] Add a third compose file, `docker-compose.mcp.yml`, used only when `wazuh_mcp_enabled`. It defines the `wazuh-mcp` service:
  - the pinned image, `env_file: /opt/wazuh/deploy/mcp.env`
  - port `127.0.0.1:3000:3000`
  - a mount of `config/wazuh_indexer_ssl_certs/root-ca.pem` → `/app/certs/ca.pem:ro`
  - upstream's hardening: `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs, memory limit 512M, healthcheck on `/health`
  - the same project, so it joins the default network with `wazuh.manager` and `wazuh.indexer`
- [ ] Expose it on the tailnet with TLS: `tailscale serve --bg --https=8443 http://127.0.0.1:3000`. Use port **8443** because `tailscale serve` already maps 443 to the dashboard. Use the shared `tailscale_serve` task file from Phase 2. Make it idempotent by checking `tailscale serve status --json` first. **Do not** enable Tailscale Funnel: the endpoint is tailnet-only.
- [ ] Extend `tailscale/acl-snippet.hujson`: grant `tag:wazuh` on `tcp:8443` only to the MCP client hosts (`{{ wazuh_mcp_client_hosts }}`: Pat's ollama-server and the Code North host, by tag or tailnet IP). Agents and other admin devices get no access to it.
- [ ] **Client-agnostic endpoint.** The MCP clients are Pat's **local** Ollama server and **Code North**, not Claude, so there is no Claude, claude.ai or Anthropic integration in this repo. Document the endpoint generically:
  - URL `https://<wazuh-magicdns>:8443/mcp`, transport **Streamable HTTP**, header `Authorization: Bearer <token>`.
  - How to get a token: `POST /auth/token` with the API key. Check the exact request body against upstream's docs before writing it down.
  - If a client only speaks stdio, it needs a local stdio↔HTTP bridge on the client host. Document that, but **don't install one**; it belongs to the client host, not this repo.
- [ ] **Token lifetime for unattended clients.** The default `TOKEN_LIFETIME_HOURS=24` will break a headless client daily. Expose `wazuh_mcp_token_lifetime_hours` (default 24) and document the two options: a longer lifetime for a read-only key (upstream's local-LLM docs describe exactly this pattern for a read-only token), or a client that re-mints from the API key. Don't pick one for Pat.
- [ ] **Tool count for local models.** The server exposes ~55 tools, which is a lot of schema for a local model's context window. README note: restrict the tool list on the client side to what's needed (agents, alerts, vulnerabilities). If the server has a supported server-side allow-list setting, wire it to a `wazuh_mcp_tools_allowlist` var; verify it exists first and don't fabricate one.
- [ ] Do **not** deploy upstream's `compose.local-llm.yml` (vLLM + Open WebUI). Pat already runs his own Ollama server elsewhere.

**Post-deploy checks (Pat runs these; Claude Code copies them into `VERIFY.md`):**
- `ss -tlnp` on the server still shows nothing on 55000/9200, and `3000` only on 127.0.0.1.
- `curl https://<magicdns>:8443/health` from the ollama-server / Code North host returns healthy. From any other tailnet device, it times out.
- A smoke test (a scripted MCP `initialize` + `tools/list` + `tools/call` with curl or a small Python client; no Claude tooling) succeeds against 4.14.8 for: listing agents, fetching recent alerts, and listing vulnerabilities. Report exactly which tools were exercised.
- An active-response tool call is refused. It should fail twice over: by scope (`wazuh:read`) and by the API user's RBAC.
- A re-run reports `changed=0`.

#### 🧑 MANUAL (Pat), Phase 7

1. Generate and vault the secrets:
   - `vault_mcp_auth_secret`: `openssl rand -hex 32`
   - `vault_mcp_api_key`: `python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"`
   - `vault_mcp_api_password` and `vault_mcp_indexer_password` (same password rules as Phase 2)
2. HTTPS certificates for the tailnet should already be on from Phase 2 (step 2a). Nothing more to do here.
3. **Tell Claude Code how the clients connect.** It needs the tailnet names or tags of the ollama-server and Code North hosts (for the ACL), and whether each one speaks Streamable HTTP natively or needs a stdio bridge. The endpoint stays tailnet-only, and no public exposure is planned; with local clients, your Wazuh data never leaves your network.
4. **Decide whether to ever allow write tools** (active response: blocking IPs, isolating hosts, restarting agents). The default is no. Turning it on needs both `wazuh:write` scope and the extra RBAC actions, and upstream recommends `WAZUH_PROTECTED_IPS` and keeping the confirmation gate on.
5. Choose the token approach for your clients: a long-lived read-only token, or re-minting from the key. Then configure the MCP connection in Code North / your Ollama front-end. That configuration lives on those hosts, outside this repo.

### Phase 8: Ship MCP activity into Wazuh (runs on the Wazuh host)

Pat runs a separate MCP gateway (NGX003 in front of MCP001) for other services. **The Wazuh MCP endpoint is not routed through it.** Everything in this phase stays on the Wazuh host. Wazuh is the SIEM, so it is also where the MCP server's own activity gets logged and alerted on.

- [ ] **A Wazuh agent on the Wazuh host itself.** Use the Phase 3 agent role against `wazuh_server` with these settings:
  - `wazuh_manager_address: "{{ wazuh_bind_lan_ip }}"`, so the agent enrolls against the manager's published 1514/1515
  - `wazuh_agent_group: wazuh-host`, a new group, created like the Phase 3 groups
  - Agent name: `{{ inventory_hostname }}-host`, so it isn't confused with the manager's built-in agent 000, which only sees inside the container.
  - This also gives the Docker host its own FIM, SCA and auth-log monitoring, which nothing in the plan covered before.
- [ ] **MCP container logs.**
  - Set `LOG_FORMAT=json` in `mcp.env`.
  - In `docker-compose.mcp.yml`, set `logging: {driver: journald, options: {tag: wazuh-mcp}}` on the `wazuh-mcp` service only. Leave the Wazuh containers on Docker's default driver.
- [ ] **Collect only that container's logs.** In the `wazuh-host` group's `agent.conf`, which the manager pushes centrally, add a `localfile` entry with `<log_format>journald</log_format>` and a filter on the MCP container. Match `CONTAINER_NAME` or `SYSLOG_IDENTIFIER=wazuh-mcp`, whichever the 4.14.8 journald collector actually supports.
  - **Verify journald support and the filter syntax against the 4.14 docs before writing this.** If it doesn't work, fall back to the `json-file` driver with `labels`/`tag` log-opts and a `localfile` on `/var/lib/docker/containers/*/*-json.log`, filtered by that tag. Note the fallback in the PR if it was used.
  - **Do not** collect the Wazuh containers' own logs this way. The indexer is chatty, and the logs would feed back into themselves.
- [ ] **Decoder and rules.** Claude Code has no running container to capture logs from. Instead, derive the log format from the upstream source at the pinned image tag: the logging setup with `LOG_FORMAT=json`, the `wazuh_mcp_server.audit` logger, and the auth-failure and scope-refusal paths. Put matching sample lines in `roles/wazuh_mcp/files/samples/`, and mark the rules **provisional** in comments. Also write `scripts/mcp-log-samples.sh` for Pat to run after deploying. It makes one read call, one refused write call, and one bad-token request, captures the resulting log lines, and feeds them through `wazuh-logtest`, so the rules can be confirmed against real output.

  Then write `files/mcp_decoders.xml` and `files/mcp_rules.xml`, rule IDs **100100–100119**, deployed alongside `local_rules.xml` with the same mount and handler pattern. Starter rules:
  - 100100, level 3: any event from the MCP container (the base rule for searching in the dashboard)
  - 100101, level 3: tool call. Extract the tool name and principal if the read logs carry them.
  - 100102, level 8: any entry from the `wazuh_mcp_server.audit` logger. Upstream logs write-tool calls there, before and after execution, with the principal, session, arguments and outcome.
  - 100103, level 10: write tool refused (scope or confirmation check).
  - 100104, level 10: authentication failures, 5 or more in 60s from the same source (`frequency`/`timeframe` with `same_source_ip` or the principal).
  - 100105, level 12: any write-tool call that *succeeded*. This should never fire while write tools are disabled.

  Tag them with MITRE techniques where it fits (T1078 for auth failures).
- [ ] **Disk usage alert.** In the `wazuh-host` `agent.conf`, add a command-monitoring `localfile` (`df -P /`, every 5 minutes). Add rules 100110 at level 7 for ≥80% used and 100111 at level 12 for ≥90%. The indexer stops accepting writes at its 95% flood-stage watermark, so these fire first.
- [ ] **Coverage caveat.** Upstream's dedicated audit logger only covers **write** tools. If read calls carry no tool name or principal at `LOG_LEVEL=INFO`, say so in the PR and the README. Don't invent fields; rule 100101 then reduces to "request received".

**Post-deploy checks (Pat runs these; Claude Code copies them into `VERIFY.md`):**
- In the dashboard, filter to `rule.groups: wazuh_mcp`. A read call made from Code North (or the smoke-test script) shows up within a minute.
- A refused active-response call fires 100103. Five bad tokens in a row fire 100104.
- `wazuh-logtest`, fed the captured sample lines, matches each starter rule.
- The `wazuh-host` agent is Active, and no Wazuh-container logs come in through it.

#### 🧑 MANUAL (Pat), Phase 8

- Review the starter rule levels after a week. Tell Claude Code if you want any of them routed to an alert channel; alerting integrations are still out of scope.
- If you later want Wazuh MCP traffic to go through NGX003 as well, treat that as a separate change. It needs per-user tokens through the gateway, not one shared token, or the MCP server's per-user scopes and audit trail collapse into one identity.

---

## 4. Claude Code's acceptance bar (static validation only)

Claude Code never runs the playbooks against Pat's hosts. Its work is done when all of the following pass and `VERIFY.md` exists:

- Lint: `ansible-lint` and `yamllint` on everything.
- `ansible-playbook --syntax-check` on every playbook. `--check` against a local throwaway container is optional; if it isn't done, say so in the PR. Do not claim a live test happened.
- Validate the rendered override with `docker compose -f docker-compose.yml -f override.yml config` (needs only Docker locally, not a live stack). Confirm in the merged output that ports have been replaced, not appended, that the dashboard publishes only `127.0.0.1:5601`, and that mounts point to `/opt/wazuh/deploy`.
- Validate `local_rules.xml`, `mcp_decoders.xml` and `mcp_rules.xml` as well-formed XML (`xmllint --noout`). If Docker is available, run the sample lines in `roles/wazuh_mcp/files/samples/` through `wazuh-logtest` in a throwaway `wazuh/wazuh-manager:4.14.8` container with the rules mounted.
- Every **Post-deploy check** from §3 appears in `VERIFY.md`, grouped by phase, with the exact commands to run.
- With `wazuh_mcp_enabled: true`, run `docker compose -f docker-compose.yml -f override.yml -f docker-compose.mcp.yml config` and confirm that `wazuh-mcp` is on the same network, publishes only `127.0.0.1:3000`, and that no other service gained ports.

## 5. Out of scope

- Wazuh 5.0 migration (revisit when GA).
- Anything on the Proxmox host or in VM provisioning (§0a): disk, guest agent, fstrim, LVM extension, vzdump/Unraid backups. Also any backup script or backup playbook in the repo.
- Multi-node / clustered indexer.
- Changing default Wazuh ruleset, SCA policies, or active response.
- Alerting integrations (email, Slack, etc.).
- nginx or any other reverse proxy (see §1.10 for why).
- Routing Wazuh MCP through Pat's NGX003/MCP001 gateway, or deploying MCP to any host other than the Wazuh server.
- Any Claude / claude.ai / Anthropic integration. The MCP clients are Pat's local Ollama server and Code North.
- Configuring the MCP clients themselves (Code North, the Ollama front-end, any stdio bridge).
- Public (internet-facing) MCP exposure, OAuth/IdP setup, and MCP write tools.

## 6. 🧑 MANUAL checklist (consolidated, in run order)

1. Build the VM per §0a (4 vCPU / 16 GB / 256 GB thin disk on the SSD lvm-thin pool, with Discard, VirtIO SCSI single, IO thread, Ubuntu 24.04). Extend the root LV if needed, enable `fstrim.timer` and `qemu-guest-agent`, then take a snapshot.
2. Create a Tailscale auth key tagged `tag:wazuh`, then enroll the server and record its IP and MagicDNS name. Turn on tailnet HTTPS certificates.
3. Merge `tailscale/acl-snippet.hujson` into the tailnet policy, and tag agent hosts `tag:wazuh-agent`.
4. Pick passwords, generate bcrypt hashes, fill in and encrypt `vault.yml`.
5. Fill in `inventory/hosts.yml` (server, tailnet agents, LAN agents, Windows agents) and the bind IPs.
6. Enable SSH/WinRM on Windows hosts and add their credentials to the vault.
7. Say whether any old 4.7 data must be migrated (default: fresh install).
8. Run `site.yml`, then work through `VERIFY.md`, starting with logging in to the dashboard and confirming agents are Active.
9. After about a week, review the 60107 noisy-process list.
10. Set up the nightly Proxmox vzdump job to Unraid, and store the vault password outside the VM.
11. *(MCP, optional)* Generate and vault the four MCP secrets.
12. *(MCP, optional)* Give Claude Code the ollama-server and Code North tailnet names, and say whether each speaks Streamable HTTP natively. Pick a token approach, and decide: read-only (default) or write tools.
13. *(MCP, optional)* Run `scripts/mcp-log-samples.sh` to confirm the provisional MCP rules against real log lines. After a week, review the rule levels.
