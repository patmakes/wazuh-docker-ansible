# Post-deploy checks

Run these after `ansible-playbook playbooks/site.yml --ask-vault-pass`. They are grouped by the
phases in `IMPLEMENTATION_PLAN.md`. None of them were run when the repo was written: it was only
validated statically (lint, syntax check, template rendering).

Replace `<magicdns>` with the server's MagicDNS name. Commands marked *server* run on the Wazuh
host, *control* on the Ansible control node, *client* on another tailnet device.

## Phase 1: scaffolding and Docker

- [ ] *control* — lint passes on the `production` profile:
  ```
  ansible-lint
  yamllint .
  ```
- [ ] *control* — the Docker role is idempotent. Run the server playbook twice; in the second run's
  recap the host shows `changed=0`:
  ```
  ansible-playbook playbooks/server.yml --ask-vault-pass
  ansible-playbook playbooks/server.yml --ask-vault-pass
  ```

## Phase 2: Wazuh server

- [ ] *server* — nothing listens on `0.0.0.0` for 9200 or 55000, 5601 is only on `127.0.0.1`, and
  443 belongs to `tailscaled`, not Docker:
  ```
  sudo ss -tlnp | grep -E ':(9200|55000|5601|443|1514|1515)\b'
  ```
  Expected: no lines for 9200 or 55000; `127.0.0.1:5601` (docker-proxy); 443 owned by `tailscaled`;
  1514/1515 on the LAN and Tailscale addresses only.
- [ ] *client* — the dashboard loads at `https://<magicdns>` **with no certificate warning** and
  accepts `admin` with the vault password:
  ```
  curl -sS -o /dev/null -w '%{http_code} tls_verify=%{ssl_verify_result}\n' https://<magicdns>/
  ```
  Expected: a 2xx/3xx code and `tls_verify=0`. Then log in from a browser.
- [ ] *server* — the upstream default password is rejected (expect `401`):
  ```
  sudo docker exec single-node-wazuh.indexer-1 \
    curl -sk -o /dev/null -w '%{http_code}\n' -u admin:SecretPassword https://localhost:9200
  ```
  Also try `admin` / `SecretPassword` in the dashboard login form: it must fail.
- [ ] *server* — **reboot test.** After the reboot, all three containers come back without manual
  steps, the dashboard loads, and test agents reconnect on the Tailscale IP:
  ```
  sudo reboot
  # after it is back:
  sudo docker ps --format '{{.Names}}\t{{.Status}}'
  sysctl net.ipv4.ip_nonlocal_bind net.ipv6.ip_nonlocal_bind
  sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
  ```
- [ ] *server* — `wazuh-logtest` loads `local_rules.xml` without errors (it prints the rule/decoder
  load errors, if any, before the prompt; leave with Ctrl-C):
  ```
  sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
  sudo docker exec single-node-wazuh.manager-1 grep -c 'id="100008"' /var/ossec/etc/rules/local_rules.xml
  ```
- [ ] *server* — the retention policy exists and is attached:
  ```
  sudo docker exec -it single-node-wazuh.indexer-1 \
    curl -sk -u admin https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention
  sudo docker exec -it single-node-wazuh.indexer-1 \
    curl -sk -u admin 'https://localhost:9200/_plugins/_ism/explain/wazuh-alerts-*?pretty'
  ```
- [ ] *control* — a second run reports `changed=0`:
  ```
  ansible-playbook playbooks/server.yml --ask-vault-pass
  ```

## Phase 3: Linux agents

- [ ] A test host in each group (`tailnet`, `lan`) shows as **Active** in the dashboard
  (Agents management → Summary) and in the right group. From the *server*:
  ```
  sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
  sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_groups -l -g tailnet
  sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_groups -l -g lan
  ```
- [ ] *control* — re-running gives `changed=0`:
  ```
  ansible-playbook playbooks/agents.yml --ask-vault-pass
  ```

## Phase 4: Windows agents

No checks are listed in the plan for this phase. Suggested: the host is **Active** in group
`windows`, and on the host `Get-Service WazuhSvc` shows `Running`.

## Phase 5: Tailscale ACL

No checks are listed in the plan. Suggested, from a host tagged `tag:wazuh-agent`:
`nc -vz <magicdns> 1514` succeeds and `nc -vz -w 5 <magicdns> 443` times out.

## Phase 7: MCP endpoint (`wazuh_mcp_enabled: true`)

- [ ] *server* — still nothing on 55000/9200, and 3000 only on `127.0.0.1`:
  ```
  sudo ss -tlnp | grep -E ':(9200|55000|3000|8443)\b'
  ```
- [ ] *client* — from the Ollama server / Code North host this returns healthy; from any other
  tailnet device it times out:
  ```
  curl -sS --max-time 10 https://<magicdns>:8443/health
  ```
- [ ] *client or server* — smoke test against 4.14.8 (plain curl + python3, no Claude tooling):
  `initialize`, `tools/list`, then `tools/call` for listing agents, recent alerts and
  vulnerabilities. From an MCP client host:
  ```
  MCP_URL=https://<magicdns>:8443 MCP_API_KEY=wazuh_... scripts/mcp-log-samples.sh --no-logtest
  ```
  or on the server: `sudo scripts/mcp-log-samples.sh`.
  Expected: `PASS` for `get_wazuh_agents`, `get_wazuh_alerts`, `get_wazuh_vulnerabilities`. The
  script prints exactly which tools it exercised; report that list. Upstream's supported range
  ends at Wazuh 4.14.7, so this test is what establishes compatibility with 4.14.8.
- [ ] An active-response call is refused. The same script calls `wazuh_block_ip` with the
  read-only token and expects `PASS  wazuh_block_ip (refused)` with "requires 'wazuh:write' scope".
  The second barrier, RBAC: the API user must hold no write actions (expect no
  `active-response:command`, `agent:restart` or `manager:restart` in the output):
  ```
  sudo docker exec -it single-node-wazuh.manager-1 bash -c '
    read -rsp "wazuh-wui password: " P; echo
    T=$(curl -sk -u "wazuh-wui:$P" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
    curl -sk -H "Authorization: Bearer $T" "https://localhost:55000/security/policies?search=mcp-readonly&pretty=true"'
  ```
- [ ] *control* — a re-run reports `changed=0`:
  ```
  ansible-playbook playbooks/server.yml --ask-vault-pass
  ```

## Phase 8: MCP activity in Wazuh, and the host agent

- [ ] In the dashboard, filter to `rule.groups: wazuh_mcp`. A read call made from Code North (or
  `scripts/mcp-log-samples.sh`) shows up within a minute as rule 100101.
- [ ] **A refused active-response call fires 100103 — cannot pass as the plan wrote it.** MCP
  server 5.0.0 logs nothing for a write call refused by scope or by the confirmation gate, so
  with the read-only token no rule can match. Check these instead:
  - the refusal itself: `PASS  wazuh_block_ip (refused)` from `scripts/mcp-log-samples.sh`;
  - nothing reached Wazuh: no 100102, 100103, 100105, 100113 or 100114 under
    `rule.groups: wazuh_mcp` for that time;
  - the tripwires load: the logtest run two items below reports 100113 for sample line 15 and
    100114 for line 16.
- [ ] The read calls show their Wazuh API endpoint: after the script runs, rule 100112 appears
  with `GET /agents`. On the server, the raw line:
  ```
  sudo docker exec single-node-wazuh.manager-1 grep mcp-readonly /var/ossec/logs/api.log | tail -5
  ```
- [ ] Authentication failures carry the tailnet client's address, not `172.x`: run the script from
  an MCP client host (`--no-logtest`), then check `data.srcip` on the 100107 alerts.
- [ ] Five bad tokens in a row fire 100104 (the script sends six):
  ```
  sudo scripts/mcp-log-samples.sh
  ```
  Then look for rule 100104 under `rule.groups: wazuh_mcp`.
- [ ] `wazuh-logtest`, fed the captured sample lines, matches each starter rule. The script above
  captures the real lines, feeds them to `wazuh-logtest` and prints the matched rule IDs; the files
  are in the directory it reports. The derived samples can be checked the same way:
  ```
  sudo docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest \
    < roles/wazuh_mcp/files/samples/mcp-samples.log 2>&1 | grep -E "id: '|description"
  ```
  Compare with `roles/wazuh_mcp/files/samples/expected.tsv` (17 lines: MCP log and manager API log).
- [ ] The `wazuh-host` agent is Active, and no Wazuh-container logs come in through it:
  ```
  sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_groups -l -g wazuh-host
  sudo docker inspect -f '{{.Name}} {{.HostConfig.LogConfig.Type}}' $(sudo docker ps -q)
  ```
  Expected: only `wazuh-mcp` uses `journald`; the three Wazuh containers use `json-file`. In the
  dashboard, events from agent `<hostname>-host` contain no indexer/manager/dashboard container logs.
- [ ] Disk-usage collection works: in the dashboard, search `agent.name: <hostname>-host` and
  `full_log: "df -P /"` (visible only once a threshold rule fires), or on the server:
  ```
  sudo grep remote_commands /var/ossec/etc/local_internal_options.conf
  sudo grep -c "df -P /" /var/ossec/etc/shared/agent.conf
  ```

## Static checks that were not possible when the repo was written

Run these once on a machine with Docker and the Compose plugin:

- [ ] Merged Compose config: ports replaced (not appended), dashboard only on `127.0.0.1:5601`,
  mounts pointing at `/opt/wazuh/deploy`. On the *server* after a deploy:
  ```
  cd /opt/wazuh/wazuh-docker/single-node
  sudo docker compose -f docker-compose.yml -f /opt/wazuh/deploy/docker-compose.override.yml config \
    | grep -E -A12 'ports:|/opt/wazuh/deploy'
  ```
- [ ] With MCP enabled: `wazuh-mcp` is on the same network, publishes only `127.0.0.1:3000`, and no
  other service gained ports:
  ```
  sudo docker compose -f docker-compose.yml -f /opt/wazuh/deploy/docker-compose.override.yml \
    -f /opt/wazuh/deploy/docker-compose.mcp.yml config | grep -E -B2 -A8 'ports:|networks:'
  ```
- [ ] `xmllint --noout` on the rule and decoder files (they were checked for well-formedness with a
  Python XML parser instead).
