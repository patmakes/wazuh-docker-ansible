#!/usr/bin/env bash
# Exercise the Wazuh MCP endpoint and (on the Wazuh host) confirm the provisional
# decoders/rules against the real log lines it produced.
#
# It makes: read tool calls (agents, alerts, vulnerabilities), one refused write call,
# and six bad-token requests. No Claude tooling: plain curl + python3 for JSON.
#
# On the Wazuh host (default; also captures logs and runs wazuh-logtest):
#     sudo scripts/mcp-log-samples.sh
# From an MCP client host (smoke test only, over the tailnet):
#     MCP_URL=https://<wazuh-magicdns>:8443 MCP_API_KEY=wazuh_... scripts/mcp-log-samples.sh --no-logtest
#
# Environment:
#   MCP_URL            base URL (default http://127.0.0.1:3000)
#   MCP_API_KEY        API key (default: read from /opt/wazuh/deploy/mcp.env, needs root)
#   MANAGER_CONTAINER  default single-node-wazuh.manager-1
#   OUT_DIR            where captured lines and logtest output go (default: a new temp dir)
set -euo pipefail

MCP_URL="${MCP_URL:-http://127.0.0.1:3000}"
MCP_ENV_FILE="${MCP_ENV_FILE:-/opt/wazuh/deploy/mcp.env}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
PROTOCOL_VERSION="2025-06-18"
RUN_LOGTEST=1
[ "${1:-}" = "--no-logtest" ] && RUN_LOGTEST=0

for bin in curl python3; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

if [ -z "${MCP_API_KEY:-}" ]; then
  [ -r "$MCP_ENV_FILE" ] || { echo "Set MCP_API_KEY or run as root on the Wazuh host ($MCP_ENV_FILE not readable)." >&2; exit 1; }
  MCP_API_KEY="$(sed -n "s/^MCP_API_KEY='\{0,1\}\([^']*\)'\{0,1\}$/\1/p" "$MCP_ENV_FILE")"
fi

OUT_DIR="${OUT_DIR:-$(mktemp -d)}"
mkdir -p "$OUT_DIR"
START="$(date '+%Y-%m-%d %H:%M:%S')"
FAILED=0

json_field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

echo "== health"
curl -fsS "$MCP_URL/health" | json_field 'd.get("status")'

echo "== token (POST /auth/token)"
TOKEN="$(curl -fsS -X POST "$MCP_URL/auth/token" -H 'Content-Type: application/json' \
  -d "{\"api_key\": \"$MCP_API_KEY\"}" | json_field 'd["access_token"]')"
echo "ok"

# rpc <session-id-or-empty> <json body>  -> response body on stdout
rpc() {
  local session="$1" body="$2"
  local -a hdr=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json'
    -H 'Accept: application/json' -H "MCP-Protocol-Version: $PROTOCOL_VERSION")
  [ -n "$session" ] && hdr+=(-H "MCP-Session-Id: $session")
  curl -sS -X POST "$MCP_URL/mcp" "${hdr[@]}" -d "$body"
}

echo "== initialize"
INIT_HEADERS="$OUT_DIR/initialize.headers"
curl -sS -D "$INIT_HEADERS" -o "$OUT_DIR/initialize.json" -X POST "$MCP_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"$PROTOCOL_VERSION\",\"capabilities\":{},\"clientInfo\":{\"name\":\"mcp-log-samples\",\"version\":\"1\"}}}"
SESSION="$(tr -d '\r' < "$INIT_HEADERS" | awk 'tolower($1)=="mcp-session-id:" {print $2}')"
json_field 'd["result"]["serverInfo"]' < "$OUT_DIR/initialize.json"
[ -n "$SESSION" ] || { echo "no MCP-Session-Id returned" >&2; exit 1; }
rpc "$SESSION" '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

echo "== tools/list"
rpc "$SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' > "$OUT_DIR/tools-list.json"
json_field '"%d tools" % len(d["result"]["tools"])' < "$OUT_DIR/tools-list.json"

# call <id> <tool> <arguments json> <expect: ok|refused>
call() {
  local id="$1" tool="$2" args="$3" expect="$4" out="$OUT_DIR/call-$2.json" is_error
  rpc "$SESSION" "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}" > "$out"
  is_error="$(json_field '("error" in d) or bool(d.get("result", {}).get("isError"))' < "$out")"
  if { [ "$expect" = ok ] && [ "$is_error" = False ]; } || { [ "$expect" = refused ] && [ "$is_error" = True ]; }; then
    echo "PASS  $tool ($expect)"
  else
    echo "FAIL  $tool (expected $expect) -> $out"; FAILED=1
  fi
  [ "$expect" = refused ] && json_field '(d.get("error") or {}).get("message") or d["result"]["content"][0]["text"][:200]' < "$out" || true
}

echo "== read tools"
call 3 get_wazuh_agents '{"limit": 5}' ok
call 4 get_wazuh_alerts '{"limit": 5}' ok
call 5 get_wazuh_vulnerabilities '{"limit": 5}' ok

echo "== write tool with a read-only token (must be refused; 192.0.2.1 is a documentation address)"
call 6 wazuh_block_ip '{"ip_address": "192.0.2.1", "agent_id": "000"}' refused

echo "== six requests with a bad token (expect 401)"
for _ in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w '%{http_code} ' -X POST "$MCP_URL/mcp" -H 'Authorization: Bearer not-a-valid-token' \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -d '{"jsonrpc":"2.0","id":9,"method":"tools/list"}'
done
echo

echo "Tools exercised: get_wazuh_agents, get_wazuh_alerts, get_wazuh_vulnerabilities (read); wazuh_block_ip (refused write)."
echo "Responses saved in $OUT_DIR"

if [ "$RUN_LOGTEST" = 1 ]; then
  command -v journalctl >/dev/null && command -v docker >/dev/null || { echo "journalctl/docker not found: use --no-logtest off the Wazuh host" >&2; exit 1; }
  sleep 3
  echo "== captured log lines (journald tag wazuh-mcp) -> $OUT_DIR/captured.log"
  journalctl -t wazuh-mcp --since "$START" -o short --no-pager | grep -v '^-- ' > "$OUT_DIR/captured.log" || true
  wc -l < "$OUT_DIR/captured.log"
  echo "== wazuh-logtest -> $OUT_DIR/logtest.txt"
  docker exec -i "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-logtest < "$OUT_DIR/captured.log" > "$OUT_DIR/logtest.txt" 2>&1 || true
  echo "Rules matched (count, id):"
  grep -oE "id: '[0-9]+'" "$OUT_DIR/logtest.txt" | sort | uniq -c || true
  echo "Expected: 100101 (read calls), 100107 and 100104 (bad tokens), 100106 (probes)."
  echo "Not expected: 100102/100103/100105. Upstream v5.0.0 does not log a scope-refused write call."
  echo "== manager API log lines for the MCP service account -> $OUT_DIR/api-captured.log"
  docker exec "$MANAGER_CONTAINER" grep -F ' mcp-readonly ' /var/ossec/logs/api.log | tail -n 20 > "$OUT_DIR/api-captured.log" || true
  docker exec -i "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-logtest < "$OUT_DIR/api-captured.log" > "$OUT_DIR/api-logtest.txt" 2>&1 || true
  grep -oE "id: '[0-9]+'" "$OUT_DIR/api-logtest.txt" | sort | uniq -c || true
  echo "Expected: 100112 (GET /agents ...), 100109 (logins). Not expected: 100113, 100114."
  echo "Send $OUT_DIR/captured.log and logtest.txt back if a line decodes wrongly, so the rules can be fixed."
fi

exit "$FAILED"
