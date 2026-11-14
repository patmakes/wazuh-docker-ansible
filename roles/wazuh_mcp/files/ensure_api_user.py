"""Idempotently create the read-only Wazuh API user for the MCP server.

Run inside the manager container with Wazuh's bundled Python, fed on stdin:
    docker exec -i <manager> /var/ossec/framework/python/bin/python3 -
Talks only to https://localhost:55000 (the API port is never published).

Environment: API_ADMIN_USER, API_ADMIN_PASSWORD, MCP_USER, MCP_PASSWORD.
Prints one JSON line: {"changed": bool, "actions": [...]}.
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://localhost:55000"
CTX = ssl._create_unverified_context()  # loopback inside the container; stock self-signed cert

# Read actions only, one policy per resource type (upstream WAZUH_COMPATIBILITY.md and
# docs/security/README.md). No active-response:command, agent:restart or manager:restart.
POLICIES = {
    "agents": (["agent:read", "syscollector:read", "syscheck:read", "sca:read"], ["agent:id:*"]),
    "groups": (["group:read"], ["group:id:*"]),
    "rules": (["rules:read"], ["rule:file:*"]),
    "manager": (["manager:read"], ["*:*:*"]),
    "cluster": (["cluster:read"], ["node:id:*"]),
}


def request(method, path, token=None, basic=None, body=None, query=None):
    url = API + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(":".join(basic).encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def authenticate(user, password):
    status, text = request("POST", "/security/user/authenticate", basic=(user, password), query={"raw": "true"})
    return text.strip() if status == 200 else None


def call(method, path, token, body=None, query=None):
    """API call that must fully succeed; returns data.affected_items."""
    status, text = request(method, path, token=token, body=body, query=query)
    try:
        payload = json.loads(text)
    except ValueError:
        payload = {}
    data = payload.get("data") or {}
    if status != 200 or payload.get("error", 0) != 0 or data.get("total_failed_items", 0):
        sys.exit("Wazuh API %s %s failed (HTTP %s): %s" % (method, path, status, text[:500]))
    return data.get("affected_items", [])


def main():
    admin_user = os.environ["API_ADMIN_USER"]
    mcp_user = os.environ["MCP_USER"]
    mcp_password = os.environ["MCP_PASSWORD"]
    actions = []

    token = authenticate(admin_user, os.environ["API_ADMIN_PASSWORD"])
    if not token:
        sys.exit("Could not authenticate to the Wazuh API as %s" % admin_user)

    # Policies
    existing = {p["name"]: p for p in call("GET", "/security/policies", token, query={"limit": 500})}
    policy_ids = []
    for suffix, (acts, resources) in POLICIES.items():
        name = "%s-%s" % (mcp_user, suffix)
        wanted = {"actions": acts, "resources": resources, "effect": "allow"}
        current = existing.get(name)
        if current is None:
            created = call("POST", "/security/policies", token, body={"name": name, "policy": wanted})
            policy_ids.append(created[0]["id"])
            actions.append("created policy " + name)
        else:
            policy_ids.append(current["id"])
            have = current.get("policy", {})
            if (sorted(have.get("actions", [])) != sorted(acts)
                    or sorted(have.get("resources", [])) != sorted(resources)
                    or have.get("effect") != "allow"):
                call("PUT", "/security/policies/%s" % current["id"], token, body={"policy": wanted})
                actions.append("updated policy " + name)

    # Role
    roles = {r["name"]: r for r in call("GET", "/security/roles", token, query={"limit": 500})}
    role = roles.get(mcp_user)
    if role is None:
        role = call("POST", "/security/roles", token, body={"name": mcp_user})[0]
        actions.append("created role " + mcp_user)
    missing = [pid for pid in policy_ids if pid not in role.get("policies", [])]
    if missing:
        call("POST", "/security/roles/%s/policies" % role["id"], token,
             query={"policy_ids": ",".join(str(p) for p in missing)})
        actions.append("linked %d policies to role" % len(missing))
    extra = [pid for pid in role.get("policies", []) if pid not in policy_ids]
    if extra:
        call("DELETE", "/security/roles/%s/policies" % role["id"], token,
             query={"policy_ids": ",".join(str(p) for p in extra)})
        actions.append("unlinked %d unexpected policies from role" % len(extra))

    # User
    users = {u["username"]: u for u in call("GET", "/security/users", token, query={"limit": 500})}
    user = users.get(mcp_user)
    if user is None:
        user = call("POST", "/security/users", token, body={"username": mcp_user, "password": mcp_password})[0]
        actions.append("created user " + mcp_user)
    elif not authenticate(mcp_user, mcp_password):
        call("PUT", "/security/users/%s" % user["id"], token, body={"password": mcp_password})
        actions.append("updated password of " + mcp_user)
    if role["id"] not in user.get("roles", []):
        call("POST", "/security/users/%s/roles" % user["id"], token, query={"role_ids": str(role["id"])})
        actions.append("linked role to user")
    extra = [rid for rid in user.get("roles", []) if rid != role["id"]]
    if extra:
        call("DELETE", "/security/users/%s/roles" % user["id"], token,
             query={"role_ids": ",".join(str(r) for r in extra)})
        actions.append("unlinked %d unexpected roles from user" % len(extra))

    print(json.dumps({"changed": bool(actions), "actions": actions}))


if __name__ == "__main__":
    main()
