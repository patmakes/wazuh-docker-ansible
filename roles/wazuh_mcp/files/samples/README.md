# MCP log samples (derived, not captured)

These lines were written from the upstream source at tag `v5.0.0`
(`monitoring.JsonLogFormatter`, uvicorn's access log format, and the
`wazuh_mcp_server.audit` calls in `server.py`), in the syslog form the Wazuh journald
collector forwards. Lines 13-17 are manager `api.log` lines, written from Wazuh v4.14.8
`api/api/alogging.py`. They were **not** captured from a running container, and they have
**not** been run through `wazuh-logtest`.

`expected.tsv` lists the rule each line is meant to match. After deploying, run
`scripts/mcp-log-samples.sh` on the Wazuh host to capture real lines and check them.
