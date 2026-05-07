# Red-Threat-Redemption - TraceMarshal SOC Agent

---
## Architecture Overview
---

<img width="1386" height="922" alt="{B8035B7A-72A6-43A8-BFCF-D08C75CAE0F7}" src="https://github.com/user-attachments/assets/1dba5bab-3679-41c0-93fd-2416cdf63d1b" />


---

TraceMarshal agent runs on a **separate device in a dedicated VLAN**, connecting to Elasticsearch on the Red Dead Redemption SIEM host over a cross-VLAN firewall rule. The SIEM has **no internet access**. The agent device has internet access for LLM API calls, IOC enrichment, and package installations.

---

## Network Requirements

### Firewal rules
|Rule|Source|Destination|Port|Proto|Purpose|
|---|---|---|---|---|---|
|ALLOW|Agent Host (Agent VLAN)|SIEM Host (SIEM VLAN)|9200|TCP/TLS|Elasticsearch queries|
|ALLOW|Agent Host|Internet|443|TCP|LLM API, threat intel, npm|

Elasticsearch on the SIEM host must bind to its VLAN IP (not just localhost) and accept TLS connections from the agent host. The Elasticsearch CA certificate must be copied to the agent host manually.

# Deployment Steps

### 1. SIEM Host: Expose Elasticsearch to Agent VLAN

Edit `/etc/elasticsearch/elasticsearch.yml` on the SIEM host:

```yaml
# Bind to SIEM VLAN IP
network.host: ["127.0.0.1", "<SIEM_IP>"]
```

Restart Elasticsearch:

```
sudo systemctl restart elasticsearch
```

### 2. Create a read-only API key for TraceMarshal queries:

**Kibana - Dev Tools**
```
POST /_security/api_key
{
  "name": "tracemarshal-direct",
  "role_descriptors": {
    "siem-readonly": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["logs-*", "zeek-*"],
          "privileges": ["read", "view_index_metadata"]
        }
      ]
    }
  }
}
```

### 3. Copy Elasticsearch CA certificate to the agent host:

```bash
# From SIEM host via SCP or manually
scp /etc/elasticsearch/certs/http_ca.crt user@<AGENT_HOST_IP>:/path/http-ca.crt
```

Block all other cross-VLAN traffic between these VLANs.

### 4. Agent Host: Install OpenClaw

```
Follow the latest OpenClaw official instructions for the installation.
```
**Follow Openclaw initial wizard to set:**
1. Agent worksapce
2. LLM authentication and model
3. Telegram (or any other channel)

### 5. Agent Host: Deploy Workspace Files
```
git clone repository or mannually copy/edit the workspace files at ~/.openclaw/workspace directory
```

### 6. Agent Host: Add secrets to .env file
**Remember to update openclaw.json every time after you update or after ran openclaw doctor with the .env variables**  
**Create .env file in ~/.openclaw/ directory and set secrets in order to set them later in openclaw.json**
```
touch ~/.openclaw/.env
chmod 600 ~/.openclaw/.env
```
**Add secrets and save**
```
# Telegram
TELEGRAM_BOT_TRACEMARSHAL=telegram_token

# Brave search
BRAVE_API_KEY=brave_api__key

# Gateway
OPENCLAW_GATEWAY_TOKEN=openclaw_gw_token

# Elasticsearch
ES_HOST=https://SIEM-IP:9200
ES_API_KEY=your_key
ES_CA_CERT=the path you copied Elasticsearch CA certificate
```

### 7. Configure openclaw.json
**Example with openai-codex and .env variables**

```
{
  "auth": {
    "profiles": {
      "openai-codex:default": {
        "provider": "openai-codex",
        "mode": "oauth"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "openai-codex/gpt-5.3-codex",
        "fallbacks": [
          "openai-codex/gpt-5.2",
          "openai-codex/gpt-5.2-codex"
        ]
      },
      "models": {
        "openai-codex/gpt-5.3-codex": {},
        "openai-codex/gpt-5.2": {},
        "openai-codex/gpt-5.2-codex": {}
      },
      "workspace": "/home/user/.openclaw/workspace",
      "compaction": {
        "mode": "safeguard"
      },
      "maxConcurrent": 4,
      "subagents": {
        "maxConcurrent": 8
      }
    },
    "list": [
      {
        "id": "main",
        "name": "TraceMarshal",
        "workspace": "/home/user/.openclaw/workspace",
        "agentDir": "/home/user/.openclaw/agents/main/agent",
        "model": {
          "primary": "openai-codex/gpt-5.3-codex",
          "fallbacks": [
            "openai-codex/gpt-5.2",
            "openai-codex/gpt-5.2-codex"
          ]
        },
        "subagents": {
          "allowAgents": []
        },
        "tools": {
          "profile": "coding",
          "allow": ["web_search", "web_fetch"]
        }
      }
    ]
  },
  "bindings": [
    {
      "agentId": "main",
      "match": {
        "channel": "telegram",
        "accountId": "default"
      }
    }
  ],
  "tools": {
    "web": {
      "search": {
        "enabled": true,
        "provider": "brave",
        "apiKey": "${BRAVE_API_KEY}"
      },
      "fetch": {
        "enabled": true
      }
    },
    "exec": {
      "host": "gateway",
      "security": "full",
      "ask": "off"
    }
  },
  "messages": {
    "ackReactionScope": "group-mentions"
  },
  "commands": {
    "native": "auto",
    "nativeSkills": "auto",
    "restart": true,
    "ownerDisplay": "raw"
  },
  "session": {
    "dmScope": "per-channel-peer"
  },
  "hooks": {
    "internal": {
      "enabled": true,
      "entries": {
        "boot-md": { "enabled": true },
        "session-memory": { "enabled": true },
        "command-logger": { "enabled": true }
      }
    }
  },
  "channels": {
    "telegram": {
      "enabled": true,
      "accounts": {
        "default": {
          "botToken": "${TELEGRAM_BOT_TRACEMARSHAL}",
          "dmPolicy": "pairing",
          "groupPolicy": "allowlist",
          "streaming": "off"
        }
      }
    }
  },
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    },
    "tailscale": {
      "mode": "off",
      "resetOnExit": false
    },
    "nodes": {
      "denyCommands": [
        "camera.snap",
        "camera.clip",
        "screen.record",
        "calendar.add",
        "contacts.add",
        "reminders.add"
      ]
    }
  },
  "skills": {
    "install": {
      "nodeManager": "npm"
    }
  },
  "plugins": {
    "entries": {
      "telegram": { "enabled": true }
    }
  }
}
```

### 8. Restart OpenClaw Gateway and perform health checks

```
openclaw gateway restart
openclaw gateway status

openclaw status

openclaw logs --follow

openclaw doctor
openclaw doctor --fix
```
