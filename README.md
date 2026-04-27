# Red-Threat-Redemption SIEM

[![Engine: Elasticsearch](https://img.shields.io/badge/Engine-Elasticsearch-red.svg)](https://www.elastic.co/)
[![Endpoint Security: Wazuh](https://img.shields.io/badge/Endpoint_Security-Wazuh-blue.svg)](https://wazuh.com/)
[![NSM: Zeek](https://img.shields.io/badge/NSM-Zeek-green.svg)](https://zeek.org/)
[![IDS/IPS: Suricata](https://img.shields.io/badge/IDS-Suricata-orange.svg)](https://suricata.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  

## Overview
Red-Threat-Redemption is an open-source SIEM (Security Information and Event Management) stack. The name is inspired by epic *Red Dead Redemption 2*. Built on Debian 13 in a Proxmox VM, it integrates Elasticsearch & Kibana, Filebeat & Vector for logs parsing, Wazuh Manager for endpoints security, Zeek for network analysis on a secondary SPAN/Port-based NIC, pfSense logs ingestion for Suricata, pfBlockerNG and syslog.  

This repo provides step-by-step guides to deploy a high-performance SIEM for threat detection, log aggregation, and visualization. Optimized for 24GB RAM, 4 cores, and secure configurations. No plaintext passwords, minimal footprint, and best practices for efficiency.

---
---

### SOC Overview Dashboard

![SOC_Overview](https://github.com/user-attachments/assets/fb4a7534-f895-4ae9-b2cf-73b08c8a2b60)

---
---

### Threat Intelligence & Threat Hunting

![Threat_Hunting](https://github.com/user-attachments/assets/92dfb330-f219-4a0a-a28b-9e6e3a8525b3)

---
---

## Wazuh Endpoint Security Dashboard

![Wazuh_Endpoint_Security](https://github.com/user-attachments/assets/dbbac13a-843b-4197-aeb0-eb8e4981c876)

---
---

### Key Features
- **Minimal Debian 13 Base**: Hardened OS setup with LVM partitioning for flexible storage.  
- **Elastic Stack with Vector**: Elasticsearch for storage/search, Kibana for visualization, Filebeat and Vector for logs parsing.  
- **Wazuh Integration**: Security monitoring with alerts ingested into Elasticsearch.  
- **Zeek Network Monitoring**: Passive analysis on PCI passthrough NIC.  
- **pfSense Logs**: System syslog, Suricata and pfBlocker logs ingestion.  
- **Security Focus**: TLS, keystores for secrets, no swap, high file limits.  

## Prerequisites
- Proxmox VE hypervisor with IOMMU enabled (This guide is focused on Proxmox VE but you can setup the infrastructure with any Hypervisor).  
- Basic Linux knowledge.  
- Hardware: 24GB RAM, 4 cores, 220GB storage, 2 NICs (the secondary NIC should be setup for SPAN/Mirror from your switch management, mirroring the port you want to monitor traffic.

## Installation Guides
Follow these guides in sequence. Each is self-contained but builds on the previous.

### 1. Debian 13 Installation and Configuration
[Debian Setup](01.%20Valentine%20%7C%20Debian%2013.md)
- VM setup on Proxmox VE.  
- Minimal netinst install with LVM partitioning.  
- Hardening and tuningg.

### 2. ELK Stack & Wazuh Setup
[Core SIEM stack Guide](02.%20%20Cores%20%7C%20SIEM%20Stack.md)  
- Install Elasticsearch, Kibana, Filebeat, Vector and Wazuh Manager.  
- Secure configurations (TLS, keystores for passwords).  
- Vector pipeline for Wazuh alerts.  
- Kibana data views.

### 3. Zeek Integration (Proxmox PCI Passthrough NIC)
[Zeek Guide](03.%20Dead%20Eye%20%7C%20Zeek-Filebeat.md)  
- Add and verify PCI NIC.  
- Install and configure Zeek.
- Kibana data view for Zeek.

### 4. pfSense Logs Integration
[pfSense Guide](04.%20Fence%20%7C%20pfSense-pfBlocker-Suricata.md) 
- Install and configure Syslog-ng.
- Configure system logs for Syslog-ng.
- Configure Syslog-ng for Suricata
- Configure cron job for pfBlockerNG.
- Vector pipelines for ingestion and parsing.  
- Kibana data views for Suricata, pfSense syslog and pfBlockerNG.

### 5. GeoIP Enrichment
[GeoIP](05.%20Talisman%20%7C%20GeoIP%20Enrichment.md)
- Integrate MaxMind and download GeoLite2-City.mmdb
- Update Vector transforms and sinks
- Add Elasticsearch Index Templates

### 6. Wazuh Agents & Endpoint enrollment
[Wazuh Agents](06.%20Pinkertons%20%7C%20Wazuh-Agents.md)
- Manage agent and key for CLI
- Create and assign groups
- Agents installation guide for Windows & Linux

### 7. Kibana Dashboards
[Kibana](07.%20Trinkets%20%7C%20Kibana%20Dashboards.md)
- Setup SOC Overview Dashboard
- Setup Threat Hunting Dashboard
- Setup Wazuh Security Dashboard

### 8. TraceMarshal SOC Agent
[Tracemarshal](08.%20TraceMarshal-SOC-Agent)
- Integrate an OpenClaw AI SOC Agent to SIEM
- Threat detection, incident triage and log correlation
- Scheduled reporting and alerts communication via dedicated channel

## Usage
1. Clone the repo.
2. Follow the guides sequentially.  
3. Access Kibana.
4. Monitor dashboards in Kibana for Wazuh alerts, Zeek events, and pfSense logs.  
5. Tune Vector configs in `/etc/vector/vector.yaml` for additional sources.

## Troubleshooting
Common issues when you customize it across guides:  
- **Connection Failures**: Verify TLS certs and secrets.  
- **Log Ingestion**: Check vector.yaml, inspect service logs for parse issues.
- **Performance**: Monitor RAM; adjust ES heap if needed.
- Refer to individual guides for tool-specific troubleshooting.

## License
MIT License. See [LICENSE](./LICENSE) for details.

## Acknowledgments
- Inspired by *Red Dead Redemption 2* for thematic naming to separate the componets for a memoprable repo.  
- Thanks to Elastic, Wazuh, Vector, Zeek, and pfSense communities.  
- Built for cybersecurity enthusiasts.

