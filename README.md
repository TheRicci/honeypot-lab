# 🛡️ Security Monitoring Stack
## Comprehensive Honeypot & SIEM Architecture

---

## 🎯 Objective
Design and implement a proof-of-concept honeypot ecosystem, containerized with Docker, that integrates IDS and SIEM tools to capture, organize, and generate alerts for potential security threats.  

---

## 📊 Traffic Flow

```
🌐 Internet Traffic → 🔒 ModSec Proxy → 🍯 Honeypot → 📈 SIEM Analysis
```

---

## 🌐 Network Architecture

### 🍯 HoneyNet
> **Purpose:** Attack detection and analysis network

| Service | Description | Ports | Key Features |
|---------|-------------|-------|--------------|
| **🍯 Honeypot (Go)** | Main honeypot service with Wazuh agent integration | - | Privileged mode, SIEM connectivity |
| **🛡️ ModSec Proxy** | NGINX + ModSecurity Web Application Firewall | `80:80`, `443:443`, `990:990` | OWASP CRS, SSL/TLS |
| **🔍 Suricata IDS** | Network intrusion detection system | - | AF-PACKET, Auto-FP, Custom rules |
| **📊 Zeek Network Monitor** | Network security monitoring & analysis | - | Custom logging, Protocol analysis |

### 🔧 SIEM Network
> **Purpose:** Security information and event management

| Service | Description | Ports | Key Features |
|---------|-------------|-------|--------------|
| **⚡ Wazuh Manager** | Central SIEM management & correlation engine | `1514:1514`, `1515:1515`, `514:514/udp`, `55000:55000` | All security tools logging |
| **🔍 Wazuh Indexer** | OpenSearch-based data indexing & storage | `9200:9200` | SSL/TLS, Authentication |
| **📊 Wazuh Dashboard** | Web-based security analytics dashboard | `5601:5601` | Real-time monitoring, Alerting |
| **🚀 Threat Central** | Custom threat intelligence service | - | Threat analysis & correlation |
| **📋 FluentBit** | Log processor & forwarder | - | ModSec, Suricata, Wazuh logs |

---

## 🔄 Service Dependencies

```mermaid
graph TD
    A[🌐 Internet] --> B[🛡️ ModSec Proxy]
    B --> C[🍯 Honeypot]
    B --> D[🔍 Suricata]
    B --> E[📊 Zeek]
    
    C --> F[⚡ Wazuh Manager]
    D --> F
    E --> F
    B --> F
    
    F --> G[🔍 Wazuh Indexer]
    G --> H[📊 Wazuh Dashboard]

    D --> I[📋 FluentBit]
    B --> I
    F --> I

    I[📋 FluentBit] --> J[🚀 Threat Central]
    
    classDef honeynet fill:#ff6b6b,stroke:#ff6b6b,stroke-width:2px,color:#fff
    classDef siemnet fill:#4ecdc4,stroke:#4ecdc4,stroke-width:2px,color:#fff
    classDef external fill:#ffa500,stroke:#ffa500,stroke-width:2px,color:#fff
    
    class B,C,D,E honeynet
    class F,G,H,I,J siemnet
    class A external
```

---

## 📈 Stack Statistics

| Metric | Count | Description |
|--------|-------|-------------|
| **🔧 Services** | 10 | Total containerized services |
| **🌐 Networks** | 2 | Isolated network segments |
| **🚪 Exposed Ports** | 7 | External access points |
| **💾 Volumes** | 15 | Persistent data storage |

---

## 🤔 Why Wazuh?

Wazuh was chosen as the core SIEM for this stack because it offers several unique advantages:

🖥️ Agent-Based Monitoring
Wazuh provides lightweight agents that run directly on endpoints and containers. These agents collect logs, monitor processes, file integrity, and system activity, giving deep visibility into what’s happening inside the honeypot.

📋 Strong Baseline Detection
In a tightly controlled and fully patched environment, Wazuh can detect deviations from the expected baseline. If a compromise occurs despite all services being up to date, this strongly suggests exploitation of an unknown (0day) vulnerability.

⚡ Real-Time Correlation
The Wazuh Manager correlates data from multiple sources (honeypot logs, IDS alerts, network monitors, and system telemetry) to identify complex attack patterns that individual tools may miss.

🌍 Threat Intelligence Integration
Wazuh supports integration with external threat feeds, allowing correlation between live attacks and known malicious indicators — and extending with custom services like Threat Central in this project.

🔐 Security Ecosystem Compatibility

Built-in support for Suricata, Zeek, and ModSecurity logs

SSL/TLS support for secure communication

Strong API and dashboard for visualization

📊 Open & Extensible
As an open-source SIEM, Wazuh allows full customization of rules, decoders, and alerts, making it ideal for a research-oriented honeypot ecosystem.

---

## 🏗️ Architecture Overview

### Security Layers

1. **🌐 Entry Point**
   - ModSecurity WAF with OWASP Core Rule Set
   - SSL/TLS termination
   - Traffic analysis and logging

2. **🍯 Detection Layer**
   - Go-based honeypot for attack simulation
   - Suricata IDS for network intrusion detection
   - Zeek for deep packet inspection and analysis

3. **📊 Analysis Layer**
   - Wazuh SIEM for event correlation
   - Custom threat intelligence integration
   - Real-time alerting and response

4. **💾 Storage Layer**
   - OpenSearch-based indexing
   - Persistent log storage
   - Historical analysis capabilities

### Network Segmentation

#### HoneyNet (`honeynet`)
- **Purpose:** Isolated environment for attack detection
- **Services:** Honeypot, ModSec Proxy, Suricata, Zeek
- **Security:** DMZ-like setup with controlled external access

#### SIEM Network (`siemnet`)
- **Purpose:** Security management and analysis
- **Services:** Wazuh stack, Threat Central, FluentBit
- **Security:** Internal network with authenticated access

---

## 🔐 Security Features

### 🛡️ Protection Mechanisms
- **Web Application Firewall** - ModSecurity with OWASP CRS
- **Network IDS** - Suricata with custom rules
- **Deep Packet Inspection** - Zeek network analysis
- **SSL/TLS Encryption** - Certificate-based security
- **Access Control** - Network segmentation and authentication

### 📋 Monitoring Capabilities
- **Real-time Alerts** - Immediate threat notification
- **Log Aggregation** - Centralized logging via FluentBit
- **Event Correlation** - Wazuh rule-based analysis
- **Threat Intelligence** - Custom threat data integration
- **Historical Analysis** - Long-term trend analysis

### 🔄 Data Flow
1. External traffic hits ModSec Proxy
2. Decrypted traffic reaches honeypot services
3. All interactions logged by monitoring tools
4. Logs processed and forwarded to Wazuh
5. Events correlated and alerts generated
6. Data indexed for analysis and reporting

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone <your-repo-url>

# Start the security stack
docker-compose up -d

# Access dashboards
echo "Wazuh Dashboard: https://localhost:5601"
echo "Wazuh API: https://localhost:55000"
```

---

## 📝 Configuration Files

| Component | Configuration |
|-----------|---------------|
| **ModSecurity** | `./modsecurity/modsecurity.conf` |
| **Suricata** | `./suricata/suricata.yaml` |
| **Zeek** | `./zeek/site/custom-logging.zeek` |
| **Wazuh** | `./config/wazuh_cluster/wazuh_manager.conf` |
| **FluentBit** | `./fluent-bit/fluent-bit.conf` |

---

*This architecture provides comprehensive security monitoring with honeypot capabilities, network intrusion detection, and centralized SIEM analysis.*
