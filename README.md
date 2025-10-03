# Homelab Enterprise Security Stack (Deployment-Ready)
# 🛡️ Homelab Enterprise Security Stack

This repository contains a **self-hosted Enterprise Security Stack** — a full SOC/XDR platform that mirrors and in some areas exceeds the capabilities of commercial solutions like **SentinelOne, CrowdStrike Falcon, Splunk ES, Cortex XSOAR, QRadar, Exabeam, and ServiceNow SecOps**.

It is designed and deployed on a Proxmox + Kubernetes homelab cluster, serving as both a **learning lab** and a **portfolio showcase** for enterprise-grade cybersecurity engineering.

---

## ✅ CI/CD Status

![Lint](https://github.com/jharr665/Homelab-Enterprise-Security-Stack/actions/workflows/lint.yml/badge.svg)
![Conftest](https://github.com/jharr665/Homelab-Enterprise-Security-Stack/actions/workflows/conftest.yml/badge.svg)
![Trivy](https://github.com/jharr665/Homelab-Enterprise-Security-Stack/actions/workflows/trivy.yml/badge.svg)

---

## 📊 Architecture Diagram

```mermaid
flowchart TD
  subgraph Enterprise_Security_Stack[Homelab Enterprise Security Stack]
    EDR[EDR/XDR\nOSQuery, Sysmon, Auditd, Falco, Velociraptor, Tetragon]
    SIEM[SIEM\nWazuh, Security Onion, Grafana]
    SOAR[SOAR\nn8n + TheHive]
    NDR[NDR\nZeek, Suricata, CrowdSec]
    TIP[TIP\nMISP, IOC feeds]
    UEBA[UEBA\nZeek + Authentik + Grafana Anomalies]
    IR[IR\nTheHive + Runbooks]
    VM[Vuln Mgmt\nOpenVAS, Trivy, Grype, kube-bench]
    DFIR[DFIR\nVelociraptor, Autopsy, Proxmox Snapshots]
    SupplyChain[Supply Chain\nHarbor, Cosign, Rekor, Kyverno]
  end

  %% Data Flows
  EDR --> SIEM
  NDR --> SIEM
  TIP --> SIEM
  UEBA --> SIEM
  VM --> SIEM
  DFIR --> IR
  SIEM --> SOAR
  SOAR --> IR
  SupplyChain --> SIEM
