# 💡 Argus End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/argus`](https://github.com/bonjoski/argus)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Argus** is a pre-flight supply-chain interceptor and real-time SIEM killswitch bus for autonomous AI agents and developer workstations. It intercepts package installations before network resolution, detecting LLM-hallucinated packages, typosquatting, slopsquatting, and malicious installation hooks without sending code to external SaaS clouds.

This directory provides concrete, task-oriented recipes for common developer and DevSecOps workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Pre-Flight Slopsquat Interception](01-preflight-slopsquat-interception.md)** | Block hallucinated or typosquatted packages before `npm`/`pip`/`cargo` reaches the network. | `argus exec -- npm install <pkg>`<br/>`argus-shim` | Pre-Flight Shell Interception |
| **[02. Offline Package Reputation Inspection](02-offline-package-inspection.md)** | Inspect package age, release velocity, and Levenshtein similarity against canonical registries. | `argus inspect npm <pkg>@<ver>`<br/>`argus explain <pkg>` | Local Quarry Engine |
| **[03. SIEM Killswitch Bus Daemon](03-siem-killswitch-daemon.md)** | Run the local event bus daemon to broadcast instant revocation alerts to Fabrial and Locksmith. | `argus daemon start`<br/>`argus ping` | Unix Domain Socket Bus |
| **[04. CI/CD Supply Chain Gate](04-cicd-supply-chain-gate.md)** | Automatically audit new dependencies in pull requests within GitHub Actions. | `argus diff --manifest package.json` | CI Pull Request Gate |
