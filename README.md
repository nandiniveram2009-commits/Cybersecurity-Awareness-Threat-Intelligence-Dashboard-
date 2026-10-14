# Cybersecurity-Awareness-Threat-Intelligence-Dashboard-
Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&amp;CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.”
# Cybersecurity Awareness & Threat Intelligence Dashboard

> A unified defensive cybersecurity engineering platform bridging automated Cyber Threat Intelligence (CTI) ingestion, IOC normalization, multi-factor risk scoring, MITRE ATT&CK mapping, and frontline human security awareness training.

## Overview
The Cybersecurity Awareness & Threat Intelligence Dashboard is an industry-oriented defensive cybersecurity project engineered to address the twin pillars of modern organizational security: technical machine telemetry and human defense behavior.

## Problem Statement
1. Alert Fatigue & IOC Overload: Thousands of disconnected indicators without standardized syntactic validation or confidence context.
2. Context-Free Prioritization: Relying strictly on raw CVSS scores fails to reflect true exposure.
3. The Human-Telemetry Disconnect: Threat intelligence rarely informs employee awareness training in real time.

## Objectives
- Ingest and parse 2,100+ safe, sanitized RFC-compliant synthetic threat records.
- Implement strict regex and boundary validation for IPv4, IPv6, FQDNs, URLs, Hashes, and CVEs.
- Mathematical multi-factor risk scoring: Severity 30%, Confidence 25%, Recency 15%, Sightings 10%, Source 10%, Context 10%.
- Anti-fatigue alert correlation merging repeat sightings into single actionable tickets.
- Contextual vulnerability prioritization combining CVSS, asset criticality, and exposure.
- 15 comprehensive awareness modules and a 32-question diagnostic quiz.
- Executive cybersecurity reporting with one-click export.

## Cybersecurity Relevance
Applicable across SOCs, Banks (FS-ISAC), Cloud Providers, Healthcare, and MSSPs. Demonstrates industry skills for SOC Analysts, CTI Specialists, Incident Responders, Vulnerability Analysts, Threat Hunters, and Security Awareness Specialists.

## Features
- SOC Threat Intelligence Dashboard (7 KPIs, 10 distribution charts)
- High-Performance Threat Feed (2,100+ records, search, filter, sort)
- IOC Search & Validation Workbench (RFC 5737/2606 safe range detection)
- Security Alerts Queue with anti-fatigue correlation
- MITRE ATT&CK Behavioral Matrix with live telemetry hit counts
- Vulnerability Awareness & Priority Calculator
- Incident Response Lifecycle & Interactive Containment Checklist
- Awareness Learning Center (15 Modules)
- Security Awareness Quiz (32 Questions & Targeted Remediation)
- Executive Summary & Report Export (.txt)
- Automated Unit Testing Suite (35 Scenarios)

## Technology Stack
- Frontend: React 19, TypeScript, Tailwind CSS v4, Lucide Icons, Plus Jakarta Sans, JetBrains Mono
- Backend / Data: Python Flask / Node.js Express, CSV Ingestion Engine
- Testing: Interactive 35-scenario browser test runner & pytest compatibility

## Threat Intelligence Types
1. Strategic: High-level trends for board directors and CISOs.
2. Tactical: TTPs mapped to MITRE ATT&CK for threat hunters.
3. Operational: Details on active campaigns and staging.
4. Technical: Concrete IOC artifacts (IP, domain, hash) for edge blocking.

## IOC Lifecycle
Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Expired/Closed

## Risk & Confidence Scoring
- Risk Score Formula: (Severity * 0.30) + (Confidence * 0.25) + (Recency * 0.15) + (Frequency * 0.10) + (Source Reliability * 0.10) + (Context * 0.10)
- Tiers: Critical (81-100), High (61-80), Medium (41-60), Low (21-40), Informational (0-20)
- Confidence reflects evidence quality (Grade A to D).

## Installation & Usage
```bash
git clone https://github.com/your-username/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
npm install
npm run dev
```

## Testing
Automated 35-scenario suite covering IP/domain/hash/CVE validations, risk formulas, confidence dampening, alert correlation, and quiz scoring. Run in-app or via `pytest tests/`.

## Security & Privacy
- Non-Probing Guarantee: Pure database lookup, zero external pinging or socket connection.
- RFC Documentation Standards: Strictly RFC 5737 (IPv4), RFC 3849 (IPv6), RFC 2606 (Domains).
- Zero Malware Execution: Hashes treated strictly as search strings.

## Ethical Disclaimer
“This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.”

## Author


* **GitHub:** [nandiniverna2009](https://github.com)
* **LinkedIn:** [Nandini Verma](https://linkedin.com)

