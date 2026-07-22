# Enterprise Security Architecture: Cloud, Endpoint, Network & Posture Management

Hello, and welcome to my cloud engineering portfolio. 

This repository showcases a comprehensive, enterprise-grade security and compliance architecture I designed and engineered. The platform is broken into five distinct pillars that work in tandem to enforce ISO 27001 data compliance across an organization's cloud environment, local endpoints, global edge infrastructure, incident response workflows, and overall security posture.

## Part 1: Serverless Google Workspace Security Enforcer
In enterprise environments, data leakage via cloud sharing is a constant threat. I built a relentless, 24/7 automated enforcement mechanism utilizing GCP serverless architecture to ensure zero-touch compliance.

* **The Discoverer (`discoverer.py`):** A scheduled Cloud Run service that authenticates via GCP IAM Service Accounts and scans specific Google Workspace Organizational Units (OUs). It securely packages user audit data and publishes it to a Pub/Sub message queue.
* **The Sanitizer (`sanitizer.py`):** An event-driven worker triggered dynamically via Eventarc. It reads the targeted user's Google Drive, identifies exposed files, and neutralizes the threat by restricting access. 
* **The Workspace BI Orchestrator (`dashboard_orchestrator.js`):** Every automated action is streamed directly into BigQuery. This Google Apps Script pulls that telemetry data and transforms it into a multi-tab Google Sheets dashboard to generate manager sign-off ledgers.

## Part 2: Endpoint Data Leakage Prevention (DLP) & Device Control
Securing the cloud isn't enough if users can exfiltrate data physically. I engineered a robust local device monitor that communicates asynchronously with a cloud backend to enforce strict hardware policies.

* **Endpoint DLP Agent (`usb_dlp_agent_deploy.sh` & `workspace_ephemeral_sanitizer.sh`):** A bash-deployed architecture that interacts directly with the Linux kernel (`udev`) to block unauthorized USB storage mounts. It relies on `auditd` to track illicit file writes and logs hardware hashes to a local SQLite database. 
* **Cloud Ingestion Webhook (`dlp_cloud_function.py`):** A Python-based Cloud Run endpoint that acts as a secure receiver for local endpoint agents, absorbing incoming webhook payloads and dropping them into a Pub/Sub queue.
* **ISO 27001 Compliance Dashboard (`compliance_dashboard.js`):** An application that pulls the hardware logs from the cloud and dynamically generates an immutable audit ledger and an executive security posture matrix. 

## Part 3: Global Infrastructure & Network Compliance Posture
To satisfy rigorous regulatory requirements for business continuity and physical security, I built a centralized orchestration ledger that audits the edge network in real-time.

* **Infrastructure API Orchestrator (`unifi_compliance_dashboard.js`):** This engine authenticates securely via GCP Secret Manager to pull hardware states, IPS/IDS configurations, and network failover events from global enterprise gateways and NVRs (Network Video Recorders).
* **High Availability (HA) Algorithmic Validation:** To prevent false penalties, the script utilizes a custom interval intersection algorithm to extract strict chronologically overlapping downtime between primary and secondary ISPs, calculating true fault-tolerant business continuity SLA metrics.

## Part 4: Threat Intelligence & Incident Response Middleware
A security architecture requires seamless ways to ingest threat data and route incidents to the SOC (Security Operations Center). I engineered middleware pipelines to handle both automated data intelligence and human-reported escalations.

* **Exfiltration Intelligence Feed (`exfiltration_intelligence_dashboard.js`):** A BI script that queries BigQuery to separate Workspace exfiltration events (Drive vs. Gmail attachments), aggregating risk by global region and mathematically isolating the top internal offenders and external receiving domains.
* **Infrastructure as Code: Form Provisioning (`provision_security_form.js`):** A script that programmatically generates and standardizes bilingual, globally distributed security escalation forms, ensuring consistent data structures for incident reporting.
* **SOC Routing Middleware (`soc_escalation_middleware.js` & `visitor_log_middleware.js`):** Event-driven middleware that intercepts form submissions, reformats the data into executive-branded HTML reports, appends the raw JSON payload, and routes it directly to the SIEM/Ticketing ingestion queues.

## Part 5: Enterprise Security Posture Management (CSPM)
The capstone of this architecture is a massive, asynchronous orchestration engine that correlates identity, endpoint health, and threat intelligence into a single pane of glass.

* **State Machine Orchestrator (`security_posture_management.js`):** To bypass standard serverless execution timeouts, this script utilizes a custom 4-phase chained architecture driven by `LockService` and time-based triggers.
* **Multi-Vendor Correlation:** It actively polls Identity APIs (JumpCloud) and EDR APIs (ESET), using dual-verification (hostname and hardware serial matching) to identify coverage gaps, unbound admins, missing MFA, dormant hardware, and malicious browser extensions.
* **Automated SOAR Integration:** Beyond passive reporting, the engine automatically dispatches webhooks to the enterprise ticketing system (LiveAgent/SOAR) to trigger active incident response protocols for critical vulnerabilities.

## Business Impact
By combining local hardware control, global network API integrations, state-machine orchestration, and event-driven serverless cloud components, this architecture achieves true **zero-touch compliance**. It autonomously blocks data exfiltration, validates high-availability network routing, actively hunts for system vulnerabilities, and maintains rigorous, immutable audit trails for regulatory compliance without requiring manual intervention.