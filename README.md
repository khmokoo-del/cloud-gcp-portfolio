# Serverless Google Workspace Security Enforcer

Hello, and welcome to my cloud engineering portfolio. 

This repository showcases an enterprise-grade security pipeline I architected and built on Google Cloud Platform (GCP). I designed this system to solve a massive headache for large organizations: ensuring that thousands of employees across multiple regions are strictly adhering to data sharing and compliance policies in Google Workspace, without relying on manual audits.

## The Problem
In enterprise environments, data leakage—whether accidental or malicious—is a constant threat. Employees often share sensitive documents outside the organization or leave highly classified files accessible to "anyone with the link." Auditing this manually across thousands of accounts is impossible, and waiting for a quarterly security review is too slow.

## The Solution
I built a relentless, 24/7 automated enforcement mechanism. It acts as a bridge between GCP and Google Workspace, automatically hunting down compliance violations, remediating them in real-time, and logging everything for executive review.

Here is how it works under the hood:

### 1. The Discoverer (`discoverer.py`)
This is a scheduled Cloud Run service that acts as the scout. It authenticates using GCP IAM Service Accounts and scans specific Organizational Units (OUs) within Workspace. When it finds users to audit, it securely packages their information and publishes it to a Pub/Sub message queue.

### 2. The Sanitizer (`sanitizer.py`)
This is the worker node, triggered dynamically via Eventarc whenever a new message hits the Pub/Sub queue. It reads the user's Google Drive, identifies exposed files (like external shares or unapproved executables), and neutralizes the threat by trashing or restricting the file. To handle Google API rate limits gracefully, I engineered a Dead Letter Queue (DLQ) with bookmarking capabilities so the system never loses track of a scan, even if it times out.

### 3. The Orchestrator (`dashboard_orchestrator.js`)
Security data is useless if leadership can't read it. Every action the Sanitizer takes is streamed directly into BigQuery. I wrote a Google Apps Script orchestrator that pulls this massive dataset and transforms it into a multi-tab Google Sheets dashboard. It automatically highlights critical external threats (DLP), generates manager sign-off ledgers, and builds executive summaries.

## Business Impact
By shifting from manual audits to an event-driven, serverless architecture, this pipeline achieved zero-touch compliance. Because it utilizes scale-to-zero serverless components, it easily handles massive spikes in employee activity while keeping cloud infrastructure costs down to fractions of a cent.

Feel free to explore the code in this repository to see my approach to error handling, asynchronous messaging, and Google API integration!
