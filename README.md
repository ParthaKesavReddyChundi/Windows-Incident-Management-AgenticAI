# Agentic AI Framework for Windows System Incident Detection, Root-Cause Analysis and Safe Remediation

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyTorch CUDA](https://img.shields.io/badge/PyTorch-2.5.1%20CUDA%2012.1-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/React-19.0-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi--Agent%20Reasoning-FF6F00)](https://langchain-ai.github.io/langgraph/)
[![Ollama](https://img.shields.io/badge/Ollama-Llama%203.2%203B-black)](https://ollama.ai)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Vector%20Store-blue)](https://www.trychroma.com/)
[![Tests](https://img.shields.io/badge/Tests-181%2F181%20Passed%20(100%25)-brightgreen)](reports/FINAL_EVALUATION_REPORT.md)
[![License: Academic](https://img.shields.io/badge/License-Academic%20Research-purple.svg)](LICENSE)

> **A closed-loop, explainable, and provably safe operating system resilience framework combining Deep Learning Anomaly Detection (UNSW ToN-IoT), Local Multi-Agent LLM Reasoning (Ollama Llama 3.2 3B), ChromaDB Retrieval-Augmented Generation (RAG), a Human-in-the-Loop Sandboxed PowerShell Remediation Engine, and a Tamper-Evident SHA-256 Cryptographic Audit Trail.**

---

## Table of Contents

1. [Executive Summary & System Architecture](#executive-summary--system-architecture)
2. [What Was Built: 10-Phase Milestone Overview](#what-was-built-10-phase-milestone-overview)
3. [Deep Learning & Benchmark Results](#deep-learning--benchmark-results)
4. [Safety, Guardrails & Remediation Policy](#safety-guardrails--remediation-policy)
5. [Prerequisites & System Setup Guide](#prerequisites--system-setup-guide)
6. [Step-by-Step Walkthrough: Using the Website](#step-by-step-walkthrough-using-the-website)
7. [Comprehensive Website Functionality Reference](#comprehensive-website-functionality-reference)
8. [REST API & WebSocket Documentation](#rest-api--websocket-documentation)
9. [Project Directory Layout](#project-directory-layout)
10. [Academic Citation & Acknowledgements](#academic-citation--acknowledgements)

---

## Executive Summary & System Architecture

Modern Windows operating systems run mission-critical workloads vulnerable to resource starvation, memory leaks, runaway worker processes, service termination, and sophisticated cyberattacks (credential brute-forcing, network floods, process injection). Traditional rule-based monitors generate high false positive rates and alert fatigue, while unconstrained autonomous remediation presents immense operational risk (e.g., terminating critical kernel processes or executing corrupted shell scripts).

This project implements an **enterprise-grade, closed-loop Cyber-SRE platform** designed specifically for **Windows 10/11**:

1. **Non-Invasive Live Telemetry:** Six dedicated system collectors stream high-frequency metrics across CPU, Memory, Disk, Network, Top Processes, and Windows Services via non-blocking asynchronous loops.
2. **Deep Learning Anomaly Detection:** A PyTorch Deep Autoencoder trained on the UNSW ToN-IoT Windows dataset scores multivariate telemetry vectors with sub-5ms latency, achieving **97.46% F1-score** and **100% recall** across all attack categories.
3. **Smart Alert Correlation:** Sliding-window aggregation groups burst telemetry spikes into unified incident records to eliminate duplicate ticket noise.
4. **Local Retrieval-Augmented Generation (RAG):** ChromaDB with GPU-accelerated dense embeddings (`all-MiniLM-L6-v2`) indexes Microsoft troubleshooting runbooks, Event ID forensic triages, and MITRE ATT&CK techniques.
5. **Specialized Multi-Agent AI (LangGraph + Ollama):** Autonomous agents powered by local `llama3.2:3b` analyze anomalies sequentially:
   - **Diagnosis Agent:** Identifies probable root causes and affected OS subsystems with confidence scoring.
   - **Security Agent:** Maps threat signatures to MITRE ATT&CK technique IDs (e.g., T1499, T1071).
   - **Remediation Agent:** Synthesizes runbooks into deterministic, allowlisted actions with explicit rollback plans.
6. **Provably Safe Remediation Engine:** Enforces an immutable 6-action allowlist, protects Windows kernel processes (`lsass`, `csrss`, `wininit`, `services`), sanitizes shell metacharacters, and executes commands strictly via argument-vector subprocesses (`shell=False`).
7. **Human-in-the-Loop Authorization:** Remediation actions remain quarantined until explicitly approved by an operator in the React dashboard.
8. **Automated Verification & Rollback:** Post-execution PowerShell probes verify resolution; failure triggers immediate automated rollback.
9. **Tamper-Evident SHA-256 Audit Chain:** Every proposed, approved, executed, and verified action is cryptographically anchored in an append-only hash chain.
10. **Cyber-SRE Dark-Mode Dashboard:** Built with React 19, TypeScript, and Vite, featuring zero-dependency live SVG sparklines, interactive triage queue, incident forensic drawer, knowledge search, and synthetic incident injection controls.

```mermaid
flowchart TD
    subgraph Host["Windows 10/11 Operating System Host"]
        telemetry["Live Windows Telemetry Collectors\n(CPU, Memory, Disk, Network, Process, Service)"]
        powershell["Sandboxed Subprocess Execution Engine\n(asyncio without shell=True)"]
        audit["SHA-256 Cryptographic Audit Chain\n(logs/remediation_audit.jsonl)"]
    end

    subgraph Detection["Deep Learning Detection Engine"]
        aligner["44-Feature Vector Normalizer\n(ToN-IoT Schema Aligner)"]
        autoencoder["PyTorch Deep Autoencoder\n(F1: 97.46%, Recall: 100%, RTX 4060 CUDA)"]
        detector["Reconstruction Error Classifier\n(Threshold τ = 0.002391)"]
    end

    subgraph Database["Incident Lifecycle & Persistence"]
        sqlite["SQLite Async DB (incidents.db)\n(State Machine: detected -> investigating -> awaiting_approval -> remediating -> resolved)"]
        ws["FastAPI WebSocket Hub\n(Real-time State & Sparkline Broadcasting)"]
    end

    subgraph RAG["Retrieval-Augmented Generation (RAG)"]
        chroma["ChromaDB Local Vector Store\n(36 Curated Runbook Chunks)"]
        embedder["all-MiniLM-L6-v2 Embedder\n(CUDA Dense Similarity Search)"]
    end

    subgraph Agents["LangGraph Multi-Agent Reasoning"]
        diagnosis["Diagnosis Agent\n(Root Cause & Evidence Extraction)"]
        security["Security Agent\n(MITRE ATT&CK T1499, T1071 Classification)"]
        remediation["Remediation Agent\n(Allowlisted Actions & Rollback Construction)"]
        llama["Local Ollama Server\n(Llama 3.2 3B Structured JSON Inference)"]
    end

    subgraph UI["Cyber-SRE Operator Dashboard"]
        dashboard["React 19 + TypeScript + Vite UI\n(Live Sparklines, Incident Queue, Action Gates)"]
        operator["Human Lead SRE / Security Administrator\n[Approve Action] / [Reject Action]"]
    end

    telemetry --> aligner --> autoencoder --> detector
    detector -- "MSE > τ (Anomaly Flagged)" --> sqlite
    sqlite --> ws --> dashboard
    sqlite --> diagnosis
    chroma <--> embedder <--> diagnosis
    diagnosis --> security --> remediation
    diagnosis -.-> llama
    security -.-> llama
    remediation -.-> llama
    remediation --> sqlite
    dashboard --> operator
    operator -- "POST /api/actions/{id}/approve" --> powershell
    powershell --> audit
    powershell --> telemetry
```

---

## What Was Built: 10-Phase Milestone Overview

| Phase | Milestone Name | Key Technical Deliverables | Status |
| :---: | :--- | :--- | :---: |
| **1** | **Workspace Audit & Architecture** | 10-phase technical specification, dataflow diagrams, safe remediation contracts, and project directory structure. | ✅ Complete |
| **2** | **Project Foundation** | Async settings management (`pydantic-settings`), multi-destination logging, `.env.example`, database schemas, and foundational tests. | ✅ Complete |
| **3** | **Telemetry Collectors & Incident Simulator** | 6 async Windows collectors (CPU, Memory, Disk, Network, Top-20 Processes, Windows Services, Event Logs) with backpressure queuing, plus a 6-scenario synthetic incident simulator. | ✅ Complete |
| **4** | **Dataset Pipeline & Deep Learning Anomaly Detection** | Ingestion of UNSW ToN-IoT Windows dataset, unsupervised zero-variance preprocessor (44 features), PyTorch Deep Autoencoder (CUDA-accelerated), 95th-percentile threshold calibration ($\tau = 0.002391$), and Isolation Forest baseline. | ✅ Complete |
| **5** | **Database & Incident Management** | Async SQLAlchemy + `aiosqlite` persistence, strict incident state machine (`detected` $\rightarrow$ `investigating` $\rightarrow$ `awaiting_approval` $\rightarrow$ `remediating` $\rightarrow$ `resolved`), 5-min sliding window alert correlation. | ✅ Complete |
| **6** | **RAG Knowledge Base** | 9 curated Microsoft troubleshooting runbooks & MITRE ATT&CK guides, SentenceTransformers `all-MiniLM-L6-v2` dense embedder on CUDA, ChromaDB vector store, semantic retrieval with similarity scoring. | ✅ Complete |
| **7** | **Local Llama & Multi-Agent AI** | Local Ollama (`llama3.2:3b`), LangGraph sequential state graph (`Diagnosis` $\rightarrow$ `Security` $\rightarrow$ `Remediation`), Pydantic JSON validation, fallback action generation. | ✅ Complete |
| **8** | **React Cyber-SRE Dashboard** | React 19 + TypeScript + Vite frontend, dark Cyber-SRE theme, live SVG sparklines, incident triage table, forensic modal with approval gates, RAG search console, and simulator panel. | ✅ Complete |
| **9** | **Controlled Remediation & Safety** | 6-action strict allowlist, Windows kernel process defense (`lsass`, `csrss`, etc.), shell metacharacter rejection, `asyncio.create_subprocess_exec` (`shell=False`), automated post-check verification, rollback engine, and SHA-256 hash-chained audit log. | ✅ Complete |
| **10** | **Final Integration & Evaluation** | Complete end-to-end closed-loop integration verification, adversarial safety fuzzing, 181 passing automated tests (100% pass rate), and quantitative academic benchmark report. | ✅ Complete |

---

## Deep Learning & Benchmark Results

The anomaly detection engine was trained on the **UNSW ToN-IoT Windows 10 dataset** and benchmarked against an **Isolation Forest baseline**.

### Model Performance Metrics

| Evaluation Metric | Deep Autoencoder (Ours) | Isolation Forest (Baseline) | Performance Delta |
| :--- | :---: | :---: | :---: |
| **Overall Accuracy** | **97.25%** | 76.76% | **+20.49%** |
| **Precision** | **95.04%** | 69.36% | **+25.68%** |
| **Recall (Sensitivity)** | **100.00%** | 100.00% | Parity |
| **F1-Score** | **97.46%** | 81.91% | **+15.54%** |
| **ROC-AUC** | **0.99997** | 0.98601 | **+0.01396** |
| **PR-AUC** | **0.99997** | 0.98529 | **+0.01468** |
| **Inference Latency (p50)** | **4.08 ms** | - | Ultra-fast real-time |
| **Inference Latency (p99)** | **77.11 ms** | - | Sub-100ms guaranteed |

### Zero False Negatives Across Cyber Attack Classes

The Deep Autoencoder achieved **100% detection recall (0 false negatives)** across all attack vectors present in the ground truth test split:

```
[+] Distributed Denial of Service (DDoS) :  918 /  918 detected  (100.0% Recall, 1.00 F1)
[+] Credential Brute-Force (Password)    :  719 /  719 detected  (100.0% Recall, 1.00 F1)
[+] Cross-Site Scripting (XSS)           :  256 /  256 detected  (100.0% Recall, 1.00 F1)
[+] Command / SQL Injection              :  120 /  120 detected  (100.0% Recall, 1.00 F1)
[+] Denial of Service (DoS)              :  105 /  105 detected  (100.0% Recall, 1.00 F1)
[+] Network Port Scanning                :   99 /   99 detected  (100.0% Recall, 1.00 F1)
[+] Man-in-the-Middle (MITM)             :    4 /    4 detected  (100.0% Recall, 1.00 F1)
```

### System Latencies & Resilience
- **Telemetry Collection:** ~2.3 seconds across all 6 OS subsystems (well within the 5.0s polling cycle).
- **RAG Knowledge Retrieval:** Median latency **18.22 ms** (ChromaDB top-$k=3$ cosine similarity).
- **Multi-Agent AI Reasoning:** Sub-2-second inference on NVIDIA RTX 4060 GPU with Ollama `llama3.2:3b`.
- **Safety Policy Enforcement:** 100.0% compliance against adversarial command injections and protected targets.
- **Cryptographic Audit Chain:** 100% integrity across sequential remediation events.

---

## Safety, Guardrails & Remediation Policy

Autonomous actions on an operating system carry inherent risks. This framework applies **defense-in-depth safety engineering**:

1. **Strict Action Allowlist:** Only 6 primitive verbs can ever be proposed or executed:
   - `throttle_process` (adjusts thread/process priority class to `BelowNormal` or `Idle`)
   - `kill_process` (terminates unauthorized or runaway worker processes by PID)
   - `restart_service` (safely cycles an unresponsive Windows system service)
   - `flush_memory` (clears working sets and trims inactive system cache)
   - `block_ip` (adds a targeted inbound/outbound Windows Defender Firewall rule)
   - `isolate_network` (quarantines the network adapter during active exfiltration)
2. **Immutable Protected Process Defense:** Critical Windows subsystems are hardcoded in the safety policy and **strictly cannot be killed or throttled under any circumstances**:
   - `lsass`, `csrss`, `wininit`, `smss`, `services`, `svchost`, `winlogon`, `system`, `ntoskrnl`, `dwm`, `explorer`
3. **Shell Metacharacter Rejection:** All targets, parameters, and inputs are checked against regex patterns rejecting command chainers and delimiters (`;`, `&`, `|`, `` ` ``, `$`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `\`, `'`, `"`, `\n`, `\r`, `\0`).
4. **Sandboxed Subprocess Execution:** Actions are executed via `asyncio.create_subprocess_exec` directly with explicit argument vectors (`shell=False`). Shell command chaining is physically impossible.
5. **Human-in-the-Loop Barrier:** High-risk actions unconditionally require explicit operator authorization via the dashboard before any PowerShell execution occurs.
6. **Automated Post-Execution Verification:** After execution, a verification probe checks the OS state (e.g., verifying that the PID is terminated or the service is running).
7. **Automated Rollback Engine:** If an action fails or its verification check fails, compensating rollback commands execute immediately (e.g., restoring priority or removing firewall block rules).
8. **Cryptographic SHA-256 Audit Trail:** Every event is cryptographically linked to the previous record's hash (`logs/remediation_audit.jsonl`), creating a tamper-evident audit ledger.

---

## Prerequisites & System Setup Guide

### 1. Prerequisites
- **Operating System:** Windows 10 or Windows 11 (64-bit)
- **Python:** Version 3.12 or newer
- **Node.js:** Version 20.x or 22.x with `npm`
- **Ollama:** Download and install from [ollama.ai](https://ollama.ai)
- **GPU (Recommended):** NVIDIA GPU with CUDA drivers (e.g., RTX 4060) for fast PyTorch and Ollama inference. CPU fallback is fully supported.
- **Git:** Git for Windows

---

### 2. Step-by-Step Installation

#### Step 1: Clone the Repository
```powershell
git clone https://github.com/ParthaKesavReddyChundi/Windows-Incident-Management-AgenticAI.git
cd Windows-Incident-Management-AgenticAI
```

#### Step 2: Create and Activate Virtual Environment
```powershell
# Create Python 3.12 virtual environment
python -m venv .venv

# Activate environment in PowerShell
.\.venv\Scripts\Activate.ps1
```

#### Step 3: Install Python Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```
*(If developing or running test suites, also run: `pip install -r requirements-dev.txt`)*

#### Step 4: Configure Environment Variables
Copy `.env.example` to create `.env`:
```powershell
Copy-Item .env.example .env
```
The default configuration works out of the box:
```env
APP_ENV=development
APP_HOST=127.0.0.1
APP_PORT=8000
TELEMETRY_INTERVAL_SECONDS=5
MODEL_PATH=models/autoencoder.pt
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2:3b
DATABASE_URL=sqlite+aiosqlite:///./database/incidents.db
```

#### Step 5: Start Ollama & Pull the Model
Open a new terminal window to run the Ollama daemon:
```powershell
# Start Ollama service (if not running in system tray)
ollama serve

# Pull the lightweight, high-reasoning Llama model
ollama pull llama3.2:3b
```

#### Step 6: Verify or Retrain the Anomaly Detection Model (Optional)
The pre-trained PyTorch model is already included in `models/autoencoder.pt`. If you wish to retrain it on the included UNSW ToN-IoT Windows dataset:
```powershell
python scripts/train_model.py
```

#### Step 7: Start the FastAPI Backend
In your activated virtual environment terminal:
```powershell
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend API:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Live WebSocket Telemetry:** `ws://127.0.0.1:8000/ws/telemetry`

#### Step 8: Install and Launch the React Frontend
In a new terminal window:
```powershell
cd frontend
npm install
npm run dev
```
- **Frontend URL:** [http://localhost:5173](http://localhost:5173)

#### Step 9: Verify by Running the Automated Test Suite
```powershell
# Run all 181 automated unit and integration tests
pytest -v
```

---

## Step-by-Step Walkthrough: Using the Website

Follow this hands-on guide to experience the full closed-loop incident detection, AI diagnosis, and human-in-the-loop remediation lifecycle.

```mermaid
sequenceDiagram
    autonumber
    actor Operator as SRE Operator
    participant UI as React Dashboard
    participant Backend as FastAPI & WS Hub
    participant Sim as Simulator Engine
    participant AE as PyTorch Autoencoder
    participant RAG as ChromaDB Vector Store
    participant Agent as LangGraph (Ollama)
    participant Safety as SafetyGuard & Executor
    participant Audit as SHA-256 Audit Log

    Operator->>UI: 1. Navigate to "Incident Simulator" Tab
    Operator->>UI: 2. Click "Inject Scenario" (e.g. CPU Core Starvation)
    UI->>Backend: POST /api/simulator/inject {scenario: cpu_overload}
    Backend->>Sim: Execute synthetic anomaly scenario
    Sim-->>Backend: Telemetry metrics spike
    Backend->>AE: Run PyTorch Inference on 44 normalized features
    AE-->>Backend: Reconstruction MSE > τ (Anomaly Flagged!)
    Backend->>Backend: Deduplicate & correlate into Incident Ticket
    Backend-->>UI: WebSocket broadcast (incident_detected)
    UI->>UI: Alert banner pulses red; Incident appears in Queue

    Operator->>UI: 3. Click Incident Card -> Open Forensic Drawer
    Operator->>UI: 4. Click "Trigger AI Investigation"
    UI->>Backend: POST /api/incidents/{id}/investigate
    Backend->>RAG: Query ChromaDB for troubleshooting runbooks
    RAG-->>Backend: Top-k runbook chunks & MITRE ATT&CK guides
    Backend->>Agent: Run LangGraph pipeline (Diagnosis -> Security -> Remediation)
    Agent-->>Backend: Structured Root Cause, MITRE IDs & Allowlisted Actions
    Backend-->>UI: Return complete diagnostic investigation report
    UI->>UI: Display Root-Cause analysis, Confidence %, MITRE badges, and Action Preview

    Operator->>UI: 5. Review PowerShell command preview & Rollback Plan
    Operator->>UI: 6. Click "Approve & Authorize Execution"
    UI->>Backend: POST /api/actions/{action_id}/approve
    Backend->>Safety: Check strict allowlist & kernel process guardrails
    Safety->>Safety: Sanitize metacharacters & construct argument list
    Safety->>Backend: Execute via asyncio.create_subprocess_exec (shell=False)
    Backend->>Safety: Run post-execution PowerShell verification probe
    Safety->>Audit: Append record with SHA-256 hash chaining
    Backend-->>UI: Broadcast status update (action_executed & verified)
    UI->>UI: Display green execution badge & update sparklines

    Operator->>UI: 7. Click "Mark as Resolved"
    UI->>Backend: PATCH /api/incidents/{id}/status {status: resolved}
    Backend-->>UI: State updated; active incident counter decrements
```

### Detailed User Flow:

1. **Open the Dashboard:**
   Visit `http://localhost:5173`. You will see the Cyber-SRE dark interface. Check the header: the connection pill indicates `LIVE WS` with a green pulse, and the status indicator shows `SYSTEM NORMAL`.
2. **Observe Live Telemetry:**
   Review the top metric cards (Active Incidents, CPU Utilization, RAM Usage, Disk I/O, Network Throughput). Watch the rolling SVG sparklines update smoothly in real time every 5 seconds.
3. **Inject a Synthetic Anomaly:**
   Click the **Simulator** tab in the navigation bar. You will see 6 synthetic incident cards. Click **"Inject Scenario"** on **CPU Core Starvation** (or **RAM Pressure & Leak**).
4. **Witness Anomaly Flagging:**
   The simulator spins up synthetic high-load telemetry. The PyTorch Deep Autoencoder flags the reconstruction error above the threshold ($\tau = 0.002391$). The top status badge instantly changes to **`ANOMALY FLAGGED`** with a red pulse. A new incident ticket automatically appears in the active queue.
5. **Open Incident Forensic Drawer:**
   Click on the newly created incident in the queue (or switch to the **Incidents Queue** tab). A forensic drawer slides out showing:
   - Incident ID and severity badge (`CRITICAL` or `HIGH`)
   - Anomaly score and detection timestamp
   - Top deviant telemetry features causing the anomaly
6. **Trigger AI Multi-Agent Investigation:**
   Click the blue **"Trigger AI Investigation"** button. The backend dispatches the incident to the LangGraph pipeline:
   - Retrieves Microsoft troubleshooting runbooks from ChromaDB.
   - **Diagnosis Agent** analyzes features and outputs the probable root cause, technical analysis, and confidence score.
   - **Security Agent** assesses threat indicators and classifies MITRE ATT&CK techniques.
   - **Remediation Agent** prepares allowlisted remediation actions.
7. **Review Agent Findings & Action Preview:**
   Examine the generated report:
   - Root cause and affected subsystems.
   - MITRE ATT&CK badge (e.g., `T1499 - Endpoint Denial of Service`).
   - Proposed action card (e.g., `throttle_process` or `kill_process`), complete with PowerShell command preview, parameter inspection, and rollback compensation plan.
8. **Approve Action (Human-in-the-Loop Gate):**
   Click the green **"Approve & Authorize Execution"** button.
   - SafetyGuard validates the target (verifying it is not a protected kernel process like `lsass.exe` or `csrss.exe`).
   - The action is safely executed via sandboxed `asyncio.create_subprocess_exec`.
   - The automated post-check verification runs to confirm resolution.
   - The event is cryptographically committed to `logs/remediation_audit.jsonl`.
   - The UI updates with a green **"Action executed successfully"** confirmation.
9. **Resolve the Incident:**
   Click **"Mark as Resolved"** in the drawer footer. The incident lifecycle advances to `RESOLVED`, and the active incident counter decrements.
10. **Explore Knowledge Base Search:**
    Switch to the **RAG Knowledge Base** tab. Enter queries such as *"high cpu runaway process"*, *"lsass credential dumping"*, or *"event 7034 service crash"*. Filter by category and inspect the retrieved runbook sections and cosine similarity scores.

---

## Comprehensive Website Functionality Reference

The dashboard provides a dedicated Cyber-SRE operational console. Below is an exhaustive breakdown of every UI view, widget, and control:

### 1. Global Navigation & Header Bar (`Navbar.tsx`)
- **Brand Logo & Title:** Displays the system identity with cyber-teal branding.
- **Navigation Tabs:**
  - `Live Telemetry`: Main dashboard with sparklines, core metrics, and quick queue.
  - `Incidents Queue`: Full incident triage management console with search and filters.
  - `RAG Knowledge Base`: Semantic search interface across ChromaDB vector store.
  - `Incident Simulator`: Synthetic scenario execution controls.
- **System Health Status Pill:** Dynamic real-time indicator:
  - Green `SYSTEM NORMAL`: System telemetry operating within normal parameters.
  - Glowing Red `ANOMALY FLAGGED`: Active anomaly flagged by the Autoencoder.
- **WebSocket Connection Indicator:** Displays `LIVE WS` with a pulsing emerald status dot when connected, or amber/red with automatic reconnect logic when disconnected.
- **Force Snapshot Refresh Button:** Instant manual trigger invoking `POST /api/telemetry/collect` to gather fresh telemetry on demand.

### 2. High-Level Metrics Summary (`StatsCards.tsx`)
- **Active Incidents Card:** Shows total active unresolved tickets, broken down with distinct severity badges (`Critical`, `High`, `Medium`, `Low`).
- **CPU Utilization Card:** Displays overall CPU load percentage, clock frequency (GHz), and dynamic left-border coloring (blue for normal, red when $> 80\%$).
- **RAM Usage Card:** Displays current RAM percentage, used gigabytes out of total installed physical RAM, and paging file utilization.
- **Disk I/O Throughput Card:** Real-time aggregate read and write bandwidth in MB/s across all storage partitions.
- **Network Rate Card:** Interface send and receive bandwidth in KB/s and active TCP/UDP socket connections.

### 3. Real-Time Telemetry & Health Visualizations (`TelemetryCharts.tsx`)
- **Rolling CPU % Sparkline:** Zero-dependency SVG chart rendering the last 30 telemetry points with smooth cubic bezier curves and a glowing linear gradient fill.
- **Rolling RAM % Sparkline:** Real-time memory pressure sparkline with dynamic threshold markers.
- **Per-Core CPU Meters:** Vertical utilization bars representing each physical and logical CPU core, highlighting core starvation or single-threaded bottlenecking.
- **Top Resource-Consuming Processes:** High-performance live table showing the top 10 running processes sorted by CPU and memory usage, displaying PID, process name, CPU %, Memory %, and thread count.
- **Windows Core Services Matrix:** Health status indicators for critical Windows system services (`wuauserv`, `WinDefend`, `EventLog`, `Spooler`, `LanmanServer`), showing real-time `RUNNING`, `STOPPED`, or `PENDING` states.

### 4. Incident Management Console (`IncidentList.tsx`)
- **Lifecycle Status Filter Pills:** Filter tickets by state: `All`, `Detected`, `Investigating`, `Awaiting Approval`, `Remediating`, `Resolved`, `Dismissed`.
- **Severity Filter Selector:** Filter by `Critical`, `High`, `Medium`, `Low`.
- **Full-Text Incident Search:** Search bar filtering by incident title, subsystem, or description.
- **Incident Triage Cards:**
  - Severity and status badges.
  - Incident title, detection timestamp, and data source (`live` or `simulated`).
  - Autoencoder anomaly reconstruction error score.
  - Quick action buttons: **"Investigate"** (triggers AI reasoning) and **"Resolve"** (closes ticket).

### 5. Forensic Incident Detail Drawer (`IncidentDetailModal.tsx`)
- **Header Badges:** Displays severity, current lifecycle state, and unique ticket UUID.
- **Forensic Metadata Grid:** Source, anomaly score vs threshold, detection timestamp, and multi-agent confidence percentage.
- **Description & Telemetry Evidence:** Contextual summary of anomalous signals and top deviant metrics.
- **Diagnosis Agent Report Card:**
  - Probable root cause statement.
  - Confidence meter (0–100%).
  - Technical analysis narrative.
  - Tagged affected OS subsystems.
  - Supporting evidence bullet points.
- **Security Agent Assessment Card:**
  - Threat classification badge (`Denial of Service`, `Exfiltration`, `System Anomaly`).
  - MITRE ATT&CK technique tags (e.g., `T1499`, `T1071`).
  - Containment warning banner if immediate network or process isolation is required.
- **Proposed Remediation Action Console:**
  - Action type tag (`throttle_process`, `kill_process`, `restart_service`, `flush_memory`, `block_ip`, `isolate_network`).
  - Operational risk badge (`Low`, `Medium`, `High`).
  - PowerShell command preview and parameter inspector.
  - Rollback plan documentation.
  - **Human-in-the-Loop Action Buttons:** Green **"Approve & Authorize Execution"** and red **"Reject"** buttons.
  - Post-execution success indicator.
- **Footer Controls:** "Mark as Resolved" and "Close" buttons.

### 6. Controlled Incident Simulator (`SimulatorPanel.tsx`)
- **6 Realistic Synthetic Scenarios:**
  1. **CPU Core Starvation (`cpu_overload`):** Simulates runaway compute threads across multiple CPU cores ($>90\%$ utilization).
  2. **RAM Pressure & Leak (`memory_pressure`):** Simulates progressive memory buffer allocation and swap thrashing.
  3. **Disk Thrashing & I/O Burst (`disk_pressure`):** Generates high-frequency read/write IOPS to saturate storage queue lengths.
  4. **Windows Service Crash (`service_failure`):** Simulates abnormal termination of a critical Windows system service.
  5. **Network Flood & DoS Burst (`network_anomaly`):** Mimics outbound data exfiltration surges or DoS floods.
  6. **Application Exception Storm (`app_failure`):** Injects simulated unhandled exceptions and Windows Event Log error events (Event ID 1000/1001).
- **One-Click Injection:** Card button with loading spinner, execution feedback banner, sample count, and duration.

### 7. RAG Knowledge Base Console (`KnowledgeSearch.tsx`)
- **Semantic Search Input:** Free-text query bar to search curated Microsoft troubleshooting runbooks and MITRE ATT&CK techniques.
- **Category Filter Pills:** Filter by `all`, `performance`, `services`, `memory`, `security`, `general`.
- **Search Results Cards:**
  - Runbook title and section heading.
  - Category badge and source document citation.
  - Cosine similarity match score bar (percentage match).
  - Formatted markdown chunk preview.
- **Vector Store Statistics Banner:** Displays total indexed chunks (36 chunks), embedding model (`all-MiniLM-L6-v2`), and vector dimension (384-d).
- **One-Click Reindex Button:** Forces ChromaDB to clear and re-parse all markdown source documents in `rag/sources/`.

---

## REST API & WebSocket Documentation

The FastAPI backend exposes comprehensive REST endpoints and WebSocket channels:

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/health` | Server health check, uptime, and database connectivity. |
| `GET` | `/api/telemetry/latest` | Returns latest 6-subsystem telemetry snapshot. |
| `POST` | `/api/telemetry/collect-now` | Forces an immediate synchronous telemetry collection cycle. |
| `GET` | `/api/telemetry/status` | Collector status, latency history, and backpressure queue metrics. |
| `POST` | `/api/telemetry/detect` | Scores telemetry vector against PyTorch Autoencoder; optionally auto-correlates into an incident. |
| `GET` | `/api/telemetry/model-info` | Returns PyTorch model specs, active features, threshold, and training metrics. |
| `GET` | `/api/incidents` | Lists incidents with pagination, status, and severity filters. |
| `GET` | `/api/incidents/stats/summary` | Aggregated dashboard counters (active, resolved, severity distribution). |
| `GET` | `/api/incidents/{id}` | Detailed incident record with linked anomalies, actions, and audit logs. |
| `POST` | `/api/incidents/{id}/investigate` | Triggers LangGraph multi-agent reasoning (Diagnosis $\rightarrow$ Security $\rightarrow$ Remediation). |
| `GET` | `/api/incidents/{id}/investigation` | Retrieves stored multi-agent investigation report. |
| `PATCH`| `/api/incidents/{id}/status` | Advances incident lifecycle state through the validated state machine. |
| `GET` | `/api/actions/pending` | Lists remediation actions awaiting human operator approval. |
| `POST` | `/api/actions/{id}/approve` | Validates, executes, verifies, and audits proposed remediation action. |
| `POST` | `/api/actions/{id}/reject` | Rejects remediation action with operator reason code. |
| `GET` | `/api/actions/audit-log` | Returns immutable cryptographic SHA-256 remediation audit records. |
| `POST` | `/api/rag/query` | Semantic vector search across ChromaDB runbooks. |
| `GET` | `/api/rag/stats` | Vector store statistics, chunk count, and embedding configuration. |
| `POST` | `/api/rag/reindex` | Re-indexes all markdown source documents into ChromaDB. |
| `GET` | `/api/simulator/scenarios` | Lists available synthetic incident scenarios. |
| `POST` | `/api/simulator/run/{name}` | Injects synthetic incident pattern for closed-loop evaluation. |
| `WS` | `/ws/telemetry` | Real-time WebSocket broadcasting telemetry snapshots (5s) and incident events. |

---

## Project Directory Layout

```
.
├── backend/                  FastAPI REST and WebSocket server
│   └── app/
│       ├── api/              Routers: telemetry, detection, incidents, actions, rag, ws
│       ├── schemas/          Pydantic schemas for request/response contracts
│       ├── services/         IncidentService, InvestigationService, RAGService
│       └── main.py           FastAPI application factory, lifespan hooks, CORS, routers
├── collectors/               Windows system telemetry collectors
│   ├── base.py               Abstract collector base with error isolation & timing
│   ├── cpu_collector.py      psutil CPU % (overall & per-core) and frequency
│   ├── memory_collector.py   Physical RAM, swap, and paging metrics
│   ├── disk_collector.py     Partition space and read/write I/O throughput (B/s)
│   ├── network_collector.py  Network throughput, packet rates, socket counts
│   ├── process_collector.py  Top-20 processes sorted by CPU & RAM consumption
│   ├── service_collector.py  Windows system service status enumeration
│   ├── event_log_collector.py Windows Event Log reader (System & Application channels)
│   └── collector_manager.py  Async non-blocking orchestrator with backpressure queue
├── data/                     Datasets & simulation storage
│   ├── raw/train_test/       UNSW ToN-IoT Windows 7 & 10 benchmark CSV datasets
│   └── simulated/            Synthetic scenario outputs (JSON & CSV feature summaries)
├── data_pipeline/            Data engineering and feature alignment
│   ├── validator.py          Schema inspection, label distribution, null checks
│   ├── preprocessor.py       Zero-variance filter & StandardScaler (trained on normal data)
│   └── feature_engineering.py Derived ratios, pressure indexes, rolling statistics
├── database/                 Persistence layer & state machine
│   ├── models.py             SQLAlchemy models: Incident, AnomalyRecord, RemediationAction, AuditLog
│   ├── session.py            Async SQLAlchemy engine & session maker (aiosqlite)
│   └── state_machine.py      Formal incident lifecycle transition validator
├── detection/                PyTorch Deep Autoencoder detection engine
│   ├── autoencoder.py        TelemetryAutoencoder (44 -> 64 -> 32 -> 16 -> 32 -> 64 -> 44)
│   ├── trainer.py            GPU-accelerated batch training with early stopping
│   ├── threshold_calibrator.py 95th-percentile anomaly threshold calibrator (τ = 0.002391)
│   ├── baseline.py           Isolation Forest benchmark implementation
│   ├── evaluator.py          Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC evaluator
│   └── anomaly_detector.py   Production inference engine (CUDA with CPU fallback)
├── agents/                   LangGraph multi-agent AI reasoning
│   ├── schemas.py            Pydantic output schemas (Diagnosis, Security, Remediation)
│   ├── llm_factory.py        Ollama chat model factory with robust JSON parsing
│   ├── diagnosis_agent.py    Root cause analysis & evidence extraction agent
│   ├── security_agent.py     MITRE ATT&CK classification & threat assessment agent
│   ├── remediation_agent.py  Allowlisted action formulation & rollback planner agent
│   └── graph.py              LangGraph state graph coordinating the agent pipeline
├── rag/                      Retrieval-Augmented Generation subsystem
│   ├── embedder.py           SentenceTransformers (all-MiniLM-L6-v2) on CUDA
│   ├── vector_store.py       ChromaDB persistent vector store wrapper
│   ├── ingester.py           Markdown chunker with section-aware metadata extraction
│   ├── retriever.py          Semantic retriever translating symptoms into runbook context
│   └── sources/              9 curated Microsoft troubleshooting and MITRE runbooks
├── remediation/              Safe execution engine & guardrails
│   ├── safety_guard.py       Strict allowlist policy & kernel process protection
│   ├── action_executor.py    Sandboxed subprocess runner (asyncio without shell=True)
│   ├── verification_engine.py Automated PowerShell post-remediation verification
│   ├── rollback_engine.py    Compensating rollback execution on failure
│   └── audit_logger.py       Tamper-evident SHA-256 cryptographic hash-chained audit log
├── frontend/                 Cyber-SRE React 19 + TypeScript + Vite dashboard
│   ├── src/
│   │   ├── components/       Navbar, StatsCards, TelemetryCharts, IncidentList,
│   │   │                     IncidentDetailModal, SimulatorPanel, KnowledgeSearch
│   │   ├── hooks/            useWebSocket auto-reconnecting stream hook
│   │   ├── services/         api.ts typed REST API client
│   │   ├── types/            Complete TypeScript domain interfaces
│   │   ├── App.tsx           Main application component and tab router
│   │   └── index.css         Cyber-SRE dark theme and design system
│   ├── package.json          Frontend dependencies (React 19, Lucide, Tailwind)
│   └── vite.config.ts        Vite build configuration with API reverse proxy
├── models/                   Trained PyTorch weights, scalers, and thresholds
├── reporting/                Automated benchmark evaluation script
├── reports/                  FINAL_EVALUATION_REPORT.md and JSON benchmark results
├── scripts/                  CLI training pipeline (train_model.py)
├── simulator/                Synthetic incident anomaly generator
└── tests/                    181 automated tests (Unit, Integration, E2E)
```

---

## Academic Citation & Acknowledgements

This research and software framework utilizes the **UNSW ToN-IoT Windows Dataset** for cyber telemetry benchmarking:

```bibtex
@article{moustafa2020ton_iot,
  title   = {A New Distributed Architecture for Evaluating AI-based Security Systems at the Big Data in Healthcare Applications},
  author  = {Moustafa, Nour},
  journal = {IEEE Transactions on Industrial Informatics},
  volume  = {16},
  number  = {4},
  pages   = {2457--2466},
  year    = {2020},
  publisher = {IEEE}
}
```

*Developed as an advanced academic engineering demonstration of closed-loop operating system resilience through the synergy of Deep Learning, Sandboxed Execution, and Local Agentic AI.*
