# Backend Architecture & Logic

## Overview
The Agentic Honeypot connects a lightweight Flask backend with a powerful Llama-3 based AI engine to autonomously detect and engage with scammers.

## Core Components

### 1. Scam Detector (Hybrid Engine)
The system uses a two-layer approach for detecting scams:
*   **Layer 1 (Regex):** Immediate pattern matching for known scam indicators (e.g., "OTP request", "Account compromised").
*   **Layer 2 (Contextual):** Uses extracted intelligence (like Phishing Links or suspicious UPI IDs) as a strong signal to confirm malicious intent.

### 2. Risk Engine
Calculates a dynamic `Risk Score` (0-100) for every conversation:
*   **Base Score:** Increases if scam keywords are detected.
*   **Multiplier:** Adds points for extracted entities (Bank Accounts +25, Phishing Links +25).
*   **Tactic Recognition:** Identifies specific tactics like "Urgency" or "Fear" to refine the score.

### 3. Agentic Persona
The system deploys varied personas (e.g., "Confused Grandma", "Busy Executive") to maintain engagement. Each persona has a unique instruction set (System Prompt) that guides the LLM response style while ensuring the goal remains constant: **Waste Time & Extract Intel**.

### 4. Intelligence Extractor
A regex-based module that constantly scans incoming text for:
*   Phone Numbers (+91...)
*   UPI IDs (scammer@upi)
*   Bank Account Numbers
*   Phishing URLs
*   Email Addresses
*   Case IDs / Policy Numbers

## Data Flow
1.  **Incoming Request:** User/Scammer sends a message via POST `/api/honeypot`.
2.  **Authentication:** Validated via `x-api-key`.
3.  **Processing:**
    *   `ScamDetector` analyzes intent.
    *   `IntelligenceExtractor` pulls entities.
    *   `RiskEngine` updates the session score.
4.  **AI Response:** If a scam is detected, `AgenticHoneypot` generates a context-aware reply using Llama-3 (via Groq).
5.  **Persistence:** Session state is updated in `honeypot.db` (SQLite).
6.  **Callback:** If sufficient intelligence is gathered (>2 items), a final report is sent to the evaluation server.
