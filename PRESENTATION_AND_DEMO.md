# 🏆 India AI Impact Buildathon: Presentation & Demo Kit

**Team Name:** [Your Team Name]
**Project:** Agentic Honeypot (v4.0-JUDGE-READY)
**Submission Deadline:** Feb 13th, 2026

---

## 📽️ PART 1: Presentation Slides (Content Guide)

Use this content to fill your slide deck. Focus on **clarity** and **impact**.

### **Slide 1: Title Slide**
*   **Title:** Agentic Honeypot: Turning the Tables on Scammers with AI
*   **Subtitle:** An autonomous, AI-driven defense system that engages scammers, wastes their time, and extracts actionable threat intelligence.
*   **Team Name:** [Your Team Name]

---

### **Slide 2: The Problem (What real problem are you solving?)**
*   **The Issue:** Scammers operate at scale (Millions of calls/day). Blocking numbers doesn't work (they spoof new ones instantly). Victims (especially elderly) lose life savings to fear/urgency tactics.
*   **Why it's a problem:** Current defenses are **passive** (blocking). We need **active** defense to exhaust their resources.
*   **Who is affected:** Everyone with a phone, but especially vulnerable populations (elderly, non-tech savvy).

---

### **Slide 3: Our Solution (What did you build?)**
*   **Visual Strategy:** Use the **4 Image Layout** or **5 Circles** to show the flow.
*   **Content:**
    1.  **Detects:** Real-time intent analysis.
    2.  **Engages:** AI Personas (Grandma/Techie).
    3.  **Wastes Time:** Stalling tactics.
    4.  **Extracts Intel:** UPIs/Links for reporting.
*   **Key Capability:** **Autonomous Resource Exhaustion**. We make scamming expensive and frustrating.

---

### **Slide 4: How It Works (Simple Flow)**
*   **Input:** Incoming Call/Message (Analyzed for Keywords: "Bank Blocked", "KYC Update", "Lottery").
*   **Decision (AI Brain):**
    *   Is it a scam? -> **YES**.
    *   Which Persona to use? -> **"Confused Grandma"**.
    *   What Tactic are they using? -> **"Urgency"**.
*   **Output:** The AI generates a context-aware, stalling response (e.g., *"Oh dear, my glasses are missing, can you wait a moment?"*) to keep the scammer engaged.

---

### **Slide 5: Technical Approach (Backend Focus)**
*   **Visual Strategy:** Use the **5 Circles Layout**.
*   **Circle 1 (Core):** Python/Flask Server + Async Tasks.
*   **Circle 2 (Brain):** **Groq Llama-3** (Sub-second Latency).
*   **Circle 3 (Logic):** Hybrid Detection (Regex + LLM) + Risk Scoring.
*   **Circle 4 (Memory):** SQLite (Context-Aware Session Persistence).
*   **Circle 5 (Frontend):** Leaflet.js Map + WebSocket Real-time Updates.

---

### **Slide 6: Proof It Works (Evidence)**
*   **Visual Strategy:** Use the **4 Image Layout** (Crucial!).
    *   **Image 1:** **Terminal Output** showing `[SCAM DETECTED]` & `[INTEL EXTRACTED]`.
    *   **Image 2:** **Dashboard Map** showing the Red Dot (Threat Location).
    *   **Image 3:** **Risk Panel** showing Score 100/100 & Tactics (Urgency/Fear).
    *   **Image 4:** **Extracted Evidence Panel** showing captured UPI ID.
*   **Narration Script (Say this):**
    *"Here is our system in action. Top left shows our backend detecting a live scam. Top right tracks the threat location in real-time. Bottom left shows our AI analyzing the 'Urgency' tactic to assign a Critical Risk Score of 100. And finally, bottom right proves we successfully extracted the scammer's UPI ID to report to authorities."*

---

### **Slide 7: A Nuance You Handled**
*   **Context-Aware Memory:** Scammers hate repeating themselves.
*   **The nuance:** Most bots fail when a scammer says *"I just told you that"*.
*   **Our Design:** We implemented a **Conversational Buffer** in the database. The AI remembers previous turns (e.g., *"Oh yes, the OTP is 1234, sorry I forgot"*), making it indistinguishable from a real, confused victim.

---

### **Slide 8: A Trade-Off You Made**
*   **Visual Strategy:** Use the **Table Layout** (4 Columns).
*   **Table Content:**

| Feature (Metric) | Option A (GPT-4) | Option B (Groq Llama-3) | Our Choice (Impact) |
| :--- | :--- | :--- | :--- |
| **Latency (Speed)** | High (~3-5s) | **Ultra-Low (<1s)** | **Essential for Realism** |
| **Conversation Flow** | Pauses feel robotic | **Instant replies** | **Keeps Scammer Hooked** |
| **Cost per Token** | High ($$$) | **Low ($)** | **Scale to Millions** |

*   **Narration:** *"We faced a trade-off between Intelligence and Speed. While GPT-4 is smarter, its 3-second delay breaks the illusion of a real phone call. We chose Groq Llama-3 because its sub-second latency is critical for keeping a scammer engaged without them suspecting a bot."*

---

### **Slide 9: A Failure Case (Where it struggles)**
*   **Visual-Based Scams:**
    *   **Limitation:** If a scammer asks for a Video Call or Screen Share (e.g., AnyDesk scams).
    *   **Current State:** The system relies on Text/Audio. It cannot generate a convincing real-time Deepfake Video stream yet to fool a visual check.

---
---

## 🎬 PART 2: Demo Video Script (Terminal + Dashboard)

**Goal:** Show the backend working and the dashboard updating in real-time *without* needing a real scammer on the phone.

**Prerequisites:**
1.  Open **Two Windows** side-by-side:
    *   **Left:** VS Code Terminal.
    *   **Right:** Browser with Dashboard (`http://127.0.0.1:5000/dashboard`).
2.  Ensure server is running (`python app.py`).

**Step-by-Step Script:**

### **Scene 1: The Setup (0:00 - 0:15)**
*   **Visual:** Show the Dashboard. Explain the layout briefly.
*   **Narrator:** *"This is the Agentic Honeypot Dashboard. It monitors active threats, visualizes scam locations, and tracks extracted intelligence in real-time."*
*   **Action:** Point out "Total Intercepts" and "Active Threats" are waiting for data.

### **Scene 2: The Attack (0:15 - 0:45)**
*   **Visual:** Switch focus to Terminal. Run the verification script.
*   **Command:** `python verify_live_deployment.py` (or `verify_round2.py` if local).
*   **narrator:** *"We simulate an incoming scam attack using our verification engine. The system receives a high-risk message: 'URGENT: Your account is blocked.'"*
*   **Action:** Watch the terminal output showing:
    *   `[SCAM DETECTED]`
    *   `[AI RESPONSE GENERATED]`
    *   `[INTEL EXTRACTED]`

### **Scene 3: The Defense (0:45 - 1:15)**
*   **Visual:** **IMMEDIATELY** switch focus to the Dashboard (Right side).
*   **Action:**
    *   See the **Red Dot** appear on the Map (No jitter!).
    *   See the **Risk Score** spike to 100.
    *   See the **"LIVE THREAT ANALYTICS"** flash "UPI FRAUD" with "URGENCY" and "FEAR" tags.
    *   **Scroll Down** to the **Extracted Evidence** panel (Show off the scrollbar!).
*   **Narrator:** *"Instantly, the dashboard updates. The heatmap identifies the threat origin. The AI analyzes the 'Urgency' tactic and assigns a Risk Score of 100. Most importantly, it extracts the scammer's UPI ID for reporting."*

### **Scene 4: The Conclusion (1:15 - 1:30)**
*   **Visual:** Show the "System Logs" scrolling with the conversation history.
*   **Narrator:** *"By engaging the scammer autonomously, we've wasted their time, protected a potential human victim, and gathered actionable evidence for authorities. This is Active Defense."*

---

> **💡 Pro Tip for Demo:**
> Keep the Terminal text somewhat large (Ctrl + +) so judges can read the "SCAM DETECTED" logs.
> Make sure to **Refresh** the dashboard right before recording so it starts clean.
