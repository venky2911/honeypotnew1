import os
import json
import re
import requests
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import random
from datetime import datetime
import threading
import random
from datetime import datetime
import threading
from dotenv import load_dotenv
import google.generativeai as genai

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'AIzaSyAnv8Ne4xD4L4TZsdOwHOjdlKYY1b6UpE0')
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Determine if Gemini is configured
gemini_available = bool(GEMINI_API_KEY)

@dataclass
class ExtractedIntelligence:
    bankAccounts: List[str]
    upiIds: List[str]
    phishingLinks: List[str]
    phoneNumbers: List[str]
    emailAddresses: List[str]
    caseIds: List[str]
    policyNumbers: List[str]
    orderNumbers: List[str]
    suspiciousKeywords: List[str]
    tactics: List[str] = None
    scamType: str = "Unknown"
    riskScore: int = 0

class RiskEngine:
    """Calculates a dynamic risk score (0-100) based on accumulated indicators"""
    @staticmethod
    def calculate_score(is_scam: bool, intel: ExtractedIntelligence, message_text: str) -> int:
        score = 0
        text = message_text.lower()

        # 1. Base Score
        if is_scam: score += 30

        # 2. Hard Evidence (High Impact)
        if intel.upiIds: score += 25
        if intel.phishingLinks: score += 25
        if intel.bankAccounts: score += 25
        if intel.phoneNumbers: score += 15
        if intel.emailAddresses: score += 15
        if intel.caseIds or intel.policyNumbers or intel.orderNumbers: score += 10

        # 3. Behavioral/Tactic Indicators (Medium Impact)
        if any(t in text for t in ['urgent', 'immediately', 'block', 'suspend']): score += 10
        if any(t in text for t in ['offer', 'lottery', 'bonus', 'job']): score += 10
        
        # 4. Contextual
        if len(intel.tactics or []) > 0: score += 10

        # Cap at 100
        return min(100, score)

class ScamDetector:
    def __init__(self):
        self.scam_patterns = [
            r'account.*block', r'account.*compromised', r'account.*suspend',
            r'verify.*immediately', r'urgent.*action', r'click.*link',
            r'share.*otp', r'share.*pin', r'upi.*id', r'bank.*details',
            r'suspended.*account', r'expire.*today', r'confirm.*identity',
            r'freeze.*account', r'security.*verify', r'provide.*account.*number',
            r'policy.*lapsing', r'case.*id', r'contact.*support'
        ]
        
        self.scam_keywords = [
            'urgent', 'verify', 'blocked', 'suspended', 'expire', 'immediate',
            'click here', 'confirm', 'otp', 'upi', 'bank account', 'credit card',
            'debit card', 'atm', 'pin', 'cvv', 'security code', 'compromised',
            'freeze', 'permanently', 'act now', 'lapsing', 'policy', 'case id'
        ]

    def classify_scam_type(self, text: str, intel: ExtractedIntelligence) -> str:
        """Simple rule-based classification (LLM can override later)"""
        text = text.lower()
        if intel.upiIds or 'upi' in text: return "UPI Fraud"
        if intel.bankAccounts or 'otp' in text or 'kyc' in text: return "Bank/KYC Fraud"
        if 'job' in text or 'hiring' in text: return "Job Scam"
        if 'investment' in text or 'returns' in text or 'crypto' in text: return "Investment Scam"
        if 'loan' in text or 'credit' in text: return "Loan Fraud"
        if intel.phishingLinks: return "Phishing Link"
        if intel.caseIds: return "Support Impersonation"
        if intel.policyNumbers: return "Insurance Fraud"
        return "General Suspicion"
    
    def detect_scam(self, message: str) -> Tuple[bool, float]:
        """Detect if a message is a scam and return confidence score"""
        message_lower = message.lower()
        
        # Pattern matching
        pattern_matches = sum(1 for pattern in self.scam_patterns 
                            if re.search(pattern, message_lower))
        
        # Keyword matching
        keyword_matches = sum(1 for keyword in self.scam_keywords 
                            if keyword in message_lower)
        
        # Calculate confidence score
        total_indicators = len(self.scam_patterns) + len(self.scam_keywords)
        confidence = (pattern_matches + keyword_matches) / total_indicators
        
        # Consider it a scam if confidence > 0.15 or has critical patterns
        is_scam = confidence > 0.15 or any(
            re.search(pattern, message_lower) 
            for pattern in [
                'account.*block', 'verify.*immediately', 'share.*otp', 
                'account.*compromised', 'freeze.*account', 'provide.*account.*number'
            ]
        )
        
        return is_scam, confidence

class IntelligenceExtractor:
    def __init__(self):
        self.patterns = {
            'bankAccounts': [r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', r'\b\d{10,18}\b'],
            'upiIds': [r'[a-zA-Z0-9\.\-_]+@[a-zA-Z]+'],
            'phishingLinks': [r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'],
            'phoneNumbers': [r'\+91[-\s]?[6-9]\d{9}', r'\b[6-9]\d{9}\b'],
            'emailAddresses': [r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'],
            'caseIds': [r'(?:Case|Ref|Ticket)\s*(?:ID|No|#)?\s*[:\-\s]\s*([A-Z0-9-]{5,})'],
            'policyNumbers': [r'(?:Policy|Plan)\s*(?:No|#)?\s*[:\-\s]\s*(\d{6,})'],
            'orderNumbers': [r'(?:Order|Tracking)\s*(?:ID|No|#)?\s*[:\-\s]\s*([A-Z0-9-]{6,})']
        }
        
        self.tactic_keywords = {
            'Urgency': ['urgent', 'immediately', 'now', 'today', 'expire', 'deadline'],
            'Fear': ['police', 'block', 'suspend', 'arrest', 'illegal', 'fail', 'court', 'lawsuit'],
            'Greed/Reward': ['lottery', 'winner', 'bonus', 'cashback', 'prize', 'gift'],
            'Authority': ['bank manager', 'police officer', 'tax department', 'fbi', 'cbi', 'customs', 'manager']
        }
    
    def extract_from_text(self, text: str) -> ExtractedIntelligence:
        """Extract intelligence from text"""
        intelligence = ExtractedIntelligence(
            bankAccounts=[], upiIds=[], phishingLinks=[], phoneNumbers=[], 
            emailAddresses=[], caseIds=[], policyNumbers=[], orderNumbers=[],
            suspiciousKeywords=[], tactics=[], scamType="Unknown", riskScore=0
        )
        
        # Extract using patterns
        for field, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                getattr(intelligence, field).extend(matches)
        
        # Extract suspicious keywords
        scam_keywords = ['urgent', 'verify', 'blocked', 'suspended', 'expire', 'immediate', 'otp', 'pin', 'cvv', 'account', 'bank', 'upi']
        for keyword in scam_keywords:
            if keyword.lower() in text.lower():
                intelligence.suspiciousKeywords.append(keyword)
        
        # Extract Tactics
        found_tactics = set()
        for tactic, keywords in self.tactic_keywords.items():
            if any(k in text.lower() for k in keywords):
                found_tactics.add(tactic)
        intelligence.tactics = list(found_tactics)

        # Remove duplicates
        intelligence.bankAccounts = list(set(intelligence.bankAccounts))
        intelligence.upiIds = list(set(intelligence.upiIds))
        intelligence.phishingLinks = list(set(intelligence.phishingLinks))
        intelligence.phoneNumbers = list(set(intelligence.phoneNumbers))
        intelligence.emailAddresses = list(set(intelligence.emailAddresses))
        intelligence.caseIds = list(set(intelligence.caseIds))
        intelligence.policyNumbers = list(set(intelligence.policyNumbers))
        intelligence.orderNumbers = list(set(intelligence.orderNumbers))
        intelligence.suspiciousKeywords = list(set(intelligence.suspiciousKeywords))
        
        return intelligence

# We expect database to be in same package or path
import database

class AgenticHoneypot:
    def __init__(self):
        self.detector = ScamDetector()
        self.extractor = IntelligenceExtractor()
        # Initialize Database
        database.init_db()
        
        # AI Agent personas (Randomized)
        self.personas = [
            "curious_user",
            "concerned_customer", 
            "tech_naive_person",
            "elderly_victim",
            "busy_professional"
        ]
    
    def get_ai_response(self, message: str, conversation_history: List[Dict], persona: str = "curious_user") -> str:
        """Generate AI response using Gemini or fallback to rule-based"""
        if gemini_available:
            return self._get_gemini_response(message, conversation_history, persona)
        else:
            return self._get_fallback_response(message, conversation_history)
    
    def _get_gemini_response(self, message: str, conversation_history: List[Dict], persona: str) -> str:
        """Generate response using official Gemini SDK with FULL CONTEXT MEMORY"""
        try:
            genai.configure(api_key=GEMINI_API_KEY)
            
            # Build conversation context
            system_prompt = self._build_context(persona)
            
            # Use gemini-1.5-flash as it is most stable for free tiers
            model = genai.GenerativeModel('gemini-1.5-flash', system_instruction=system_prompt)
            
            # Prepare Gemini contents format (SDK uses dicts of role and parts)
            contents = []
            
            # History
            for msg in conversation_history:
                if msg.get('text'):
                    role = "user" if msg.get('sender') == 'user' else "model"
                    contents.append({'role': role, 'parts': [msg['text']]})
            
            # Add Current Message
            contents.append({'role': 'user', 'parts': [message]})
            
            # Generate Response
            response = model.generate_content(
                contents,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=150,
                    temperature=0.7,
                ),
            )
            
            # Check for block or missing text due to safety
            if not response.text:
                 logger.error("Gemini API returned empty/blocked response.")
                 return self._get_fallback_response(message, conversation_history)
                 
            return response.text.strip()
        
        except Exception as e:
            # Check specifically for Quota Exceeded (429) to log it clearly
            if '429' in str(e) or 'quota' in str(e).lower():
                logger.error(f"GEMINI QUOTA EXCEEDED (429): Your free tier credits are used up. {e}")
            else:
                logger.error(f"Gemini SDK Exception: {e}")
            return self._get_fallback_response(message, conversation_history)
    
    def _build_context(self, persona: str) -> str:
        """Build context for AI agent based on Indian Persona"""
        persona_contexts = {
            "curious_user": "You are a cautious but curious Indian user named Rahul from Pune. Ask 1 question at a time. Act confused about banking terminologies like NEFT or UPI. Never reveal you know it's a scam.",
            "concerned_customer": "You are a panicked SBI customer named Amit. You're worried about your account security. Use subtle Indian English ('kindly do the needful', 'I am having tension'). Ask for specific verify steps. Do not expose the honeypot.",
            "tech_naive_person": "You are bad with technology, a shopkeeper named Ramesh in Delhi. Ask what 'OTP' or 'UPI scanner' means. Say you only know how to use WhatsApp. Waste their time with simple questions.",
            "elderly_victim": "You are an elderly pensioner named Uncle Sharma from Bangalore. You are slow to understand. Ask them to repeat. Complain about your glasses, say your grandson handles the 'Paytm'.",
            "busy_professional": "You are a busy IT professional in Hyderabad in a meeting. Ask for the 'bottom line'. Demand a quick fix but be skeptical. Threaten to call the police cyber cell if they push too hard."
        }
        base_instr = "\nGoal: Keep the scammer engaged as long as possible to extract UPI IDs, Bank Accounts, and Phone Numbers. Keep responses extremely realistic, human-like, and strictly under 2 sentences. React specifically to what they just said."
        return persona_contexts.get(persona, persona_contexts["curious_user"]) + base_instr
    
    def _get_fallback_response(self, message: str, conversation_history: List[Dict]) -> str:
        # Simple fallback (kept same)
        if 'otp' in message.lower(): return "Bhaiya, I am not receiving the OTP. Can you send it again on SMS?"
        if 'money' in message.lower() or 'pay' in message.lower(): return "I don't have that much balance right now. Can I pay later?"
        return "Sorry, I am unable to understand properly. Can you explain in simple words?"

    def _transcribe_audio(self, audio_file) -> str:
        """Transcribe audio using Groq Whisper API via direct HTTP"""
        try:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}"
            }
            files = {
                'file': (audio_file.filename, audio_file.read(), audio_file.content_type),
                'model': (None, 'whisper-large-v3')
            }
            # Rewind file pointer if read above
            audio_file.seek(0)
            
            response = requests.post(
                "https://api.groq.com/openai/v1/audio/transcriptions",
                headers=headers,
                files=files,
                timeout=30
            )
            if response.status_code == 200:
                return response.json().get('text', '')
            return "[Audio Transcription Failed]"
        except Exception:
            return "[Audio Processing Error]"

    def process_message(self, session_id: str, message: Dict, conversation_history: List[Dict], metadata: Dict) -> Dict:
        """Process incoming message with Round 2 Features"""
        
        message_text = message.get('text', '')
        
        # Load or Create Session
        session_data = database.get_session(session_id)
        if not session_data:
            session_data = {
                'scam_detected': False,
                'total_messages': 0,
                'extracted_intelligence': ExtractedIntelligence([], [], [], [], [], [], [], [], []),
                'agent_notes': [],
                'persona': random.choice(self.personas), # Feature 8: Random Persona
                'callback_sent': False, # Fix: Callback Safety
                'created_at': datetime.now().isoformat()
            }
            # Initial Save
            self._save_session(session_id, session_data)
        else:
            # Rehydrate Data
            self._rehydrate_session(session_data)

        session = session_data
        session['total_messages'] += 1
        
        # 1. Detect Scam & Calculate Score
        is_scam, confidence = self.detector.detect_scam(message_text)
        
        # 2. Extract Intelligence (Tactics + Data)
        current_intel = self.extractor.extract_from_text(message_text)
        
        # Enhanced Detection: Use Intel as Strong Signal
        if current_intel.phishingLinks or current_intel.upiIds or current_intel.bankAccounts or current_intel.phoneNumbers:
             is_scam = True
             confidence = max(confidence, 0.85)

        self._merge_intelligence(session['extracted_intelligence'], current_intel)
        
        # 3. Dynamic Risk Scoring (Feature 3)
        risk_score = RiskEngine.calculate_score(
            session['scam_detected'] or is_scam, 
            session['extracted_intelligence'], 
            message_text
        )
        session['extracted_intelligence'].riskScore = risk_score

        # 4. Update Session State
        if is_scam and not session['scam_detected']:
            session['scam_detected'] = True
            session['extracted_intelligence'].scamType = self.detector.classify_scam_type(message_text, session['extracted_intelligence'])
            session['agent_notes'].append(f"Scam Detected: {session['extracted_intelligence'].scamType} (Conf: {confidence:.2f})")
        
        # 5. Generate Response
        response_payload = {
            "status": "success",
            "transcription": message_text if message.get('is_audio') else None
        }

        if session['scam_detected']:
            # AI Agent Reply
            ai_reply = self.get_ai_response(message_text, conversation_history, session['persona'])
            response_payload["reply"] = ai_reply
            
            # Check for Callback (Fix: Safety Check)
            if self._should_end_conversation(session) and not session.get('callback_sent'):
                self._send_final_callback(session_id, session)
                session['callback_sent'] = True
                response_payload["status"] = "completed"
        else:
            response_payload["reply"] = "I don't understand. Who is this?"

        # Save State
        self._save_session(session_id, session)
        
        return response_payload
    
    def _save_session(self, session_id, session):
        db_update = session.copy()
        db_update['extracted_intelligence'] = asdict(session['extracted_intelligence'])
        if isinstance(db_update['agent_notes'], list):
             db_update['agent_notes'] = json.dumps(db_update['agent_notes']) # Store as JSON string if DB expects it
        
        # Check if exists to decide create/update (simplified for this context)
        # Assuming database.update_session handles "upsert" or we check logical flow
        # For safety in this specific file flow:
        existing_session = database.get_session(session_id)
        if existing_session:
            database.update_session(session_id, db_update)
        else:
            database.create_session(session_id, db_update)

    def _rehydrate_session(self, session_data):
        # Convert JSON strings back to Objects
        if isinstance(session_data['extracted_intelligence'], str):
             intel_dict = json.loads(session_data['extracted_intelligence'])
        else:
             intel_dict = session_data['extracted_intelligence']
        
        # Backwards compatibility: Fill missing fields
        defaults = {
            'emailAddresses': [], 'caseIds': [], 'policyNumbers': [], 'orderNumbers': [],
            'tactics': [], 'scamType': 'Unknown', 'riskScore': 0
        }
        for key, default_val in defaults.items():
            if key not in intel_dict:
                intel_dict[key] = default_val
                
        session_data['extracted_intelligence'] = ExtractedIntelligence(**intel_dict)
        
        if isinstance(session_data['agent_notes'], str):
            try:
                session_data['agent_notes'] = json.loads(session_data['agent_notes'])
            except:
                 session_data['agent_notes'] = []

    def _merge_intelligence(self, session_intel, new_intel):
        # Helper to merge lists unique
        for field in ['bankAccounts', 'upiIds', 'phishingLinks', 'phoneNumbers', 'emailAddresses', 'caseIds', 'policyNumbers', 'orderNumbers', 'suspiciousKeywords', 'tactics']:
            current = getattr(session_intel, field) or []
            new_items = getattr(new_intel, field) or []
            setattr(session_intel, field, list(set(current + new_items)))

    def _should_end_conversation(self, session: Dict) -> bool:
        """End if we have critical intel or hit msg limit (Hackathon Rule 3)"""
        intel = session['extracted_intelligence']
        intel_count = (
            len(intel.bankAccounts) + 
            len(intel.upiIds) + 
            len(intel.phishingLinks) + 
            len(intel.bankAccounts) + 
            len(intel.upiIds) + 
            len(intel.phishingLinks) + 
            len(intel.phoneNumbers) +
            len(intel.emailAddresses)
        )
        logger.info(f"Callback Check: Msgs={session['total_messages']}, Intel={intel_count} (Req: >10 or >=2)")
        # Requirement: > 10 messages OR >= 2 intel items
        # AND Scam must be detected (Feature safety)
        should_callback = session['scam_detected'] and (session['total_messages'] > 10 or intel_count >= 2)
        return should_callback
    
    def _send_final_callback(self, session_id: str, session: Dict):
        """Send final results to GUVI callback endpoint"""
        try:
            # Calculate Duration
            created_at = datetime.fromisoformat(session.get('created_at', datetime.now().isoformat()))
            duration_seconds = int((datetime.now() - created_at).total_seconds())

            payload = {
                "sessionId": session_id,
                "scamDetected": session['scam_detected'],
                "scamType": session['extracted_intelligence'].scamType,
                "confidenceLevel": session['extracted_intelligence'].riskScore / 100.0, # Feature 3 mapped
                "riskScore": session['extracted_intelligence'].riskScore,
                "totalMessagesExchanged": session['total_messages'],
                "engagementDurationSeconds": duration_seconds,
                "extractedIntelligence": asdict(session['extracted_intelligence']),
                "agentNotes": "; ".join(session['agent_notes'])
            }
            
            requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            logger.info(f"Callback sent for session {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to send callback for session {session_id}: {e}")

# Initialize the honeypot
honeypot = AgenticHoneypot()
