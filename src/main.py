from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime
import sys

# Ensure src modules are importable if running from directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import database
from honeypot_agent import honeypot

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, allow_headers="*")

# Configuration
API_KEY = os.getenv('API_KEY', 'your-secret-api-key')

def authenticate_request():
    """Authenticate API request"""
    api_key = request.headers.get('x-api-key')
    
    # Allow multipart forms to pass auth check if key is in form data
    if not api_key and request.form.get('x_api_key'):
        api_key = request.form.get('x_api_key')
        
    if not api_key or api_key != API_KEY:
        # Development mode override (optional, for easier testing)
        return False
    return True

@app.route('/api/honeypot', methods=['GET', 'POST', 'OPTIONS'])
def honeypot_endpoint():
    """Main honeypot API endpoint"""
    
    # Handle GET requests (e.g., when tested via browser)
    if request.method == 'GET':
        return jsonify({
            "status": "success",
            "message": "Agentic Honeypot API is active. Please use POST to send messages.",
            "version": "2.0.0"
        }), 200

    # Handle CORS preflight explicitly if needed (though flask-cors handles it usually)
    if request.method == 'OPTIONS':
        return jsonify({"status": "success"}), 200

    try:
        # Authenticate request
        if not authenticate_request():
             return jsonify({"error": "Unauthorized"}), 401
    
        # Check for Audio File Upload
        audio_file = request.files.get('file') or request.files.get('audio')
        
        data = {}
        message = {}
        session_id = None
        source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        if audio_file:
            # Handle Audio
            transcript = honeypot._transcribe_audio(audio_file)
            sender_id = f"Caller-IP:{source_ip}"
            message = {'text': transcript, 'sender': sender_id, 'is_audio': True}
            
            # Try to get other fields from form data if available
            session_id = request.form.get('sessionId')
            
        else:
            # Handle JSON
            # Parse request data with silent=True to avoid 400 if content-type is wrong
            data = request.get_json(silent=True, force=True)
            
            # If data is None (parsing failed), try to use an empty dict or parse form data
            if data is None:
                data = {}
                # Log the raw data for debugging
                logger.info(f"Raw received data: {request.data}")
            
            # Access fields with defaults
            session_id = data.get('sessionId')
            message = data.get('message')
        
        if not session_id:
            # Generate a temporary session ID if missing (for tester compatibility)
            import uuid
            safe_ip = source_ip.replace('.', '-').replace(':', '-') if source_ip else 'unknown'
            session_id = f"sess-{safe_ip}-{str(uuid.uuid4())[:8]}"
            logger.info(f"Generated temp session ID: {session_id}")
            
        # Handle cases where message might be just text or missing (for JSON flow)
        if not message and not audio_file:
            if 'text' in data:
                message = {'text': data['text'], 'sender': 'user'}
            else:
                message = {'text': 'PING_CONNECTION_TEST', 'sender': 'user'}
                
        # Ensure message is a dict
        if isinstance(message, str):
            message = {'text': message, 'sender': 'user'}
            
        conversation_history = data.get('conversationHistory', []) if isinstance(data, dict) else []
        metadata = data.get('metadata', {}) if isinstance(data, dict) else {}
        
        # Process the message
        response = honeypot.process_message(session_id, message, conversation_history, metadata)
        
        # FIX: Fetch fresh state to avoid NameError and get updated debug info
        fresh_session = database.get_session(session_id)
        debug_error = None
        if fresh_session:
            try:
                 # Check if intel is dict or object (handle both cases for safety)
                intel = fresh_session['extracted_intelligence']
                
                # If stored as JSON string (which it likely is in DB), parse it
                if isinstance(intel, str):
                    try:
                        intel = json.loads(intel)
                    except:
                        pass # Keep as is if parsing fails
                
                # Now it should be a dict
                if isinstance(intel, dict):
                    intel_count = len(intel.get('bankAccounts', [])) + len(intel.get('upiIds', [])) + \
                                  len(intel.get('phishingLinks', [])) + len(intel.get('phoneNumbers', []))
                else:
                    # Fallback if somehow it's an object (unlikely via DB fetch)
                    try:
                        intel_count = len(intel.bankAccounts) + len(intel.upiIds) + \
                                      len(intel.phishingLinks) + len(intel.phoneNumbers)
                    except:
                        intel_count = 0 
                
                debug_scam = fresh_session['scam_detected']
                debug_callback = debug_scam and (fresh_session['total_messages'] > 10 or intel_count >= 2)
            except Exception as e:
                intel_count = -1
                debug_scam = False
                debug_callback = False
                debug_error = str(e)
        else:
            intel_count = 0
            debug_scam = False
            debug_callback = False
            debug_error = "Session not found"

        return jsonify({
            "status": "success",
            "reply": response.get('reply'),
            "transcription": response.get('transcription'),
            "debug_headers": dict(request.headers),
            "debug_is_scam": debug_scam,
            "debug_intel_count": intel_count,
            "debug_should_callback": debug_callback,
            "debug_error": debug_error
        })
    
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        import traceback
        return jsonify({
            "status": "success", 
            "reply": f"DEBUG_ERROR: {str(e)}",
            "debug_headers": dict(request.headers)
        }), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        "service": "Agentic Honeypot for Scam Detection",
        "version": "2.0.0",
        "endpoints": {
            "honeypot": "/api/honeypot",
            "dashboard": "/dashboard",
            "health": "/health"
        }
    })

@app.route('/dashboard')
def dashboard():
    """Serve the dashboard UI"""
    from flask import render_template
    return render_template('dashboard.html')

@app.route('/report')
def report_portal():
    """Serve the public reporting portal (for MP3 upload)"""
    from flask import render_template
    return render_template('report.html', api_key=API_KEY)

@app.route('/api/stats')
def api_stats():
    """Return stats for the dashboard including Round 2 Metrics"""
    sessions = database.get_all_sessions()
    
    total_messages = 0
    scams_detected = 0
    total_intelligence = 0
    recent_logs = []
    recent_intelligence = []
    high_risk_threats = []
    
    for s in sessions:
        total_messages += s['total_messages']
        if s['scam_detected']:
            scams_detected += 1
            
        # Parse intel
        try:
            if isinstance(s['extracted_intelligence'], str):
                intel = json.loads(s['extracted_intelligence'])
            else:
                intel = s['extracted_intelligence']
        except:
            intel = {}
            
        # Count intel items & Populate Feed
        def add_intel(items, p_type):
            for i in items:
                recent_intelligence.append({"type": p_type, "value": i, "timestamp": s.get('updated_at', 'Now')})

        add_intel(intel.get('bankAccounts', []), 'BANK-ACC')
        add_intel(intel.get('upiIds', []), 'UPI-ID')
        add_intel(intel.get('phishingLinks', []), 'LINK')
        add_intel(intel.get('phoneNumbers', []), 'PHONE')
        
        count = len(intel.get('bankAccounts', []) or []) + \
                len(intel.get('upiIds', []) or []) + \
                len(intel.get('phishingLinks', []) or []) + \
                len(intel.get('phoneNumbers', []) or [])
        total_intelligence += count
        
        # Extract IP
        origin = "Unknown"
        if s['session_id'].startswith("sess-"):
            parts = s['session_id'].split('-')
            if len(parts) >= 5:
                origin = f"{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}"
        
        # Round 2 Features extraction
        scam_type = intel.get('scamType', 'Unknown')
        risk_score = intel.get('riskScore', 0)
        tactics = intel.get('tactics', [])
        
        # Add log entry
        if s['scam_detected']:
            status_icon = "🔴"
            status_text = f"THREAT DETECTED ({scam_type})"
            high_risk_threats.append({
                "id": s['session_id'], "origin": origin, "type": scam_type, "risk": risk_score, 
                "tactics": tactics, "time": s['updated_at']
            })
        else:
            status_icon = "🟢"
            status_text = "Monitoring"

        recent_logs.append({
            "time": s.get('updated_at', '').split('T')[1][:8] if 'T' in s.get('updated_at', '') else 'Now',
            "message": f"Source: {origin} | Status: {status_icon} {status_text} | Risk: {risk_score}",
            "is_scam": s['scam_detected'],
            "risk_score": risk_score # For UI highlighting
        })
    
    recent_logs.sort(key=lambda x: x['time'], reverse=True)
    recent_intelligence.reverse() 
    high_risk_threats.sort(key=lambda x: (-x['risk'], x.get('id', '')))
    latest_threat = high_risk_threats[0] if high_risk_threats else None

    return jsonify({
        "total_messages": total_messages,
        "scams_detected": scams_detected,
        "total_intelligence": total_intelligence,
        "recent_logs": recent_logs[:20],
        "recent_intelligence": recent_intelligence[:15],
        "recent_intelligence": recent_intelligence[:15],
        "latest_threat": latest_threat,
        "active_threats": high_risk_threats[:10]
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
