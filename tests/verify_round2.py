import requests
import time
import json

BASE_URL = "http://localhost:5000/api/honeypot"
API_KEY = "test-secret-api-key-123"

def run_verification():
    print("=== Round 2 Verification Script ===")
    
    # Session ID
    session_id = f"verify-{int(time.time())}"
    
    # 1. Start Conversation (Scam Trigger)
    print("\n1. Sending Initial Scam Message...")
    payload1 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "URGENT: Your SBI Policy #83748291 is lapsing. Contact support@fake-sbi-help.com immediately via Case ID: CS-998877.",
        },
        "metadata": {"channel": "SMS"}
    }
    
    headers = {"x-api-key": API_KEY, "Content-Type": "application/json"}
    
    resp1 = requests.post(BASE_URL, json=payload1, headers=headers)
    print(f"Status: {resp1.status_code}")
    data1 = resp1.json()
    print(f"Debug Scam Detected: {data1.get('debug_is_scam')}")
    
    # Check if Intel extracted
    # Note: debug_intel_count only counts the original 4 types in the python code I saw earlier, 
    # but I updated the logic to include new fields in the count? 
    # Let's check the logic I wrote in app.py for debug_intel_count...
    # I actually likely didn't update the debug_intel_count logic in the endpoint itself, 
    # just the callback logic. The endpoint logic was:
    # intel_count = len(intel.get('bankAccounts', [])) + ...
    # So debug_intel_count might report lower than actual, but that's fine for debug.
    
    # 2. Provide More Intel (Trigger Callback)
    print("\n2. Sending Follow-up with more Intel...")
    payload2 = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": "Pay the premium to UPI: insurance-renewal@okaxis or call +91 98765 43210 to avoid penalty.",
        },
        "conversationHistory": [payload1['message'], {"sender": "user", "text": "What do I do?"}]
    }
    
    resp2 = requests.post(BASE_URL, json=payload2, headers=headers)
    data2 = resp2.json()
    print(f"Status: {resp2.status_code}")
    print(f"Reply: {data2.get('reply')}")
    print(f"Debug Callback Triggered: {data2.get('debug_should_callback')}")
    
    if data2.get('debug_should_callback'):
        print("\n✅ SUCCESS: Callback logic triggered!")
    else:
        print("\n⚠️ WARNING: Callback logic NOT triggering yet (might need more messages or intel).")

if __name__ == "__main__":
    try:
        run_verification()
    except Exception as e:
        print(f"Failed: {e}")
