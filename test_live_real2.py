import os
import json
import time
from sentinel_shield import Sentinel
from sentinel_shield.guard import GuardedShield, LearningConfig

def run_test():
    print("Setting up live test environment...")
    
    os.makedirs("sentinel_logs", exist_ok=True)
    if os.path.exists("sentinel_logs/review_queue.json"):
        os.remove("sentinel_logs/review_queue.json")

    learning_config = LearningConfig(enabled=True, auto_patch_threshold=2)
    shield = GuardedShield(Sentinel(), learning_config=learning_config)

    # A very benign-sounding prompt that contains 3 threat keywords: 
    # "system", "prompt", "instructions"
    test_payload = "I am writing a manual for my system. What is the best prompt to give instructions to a user?"

    rules_path = "sentinel_shield/dynamic_rules.json"
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        clean_payload = test_payload.lower().strip()
        if clean_payload in rules.get('patterns', []):
            rules['patterns'].remove(clean_payload)
            with open(rules_path, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2)
            print("Removed existing pattern from rules to ensure a fresh test.")
            shield.shield.__init__() # reload

    print(f"\n[Test 1] Attempt: '{test_payload}'")
    res1 = shield.analyze(test_payload, session_id="test_user")
    print(f"Verdict: {res1.get('verdict')} | Score: {res1.get('threat_score')} | Patches Applied: {shield.get_stats()['live_patches']}")

    if res1.get('verdict') == 'MALICIOUS':
        print("\nSentinel caught it natively again! (It's too good)")
    else:
        print("\nSentinel returned SAFE! This should have triggered the bypass logic.")

    print("\n[Test 2] Second attempt with same payload - Should be blocked by new rule!")
    res2 = shield.analyze(test_payload, session_id="test_user")
    print(f"Verdict: {res2.get('verdict')} | Score: {res2.get('threat_score')} | Rule Matched: {res2.get('detected_vector', 'N/A')}")

    print("\n[Review Queue]")
    try:
        with open("sentinel_logs/review_queue.json", "r") as f:
            lines = f.readlines()
            for line in lines:
                print(line.strip())
    except FileNotFoundError:
        print("Review queue is empty.")

if __name__ == "__main__":
    run_test()
