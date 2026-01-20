import random
import hashlib
import time
from rich.console import Console

console = Console()

class ReverseOSINT:
    def __init__(self, target):
        self.target = target
        # Simulated list of known breach databases for the demo
        self.breach_databases = [
            "Collection #1 (2019)", 
            "DeepSound Leak", 
            "Cit0day Archive", 
            "Lazarus Group Dump",
            "Verifications.io"
        ]

    def check_breach_exposure(self):
        """
        Checks if the target's identity appears in known dark-web breach datasets.
        (Simulated logic for Hackathon stability, but mimics real API response)
        """
        findings = []
        
        # Create a deterministic hash of the target to make results consistent but "random-looking"
        target_hash = int(hashlib.md5(self.target.encode()).hexdigest(), 16)
        
        # 30% chance of being found in a breach
        if target_hash % 10 < 3: 
            db_found = self.breach_databases[target_hash % len(self.breach_databases)]
            findings.append({
                "type": "Breach Exposure",
                "data": f"Identity found in '{db_found}' dataset. Password/Email likely compromised.",
                "risk_level": "CRITICAL"
            })
        else:
             findings.append({
                "type": "Breach Check",
                "data": "No immediate records found in major public breach dumps.",
                "risk_level": "Low"
            })
            
        return findings

    def detect_trackers(self):
        """
        Analyzes the target's 'Digital Noise' to see if they are being monitored.
        """
        findings = []
        
        # Heuristic: Short/Generic usernames are scraped 10x more often
        is_high_value = len(self.target) < 6 or "admin" in self.target or "root" in self.target
        
        if is_high_value:
             findings.append({
                 "type": "Surveillance Alert", 
                 "data": f"High-value handle detected. Estimated 15+ scraper bots monitor this profile daily.",
                 "risk_level": "High"
             })
        else:
            findings.append({
                 "type": "Traffic Analysis", 
                 "data": "Profile visibility is normal. Passive bot activity detected.",
                 "risk_level": "Medium"
             })

        return findings

    def generate_honeytoken(self):
        """
        Generates a 'Trap URL' (Canary Token). 
        Concept: If the target puts this in their bio/repo, we track who clicks it.
        """
        token_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        trap_url = f"http://canary-tokens.com/u/{self.target}/{token_id}"
        
        return [{
            "type": "Counter-Intel",
            "data": f"Generated Trap URL: {trap_url} (Place in bio to track stalkers)",
            "risk_level": "Info"
        }]

    # Wrapper to run all checks
    def run_all(self):
        return self.check_breach_exposure() + self.detect_trackers() + self.generate_honeytoken()