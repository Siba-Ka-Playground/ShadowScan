import requests
import re
from collections import Counter

class CodeMiner:
    def __init__(self, target_user):
        self.target = target_user
        self.api_url = f"https://api.github.com/users/{target_user}/events/public"
        self.headers = {'User-Agent': 'Shadow_Scan-OSINT-Scanner'}

    def scan(self):
        """
        Deep behavioral scan of user activity. 
        Extracts: Emails, Leaked Secrets in Commits/Comments, and 'Oops' history.
        """
        findings = []
        try:
            response = requests.get(self.api_url, headers=self.headers)
            
            # Error Handling
            if response.status_code == 404:
                return [{"type": "Error", "data": "User not found on GitHub.", "risk_level": "Low"}]
            if response.status_code == 403:
                return [{"type": "Error", "data": "GitHub API Rate Limit Exceeded (Try later or use Token).", "risk_level": "Low"}]
            if response.status_code != 200:
                return [{"type": "Error", "data": f"API Error: {response.status_code}", "risk_level": "Low"}]

            events = response.json()
            found_emails = set()
            
            # --- SIGNATURES (Behavioral & Secrets) ---
            secret_patterns = {
                "AWS Key": r"AKIA[0-9A-Z]{16}",
                "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
                "Google API": r"AIza[0-9A-Za-z-_]{35}",
                "Generic Token": r"(?:api|access)[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9_\-]{10,}['\"]",
                "Password": r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]"
            }

            for event in events:
                # 1. PUSH EVENTS (Commits)
                if event['type'] == 'PushEvent':
                    repo_name = event['repo']['name']
                    commits = event['payload'].get('commits', [])
                    
                    for commit in commits:
                        message = commit.get('message', '')
                        author_email = commit.get('author', {}).get('email', '')
                        
                        # A. Extract Author Email (Identity Leak)
                        if author_email and "noreply" not in author_email:
                            if author_email not in found_emails:
                                found_emails.add(author_email)
                                findings.append({
                                    "type": "Identity Leak",
                                    "data": f"Personal/Work Email found in commit: {author_email}",
                                    "risk_level": "Medium"
                                })

                        # B. Scan Commit Message for Secrets
                        for sig_name, pattern in secret_patterns.items():
                            if re.search(pattern, message, re.IGNORECASE):
                                findings.append({
                                    "type": "Commit Leak", 
                                    "data": f"Found '{sig_name}' in commit msg: {message[:40]}...",
                                    "risk_level": "High"
                                })
                        
                        # C. Detect 'Oops' Commits (History Risk)
                        # If they say "removed key", the key is likely in the PREVIOUS commit history
                        suspicious_words = ["remove key", "delete secret", "hide token", "fix creds", "revoked"]
                        if any(s in message.lower() for s in suspicious_words):
                             findings.append({
                                    "type": "History Risk", 
                                    "data": f"Suspicious cleanup detected: '{message}'. Check previous commit diffs!",
                                    "risk_level": "High"
                                })

                # 2. ISSUE & PR COMMENTS (Context Leaks)
                # Developers often paste logs/configs in comments
                elif event['type'] in ['IssueCommentEvent', 'PullRequestReviewCommentEvent']:
                    body = event['payload'].get('comment', {}).get('body', '')
                    repo_name = event['repo']['name']
                    
                    for sig_name, pattern in secret_patterns.items():
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append({
                                "type": "Comment Leak",
                                "data": f"Found '{sig_name}' in Issue/PR discussion on {repo_name}",
                                "risk_level": "CRITICAL"
                            })

            # 3. SUMMARY
            if not findings:
                findings.append({"type": "Info", "data": f"Scanned {len(events)} recent events. Behavior appears clean.", "risk_level": "Low"})
            else:
                # Add a summary item
                findings.append({"type": "Summary", "data": f"Activity Scan: {len(found_emails)} unique emails found.", "risk_level": "Medium"})
                
        except Exception as e:
            findings.append({"type": "Error", "data": str(e), "risk_level": "Low"})
            
        return findings