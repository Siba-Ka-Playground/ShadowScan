import requests
import re

class RepoScanner:
    def __init__(self, repo_url, github_token=None):
        self.repo_url = repo_url.strip("/")
        # Extract Owner and Repo Name safely
        try:
            parts = self.repo_url.split("/")
            self.owner = parts[-2]
            self.repo = parts[-1]
        except IndexError:
            self.owner = None
            self.repo = None
            
        # Token is crucial for content scanning to avoid rate limits
        self.headers = {"Authorization": f"token {github_token}"} if github_token else {}
        self.token_present = bool(github_token)

        # Content Regex Patterns (The "Deep Scan" Logic)
        self.secret_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Generic Password": r"(password|passwd|pwd|secret)[\s]*[=:]+[\s]*['\"][^\n]+['\"]",
            "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})"
        }

    def scan_repo(self):
        findings = []
        
        # 1. Validation
        if not self.owner or not self.repo:
            return [{"type": "Error", "data": "Invalid GitHub URL format.", "risk_level": "Low"}]

        print(f"[DEBUG] Target Repository: {self.owner}/{self.repo}")

        # 2. Branch Detection Strategy
        files = []
        branch_used = "main"
        
        # Try 'main'
        api_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/trees/main?recursive=1"
        resp = requests.get(api_url, headers=self.headers)
        
        if resp.status_code == 200:
            files = resp.json().get('tree', [])
            branch_used = "main"
        elif resp.status_code == 404:
            # Fallback to 'master'
            print("[DEBUG] 'main' branch not found. Trying 'master'...")
            api_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/trees/master?recursive=1"
            resp = requests.get(api_url, headers=self.headers)
            if resp.status_code == 200:
                files = resp.json().get('tree', [])
                branch_used = "master"

        # 3. Handle API Errors
        if resp.status_code == 403:
             return [{"type": "API Limit", "data": "GitHub Rate Limit Exceeded. Use a Token!", "risk_level": "Low"}]
        
        if not files:
             return [{"type": "Access Denied", "data": "Could not access file tree. Repo might be Private.", "risk_level": "Low"}]

        print(f"[DEBUG] Successfully scanned branch: '{branch_used}' ({len(files)} files found)")

        # 4. Define Suspicious Filenames
        suspicious_files = {
            ".env": "Environment Config (High Risk)",
            "config.py": "Configuration File",
            "secrets.json": "Secrets File",
            "package.json": "JS Dependencies",
            "package.json.bak": "Backup File",
            "wp-config.php": "WordPress Config",
            "docker-compose.yml": "Container Orchestration",
            "id_rsa": "SSH Private Key",
            "ftp": "FTP Configuration folder"
        }

        # 5. SCANNING LOOP
        count_scanned_content = 0
        
        for file in files:
            path = file['path']
            
            # A. Metadata Scan (Filename Check)
            for filename, desc in suspicious_files.items():
                if path.endswith(filename) or path == filename:
                    findings.append({
                        "type": "Vulnerable File", 
                        "data": f"Found sensitive file: {path} ({desc})", 
                        "risk_level": "High"
                    })
            
            # B. Specific Directory Check
            if "ftp/" in path or "backup/" in path:
                findings.append({
                        "type": "Exposed Directory", 
                        "data": f"Sensitive Directory Found: {path}", 
                        "risk_level": "Medium"
                    })

            # C. DEEP CONTENT SCAN (New Feature)
            # We scan the content of specific code files for hardcoded secrets.
            # We limit this to avoiding checking images/binaries.
            if self._is_interesting_file(path) and count_scanned_content < 20: 
                # Limit to 20 files per scan to prevent freezing/rate-limits in demo
                secret_finding = self._scan_file_content(path, branch_used)
                if secret_finding:
                    findings.extend(secret_finding)
                count_scanned_content += 1

        if not findings:
             findings.append({"type": "Info", "data": f"Scan completed on '{branch_used}'. No obvious secrets found.", "risk_level": "Low"})

        return findings

    def _is_interesting_file(self, path):
        """Returns True if we should read the text content of this file."""
        exts = [".py", ".js", ".json", ".env", ".txt", ".php", ".yml", ".xml", ".sh"]
        return any(path.endswith(e) for e in exts) and "node_modules" not in path

    def _scan_file_content(self, file_path, branch):
        """
        Fetches the raw text of the file and runs Regex for secrets.
        Uses raw.githubusercontent.com to bypass some API JSON limits.
        """
        findings = []
        # Construct Raw URL (e.g., https://raw.githubusercontent.com/owner/repo/main/file.py)
        raw_url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{branch}/{file_path}"
        
        try:
            # We use a standard request here (no auth headers needed for public raw files)
            response = requests.get(raw_url, timeout=3)
            
            if response.status_code == 200:
                content = response.text
                
                for secret_name, pattern in self.secret_patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        # Mask the secret for display
                        masked = match[:4] + "..." if len(match) > 5 else "HIDDEN"
                        findings.append({
                            "type": "Hardcoded Secret", 
                            "data": f"{secret_name} found in '{file_path}': {masked}", 
                            "risk_level": "CRITICAL"
                        })
        except:
            pass # Fail silently on network errors to keep scan moving
            
        return findings