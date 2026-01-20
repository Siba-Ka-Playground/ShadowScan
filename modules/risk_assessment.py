from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm

console = Console()

class EthicsPolicy:
    def check_consent(self):
        """
        Enforces ethical usage policy before the tool runs.
        """
        console.clear()
        warning_text = (
            "[bold red]WARNING: OFFENSIVE OSINT MODE ENGAGED[/bold red]\n\n"
            "[bold yellow]This tool is designed for Authorized Red Teaming and Defensive Security Analysis.[/bold yellow]\n"
            "[bold yellow]Scanning targets without explicit permission is a violation of:[/bold yellow]\n"
            "[bold green]1. Computer Fraud and Abuse Act (CFAA)[/bold green]\n"
            "[bold green]2. GDPR & Local Privacy Laws[/bold green]\n"
            "[bold green]3. GitHub Terms of Service[/bold green]\n\n"
            "[bold yellow]You must agree to the following:[/bold yellow]\n"
            "[bold green]- I have authorization to scan this target.[bold green]\n"
            "[bold green]- I will not use this data for harassment or doxxing.[/bold green]\n"
            "[bold green]- I am responsible for any legal consequences.[/bold green]"
        )
        console.print(Panel(warning_text, title="LEGAL DISCLAIMER", border_style="red"))
        
        # In a real CLI, we force a 'y' input. 
        # If user says no, we exit.
        if not Confirm.ask("[bold yellow]Do you agree to these terms?[/bold yellow]"):
            console.print("[red]Terminating session.[/red]")
            exit()

class RiskScorer:
    def __init__(self):
        # Weighted point system
        self.risk_weights = {
            "CRITICAL": 30,  # Passwords, API Keys, Real-time Location
            "High": 15,      # PII, Commit Leaks, Vulnerable Libs
            "Medium": 10,    # Sentiment issues, Tracking detected
            "Low": 2,        # Standard metadata, Info
            "Info": 0
        }
        
        # Advice database mapped to finding types
        self.mitigation_db = {
            "Commit Leak": "Use 'BFG Repo-Cleaner' or 'git filter-branch' to scrub history. Rotate keys immediately.",
            "Visual Data Leak": "Blur sensitive monitors/notes in photos. Remove images containing credentials.",
            "Geolocation": "Disable GPS tagging in camera settings. Use an EXIF Scrubber before posting.",
            "Breach Exposure": "Enable 2FA immediately. Check HaveIBeenPwned and rotate passwords.",
            "Vulnerable Dependency": "Update libraries in requirements.txt. Run 'npm audit' or 'pip-audit'.",
            "Behavioral Risk": "Employee requires security awareness training (Phishing/Social Engineering risk)."
        }

    def calculate_score(self, findings):
        """
        Calculates a 0-100 Risk Score and generates a breakdown.
        """
        total_score = 0
        risk_counts = {"CRITICAL": 0, "High": 0, "Medium": 0, "Low": 0}
        unique_recommendations = set()

        for item in findings:
            level = item.get('risk_level', 'Info')
            
            # 1. Add Score
            points = self.risk_weights.get(level, 0)
            total_score += points
            
            # 2. Count Stats
            if level in risk_counts:
                risk_counts[level] += 1
                
            # 3. Collect Recommendations based on Type
            finding_type = item.get('type')
            if finding_type in self.mitigation_db:
                unique_recommendations.add(f"[bold cyan]Fix {finding_type}:[/bold cyan] {self.mitigation_db[finding_type]}")

        # Normalize Score (Cap at 100)
        final_score = min(total_score, 100)
        
        # Determine Severity Label
        if final_score >= 80: severity = "CRITICAL"
        elif final_score >= 50: severity = "HIGH"
        elif final_score >= 20: severity = "MEDIUM"
        else: severity = "LOW"

        # Display the detailed report
        self._print_report(final_score, severity, risk_counts, unique_recommendations)
        
        return final_score, severity

    def _print_report(self, score, severity, counts, recommendations):
        """
        Visualizes the data in a nice table.
        """
        # color logic
        color = "green"
        if severity == "HIGH": color = "orange3"
        if severity == "CRITICAL": color = "red"

        # 1. Stats Table
        table = Table(title="Vulnerability Breakdown", border_style="blue")
        table.add_column("Severity", justify="center")
        table.add_column("Count", justify="center")
        
        for level, count in counts.items():
            style = "white"
            if level == "CRITICAL" and count > 0: style = "bold red blink"
            elif level == "High" and count > 0: style = "red"
            
            if count > 0:
                table.add_row(f"[{style}]{level}[/{style}]", str(count))

        console.print("\n")
        console.print(table)

        # 2. Mitigation Plan (The "Powerful" part)
        if recommendations:
            rec_panel = "\n".join([f"- {rec}" for rec in recommendations])
            console.print(Panel(rec_panel, title="[bold green]RECOMMENDED MITIGATION PLAN[/bold green]", border_style="green"))
        else:
            console.print("[green]No specific mitigations required. Maintain OpSec.[/green]")