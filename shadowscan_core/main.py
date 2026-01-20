import argparse
import sys
import time
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich.text import Text

# --- MODULES ---
try:
    from modules.code_miner import CodeMiner
    from modules.repo_scanner import RepoScanner
    from modules.visual_intel import VisualIntel
    from modules.social_analyzer import SocialPostAnalyzer
    from modules.reverse_osint import ReverseOSINT
    from modules.risk_assessment import RiskScorer, EthicsPolicy
except ImportError as e:
    print(f"CRITICAL ERROR: Missing module files. {e}")
    sys.exit(1)

# Initialize Rich Console
console = Console()

def get_banner_text():
    """Generates the ASCII Art and Info Panel content."""
    f = pyfiglet.Figlet(font='doom')
    ascii_art = f.renderText('SHADOW SCAN')
    
    dev_info = """
[bold cyan]Tool Name:[/bold cyan] [bold magenta]SHADOW SCAN[/bold magenta]       
[bold cyan]Developed by:[/bold cyan] [bold magenta]Sibasundar Barik[/bold magenta]
[bold cyan]Team Name:[/bold cyan] [bold magenta]The GreyCrown[/bold magenta]
[bold cyan]Version:[/bold cyan] [bold magenta]1.0[/bold magenta]
    """

    pillar_text = """        
[bold yellow]1. Multi-Modal Fusion:[/bold yellow]   [bold green]Text + Image + Code integration.[/bold green]
[bold yellow]2. Visual Intelligence:[/bold yellow]  [bold green]Geo-location & Metadata extraction.[/bold green]
[bold yellow]3. Autonomous Agent:[/bold yellow]     [bold green]Self-learning scan logic.[/bold green]
[bold yellow]4. Reverse OSINT:[/bold yellow]        [bold green]Tracker & surveillance detection.[/bold green]
[bold yellow]5. Risk & Ethics:[/bold yellow]        [bold green]Vulnerability scoring & compliance.[/bold green]
    """
    
    return ascii_art + dev_info + pillar_text

class ShadowScanEngine:
    def __init__(self, args):
        self.target = args.username
        self.image = args.image
        self.caption = args.caption
        self.repo = args.repo
        self.token = args.token
        self.findings = []  # Central storage for all intelligence

    def display_banner(self):
        """Displays the banner in the main execution flow."""
        console.clear()
        banner_content = get_banner_text()
        console.print(Panel(banner_content, 
                            title="[bold red]OFFENSIVE OSINT FRAMEWORK v1.0[/bold red]", 
                            subtitle="Autonomous Intelligence Engine",
                            border_style="bold yellow"))

    def run(self):
        # --- PHASE 1: INITIALIZATION ---
        self.display_banner()
        
        # Ethics Check (Pillar 5)
        policy = EthicsPolicy()
        policy.check_consent()

        # Initialize the Intelligence Graph (Tree)
        target_label = self.target if self.target else "Unknown Target"
        root = Tree(f":detective: [bold blue]Target Identity: {target_label}[/bold blue]")
        
        with console.status("[bold green]Engaging Autonomous Agents...[/bold green]") as status:
            
            # --- PHASE 2: EXECUTION (The 5 Pillars) ---
            
            # PILLAR 1 & 3: CODE MINING
            if self.target:
                status.update(f"[bold yellow]Scanning Code Repositories for {self.target}...[/bold yellow]")
                miner = CodeMiner(self.target)
                code_data = miner.scan()
                self._update_graph(root, "Code Intelligence", code_data)
                time.sleep(0.5) 

            # PILLAR 1 (Deep Scan): REPO ANALYSIS
            if self.repo:
                status.update(f"[bold yellow]Deep Scanning Repository: {self.repo}...[/bold yellow]")
                scanner = RepoScanner(self.repo, github_token=self.token) 
                repo_data = scanner.scan_repo()
                self._update_graph(root, "Deep Repo Analysis", repo_data)

            # PILLAR 2 & 1: VISUAL & SOCIAL FUSION
            if self.image or self.caption:
                status.update(f"[bold yellow]Running Multi-Modal Social Analysis...[/bold yellow]")
                analyzer = SocialPostAnalyzer()
                social_data = analyzer.analyze_post(self.image, self.caption)
                
                # If image exists, add EXIF data to social findings
                if self.image:
                    status.update(f"[bold yellow]Extracting Visual Metadata (EXIF)...[/bold yellow]")
                    visual = VisualIntel(self.image)
                    meta_data = visual.extract_metadata()
                    social_data.extend(meta_data)

                self._update_graph(root, "Visual & Social Intel", social_data)

            # PILLAR 4: REVERSE OSINT
            if self.target:
                status.update(f"[bold yellow]Checking for Surveillance (Reverse OSINT)...[/bold yellow]")
                rev = ReverseOSINT(self.target)
                # Combine distinct checks
                rev_data = rev.check_breach_exposure() + rev.generate_honeytoken()
                # If your ReverseOSINT class has detect_trackers, add it here too
                try: 
                    rev_data += rev.detect_trackers() 
                except: pass
                
                self._update_graph(root, "Reverse OSINT & Counter-Intel", rev_data)

        # --- PHASE 3: REPORTING & RISK SCORE ---
        console.print("\n")
        console.print(root)
        
        # PILLAR 5: RISK ASSESSMENT
        scorer = RiskScorer()
        score, severity = scorer.calculate_score(self.findings)
        
        self._display_risk_panel(score, severity)

    def _update_graph(self, root_tree, branch_name, data_list):
        """Adds a branch to the tree with color-coded risk levels."""
        if not data_list: return
        branch = root_tree.add(f"[bold white]{branch_name}[/bold white]")
        
        for item in data_list:
            self.findings.append(item)
            
            # Color Mapping Logic
            lvl = item.get('risk_level', 'Low')
            style = "green"
            icon = "✓"
            
            if lvl == "Medium": 
                style = "yellow"
                icon = "⚠"
            if lvl == "High": 
                style = "magenta"
                icon = "⚡"
            if lvl == "CRITICAL": 
                style = "bold red"
                icon = "💀"
            
            branch.add(f"[{style}]{icon} {item['data']} ({lvl})[/{style}]")

    def _display_risk_panel(self, score, severity):
        """Displays the final scorecard."""
        color = "green"
        if severity == "HIGH": color = "yellow"
        if severity == "CRITICAL": color = "red"
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_row(f"[bold {color} size=20]FINAL RISK SCORE: {score}/100 ({severity})[/bold {color} size=20]")
        grid.add_row("[dim]Risk calculated based on aggregate exposure exploitability.[/dim]")
        
        console.print(Panel(grid, border_style=color, title="Risk Assessment"))

# --- CUSTOM HELP FORMATTER ---
class RichHelpFormatter(argparse.RawTextHelpFormatter):
    """Custom formatter to show ASCII art before help text."""
    def format_help(self):
        banner_content = get_banner_text()
        console.print(Panel(banner_content, 
                            title="[bold red]OFFENSIVE OSINT FRAMEWORK v1.0[/bold red]", 
                            border_style="bold yellow"))
        return super().format_help()

def print_guide():
    """Prints a detailed 'How-To' guide for the user."""
    f = pyfiglet.Figlet(font='doom')
    console.print(f.renderText('SHADOW SCAN'), style="bold magenta")
    
    guide = """
[bold white]WELCOME TO THE SHADOW SCAN COMMAND CENTER[/bold white]
This tool aggregates 5 Pillars of OSINT into a single Offensive scan.

[bold yellow]1. BASIC USER SCAN [/bold yellow]
   [green]Command:[/green] python main.py -u <username>
   [dim]Example: python main.py -u hacker_007[/dim]
   [i]Scans public code commits, events, and runs Reverse OSINT checks.[/i]

[bold yellow]2. DEEP REPO VULNERABILITY SCAN [/bold yellow]
   [green]Command:[/green] python main.py -r <github_link>
   [dim]Example: python main.py -r https://github.com/facebook/react[/dim]
   [i]Scans specific repo files for leaked API keys, passwords, and bad dependencies.[/i]

[bold yellow]3. VISUAL GEOLOCATION SCAN [/bold yellow]
   [green]Command:[/green] python main.py -i <path_to_image>
   [dim]Example: python main.py -i assets/photo.jpg[/dim]
   [i]Extracts EXIF metadata (GPS, Device Info) from local images.[/i]

[bold yellow]4. SOCIAL MEDIA THREAT ANALYSIS [/bold yellow]
   [green]Command:[/green] python main.py -i <image> -c <caption>
   [dim]Example: python main.py -i assets/screen.png -c "I hate my boss!"[/dim]
   [i]Uses NLP to read the caption and OCR to read text INSIDE the image for leaks.[/i]

[bold yellow]5. FULL OFFENSIVE MODE (All Pillars)[/bold yellow]
   [green]Command:[/green] python main.py -u <user> -r <repo> -i <image> -c <caption>
    """
    console.print(Panel(guide, title="[bold magenta]Operational Manual[/bold magenta]", border_style="blue"))

# --- ENTRY POINT ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SHADOW SCAN: Offensive Multi-Model OSINT Framework",
        formatter_class=RichHelpFormatter
    )
    
    parser.add_argument("-u", "--username", help="Target Username (e.g., github_user)")
    parser.add_argument("-r", "--repo", help="GitHub Repository URL for deep scanning")
    parser.add_argument("--token", help="GitHub API Token (Optional)")
    parser.add_argument("-i", "--image", help="Path to local image file")
    parser.add_argument("-c", "--caption", help="Social media caption text")
    parser.add_argument("-g", "--guide", action="store_true", help="Show the detailed user manual")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.guide:
        print_guide()
        sys.exit(0)

    try:
        engine = ShadowScanEngine(args)
        engine.run()
    except KeyboardInterrupt:
        console.print("\n[red][!] Operation aborted by user.[/red]")
    except Exception as e:
        console.print(f"\n[bold red][!] Critical System Error: {e}[/bold red]")