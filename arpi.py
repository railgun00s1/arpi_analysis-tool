import sys
import os
import re
import socket
import dns.resolver
import shodan
import requests
import time
import feedparser
import nmap
import google.generativeai as genai

# --- NEW IMPORTS FOR SAFETY SETTINGS ---
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from googlesearch import search
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

# --- CONFIGURATION ---
# [IMPORTANT] REPLACE THIS WITH YOUR REAL KEY FROM https://aistudio.google.com/
GEMINI_API_KEY = "AIzaSyB9e63ReQqpAFXEgHuinjtCuU4_Wh7HtN0"

# OTHER KEYS (Replace with your actual keys)
SHODAN_API_KEY = "IKN76cm7fWRxLqtXXoekkdq1G57qCX9f"
VT_API_KEY = "a145b277b8c83de1ef410fe7370649ce84e9e8253b6cc98bed2d0c285ed7faa1"

console = Console()

# --- CONFIGURE AI (Uncensored for Security Analysis) ---
genai.configure(api_key=GEMINI_API_KEY)

# Safety settings to allow security context
safety_settings = {
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

# --- BANNER ---
def print_banner():
    console.clear()
    banner = r"""
    [bold cyan]
       _    ____  ____  ___ 
      / \  |  _ \|  _ \|_ _|
     / _ \ | |_) | |_) || | 
    / ___ \|  _ <|  __/ | | 
   /_/   \_\_| \_\_|   |___|
    [/bold cyan]
    [bold white]ARPI Analysis Tool v2.2[/bold white]
    [dim]Active Recon + Passive Intel + Custom Scans[/dim]
    [bold yellow] •• This is for educational use only •• [/bold yellow]
    [dim italic]Developed by: rlgn00s1 + ai[/dim italic]

    [bold red blink]! WARNING ![/bold red blink]
    [bold red]• • Be ethical at all times! • •[/bold red]
    
    [bold green]>>> Happy Threat Hunting <<<[/bold green]
    """
    console.print(Panel(banner, border_style="cyan"))

# --- ACTIVE RECON MODULE ---
class AutoReconAI:
    def __init__(self, target, scan_profile):
        self.target = target
        self.scan_profile = scan_profile
        self.nm = nmap.PortScanner()
        self.shodan_api = shodan.Shodan(SHODAN_API_KEY)
        
        self.scan_data = {}
        self.intel_data = {}
        self.osint_data = {"dorks": [], "news": []}
        
        safe_name = target.replace("/", "_").replace(":", "")
        self.report_file = f"ARPI_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"

    def run_nmap(self):
        # Define Profiles
        profiles = {
            "1": {"name": "Quick (Top 100)", "args": "-sV --top-ports 100 --version-intensity 3"},
            "2": {"name": "Standard (Top 1000 + Scripts)", "args": "-sC -sV"},
            "3": {"name": "Aggressive (OS Detect + All)", "args": "-A -T4"},
            "4": {"name": "Full Range (All 65535 Ports)", "args": "-p- -sV -T4"}
        }
        
        selected = profiles.get(self.scan_profile, profiles["1"])
        console.print(f"\n[bold green][1/4] Running Nmap: {selected['name']}...[/bold green]")
        console.print(f"[dim]Command: nmap {selected['args']} {self.target}[/dim]")

        try:
            # Run the scan
            self.nm.scan(self.target, arguments=selected['args'])
            
            # Check if host is up
            if not self.nm.all_hosts():
                console.print("[bold red][!] Host appears down or blocked by firewall.[/bold red]")
                console.print("[yellow]Try adding '-Pn' to arguments manually if you are blocked.[/yellow]")
                return False
                
            self.scan_data['hosts'] = self.nm.all_hosts()
            return True
            
        except Exception as e:
            console.print(f"[red]Nmap Critical Error: {e}[/red]")
            return False

    def get_clean_nmap_data(self):
        """Parses Nmap object into a clean string for the Report and AI."""
        output = []
        for host in self.nm.all_hosts():
            output.append(f"Host: {host} ({self.nm[host].hostname()})")
            output.append(f"State: {self.nm[host].state()}")
            
            # OS Detection
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                output.append(f"OS Guess: {self.nm[host]['osmatch'][0]['name']}")

            # Ports
            for proto in self.nm[host].all_protocols():
                output.append(f"\nProtocol: {proto.upper()}")
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    state = self.nm[host][proto][port]['state']
                    service = self.nm[host][proto][port]['name']
                    version = self.nm[host][proto][port]['product'] + " " + self.nm[host][proto][port]['version']
                    output.append(f"  - Port {port}: {state} | Service: {service} | Version: {version}")
        
        return "\n".join(output)

    def gather_intelligence(self):
        console.print("[bold green][2/4] Gathering Intel (Shodan/VT/OSINT)...[/bold green]")
        
        # OSINT - Dorks
        try:
            query = f"site:{self.target} filetype:pdf OR filetype:xls OR filetype:docx"
            for res in search(query, num_results=3):
                self.osint_data['dorks'].append(res)
        except: pass
        
        # Threat Intel - Shodan/VT
        for ip in self.scan_data.get('hosts', []):
            try:
                host = self.shodan_api.host(ip)
                self.intel_data[ip] = host.get('vulns', [])
            except:
                self.intel_data[ip] = "No Shodan Data"

    def analyze_and_report(self):
        console.print("[bold green][3/4] Generating AI Analysis...[/bold green]")
        
        clean_nmap = self.get_clean_nmap_data()
        
        prompt = f"""
        You are the ARPI Analysis Tool. 
        Analyze this security scan for: {self.target}
        
        [NMAP RAW DATA]
        {clean_nmap}
        
        [THREAT INTEL]
        {self.intel_data}
        
        [OSINT FILES]
        {self.osint_data['dorks']}
        
        TASK:
        1. Summarize the exposed services and operating system.
        2. Identify specific risks based on the port versions (are they old?).
        3. Explain any CVEs found in the Intel section.
        """
        
        # --- SMART MODEL FALLBACK SYSTEM ---
        # This fixes the "404 Model Not Found" error by trying multiple models
        ai_text = "AI Analysis Failed."
        
        try:
            # 1. Try the Fast Model (Flash)
            console.print("[dim]Attempting AI Analysis with Gemini 1.5 Flash...[/dim]")
            model = genai.GenerativeModel('gemini-1.5-flash', safety_settings=safety_settings)
            response = model.generate_content(prompt)
            ai_text = response.text
            
        except Exception as e_flash:
            # 2. If Flash fails, Fallback to Gemini Pro (Older but more compatible)
            console.print(f"[yellow][!] Flash model failed ({e_flash}). Switching to Gemini Pro...[/yellow]")
            try:
                model = genai.GenerativeModel('gemini-pro', safety_settings=safety_settings)
                response = model.generate_content(prompt)
                ai_text = response.text
            except Exception as e_pro:
                # 3. If both fail, print error
                console.print(f"\n[bold red][!] AI Critical Failure: {e_pro}[/bold red]")
                ai_text = f"AI Analysis Failed.\nError 1 (Flash): {e_flash}\nError 2 (Pro): {e_pro}"

        console.print(f"[bold green][4/4] Saving Report to {self.report_file}...[/bold green]")
        
        with open(self.report_file, "w") as f:
            f.write(f"# ARPI Security Report: {self.target}\n")
            f.write(f"**Generated:** {datetime.now()}\n")
            f.write(f"**Scan Profile:** {self.scan_profile}\n\n")
            
            f.write("## 1. Raw Network Scan Data\n")
            f.write("```text\n")
            f.write(clean_nmap)
            f.write("\n```\n\n")
            
            f.write("## 2. AI Risk Assessment\n")
            f.write(ai_text)
            
            f.write("\n\n## 3. Passive Intel Data\n")
            f.write(f"- Google Dorks: {self.osint_data['dorks']}\n")
            f.write(f"- Shodan Vulns: {self.intel_data}\n")

# --- PASSIVE MODULE ---
class PassiveModule:
    def run(self):
        console.clear()
        console.print(Panel("[bold cyan]PASSIVE INTEL MODE[/bold cyan]"))
        
        # FIX: Loop until valid input
        target = ""
        while not target:
            target = Prompt.ask("Enter Domain/IP [dim](e.g. scanme.nmap.org)[/dim]").strip()
            if not target:
                console.print("[red]Target cannot be empty![/red]")

        # DNS
        console.print(Panel("DNS Records", style="blue"))
        try:
            for r in ['A', 'MX', 'TXT']:
                ans = dns.resolver.resolve(target, r)
                console.print(f"{r}: {[x.to_text() for x in ans]}")
        except: console.print("[red]DNS Lookup Failed[/red]")
        
        console.input("\nPress Enter to return...")

# --- MAIN ---
if __name__ == "__main__":
    while True:
        print_banner()
        console.print("1. [bold green]Active Scan[/bold green] (Nmap + AI)")
        console.print("2. [bold cyan]Passive Intel[/bold cyan] (DNS Only)")
        console.print("3. Exit")
        
        choice = Prompt.ask("Selection", choices=["1", "2", "3"])
        
        if choice == "1":
            console.print("\n[bold]Select Scan Profile:[/bold]")
            console.print("1. Quick (Top 100 ports)")
            console.print("2. Standard (Top 1000 + Scripts) [Recommended]")
            console.print("3. Aggressive (Full OS/Version Detect) [LOUD]")
            console.print("4. Full Range (All 65535 ports) [SLOW]")
            
            profile = Prompt.ask("Profile", choices=["1", "2", "3", "4"], default="2")
            
            # FIX: Loop until valid input with placeholder
            target = ""
            while not target:
                target = Prompt.ask("Enter Target IP/Domain [dim](e.g. scanme.nmap.org, testasp.vulnweb.com)[/dim]").strip()
                if not target:
                    console.print("[red]Error: Target cannot be empty. Please enter a valid IP or Domain.[/red]")

            # Initialize and Run Active Recon
            bot = AutoReconAI(target, profile)
            if bot.run_nmap():
                bot.gather_intelligence()
                bot.analyze_and_report()
                console.input("\n[bold blue]Scan Complete. Press Enter to return to menu...[/bold blue]")
        
        elif choice == "2":
            PassiveModule().run()
            
        elif choice == "3":
            console.print("[bold]Exiting...[/bold]")
            sys.exit()
