from pymetasploit3.msfrpc import MsfRpcClient
import time
import re
from urllib.parse import urlparse
from typing import List
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity

class MetasploitScanner(BaseScannerModule):
    def __init__(self, password="superparola123", port=55553):
        super().__init__()
        self.name = "Metasploit RPC Integration"
        self.description = "Communicates with msfrpcd to run auxiliary scanner modules and search for exploits"
        self.required_tools = ["msfrpcd"]
        self.password = password
        self.port = port
        self.client = None

    def check_prerequisites(self) -> bool:
        try:
            self.client = MsfRpcClient(self.password, port=self.port, ssl=True)
            return True
        except Exception as e:
            self.log(f"Cannot connect to msfrpcd: {e}", level="error")
            return False

    def get_scanner_modules(self) -> List[str]:
        if not self.client:
            if not self.check_prerequisites():
                return ["scanner/http/title"]

        try:
            self.log("Fetching module list from MSF...", level="info")
            all_auxiliary = self.client.modules.auxiliary
            scanners = [mod for mod in all_auxiliary if mod.startswith("scanner/")]
            return sorted(scanners)
        except Exception as e:
            self.log(f"Error fetching modules: {e}", level="error")
            return ["scanner/http/title"]

    def search_modules(self, keyword: str) -> str:
        """Caută module în Metasploit folosind consola virtuală."""
        self.log(f"Searching MSF for '{keyword}'...", level="info")
        
        if not self.client:
            if not self.check_prerequisites():
                return "Eroare: Nu mă pot conecta la daemon-ul Metasploit."

        try:
            console = self.client.consoles.console()
            console.write(f"search {keyword}\n")
            
            raw_output = ""
            timeout = 15 
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                res = console.read()
                if 'data' in res and res['data']:
                    raw_output += res['data']
                
                if "Interact with a module by name or index" in raw_output or "No results from search" in raw_output:
                    break
                
                time.sleep(1)

            console.destroy()

            # Curățăm textul de culorile terminalului
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', raw_output)

            if "No results from search" in clean_text:
                return f"Niciun modul găsit în Metasploit pentru: '{keyword}'."

            return clean_text.strip()

        except Exception as e:
            self.log(f"Eroare la căutare: {e}", level="error")
            return f"Eroare internă la căutare: {e}"

    def extract_module_paths(self, raw_text: str) -> List[str]:
        """Extrage căile valide de module dintr-un text brut."""
        pattern = r'\b(?:exploit|auxiliary|post|payload|encoder)/[a-zA-Z0-9_/-]+\b'
        found_modules = list(dict.fromkeys(re.findall(pattern, raw_text)))
        return found_modules

    def run(self, target: Target, module_type="auxiliary", module_name="scanner/http/title", lhost=None, target_id=None) -> List[VulnerabilityResult]:
        self.log(f"Connecting to MSF to run {module_type}/{module_name} on {target.input}...", level="info")
        results = []

        if not self.client:
            if not self.check_prerequisites():
                return results

        try:
            # Curățăm ținta
            clean_target = target.input
            if clean_target.startswith("http"):
                parsed = urlparse(clean_target)
                clean_target = parsed.hostname 
            if not clean_target:
                clean_target = target.input 

            console = self.client.consoles.console()
            console.write(f"use {module_type}/{module_name}\n")
            console.write(f"set RHOSTS {clean_target}\n")

            # Setăm opțiunile specifice exploit-urilor dacă au fost oferite
            if lhost:
                console.write(f"set LHOST {lhost}\n")
            if target_id:
                console.write(f"set TARGET {target_id}\n")

            console.write("run\n")

            raw_output = ""
            timeout = 60 
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                res = console.read()
                if 'data' in res and res['data']:
                    raw_output += res['data']
                
                if "Auxiliary module execution completed" in raw_output or "Action completed" in raw_output or "[-] Auxiliary failed" in raw_output or "Exploit completed" in raw_output:
                    break
                
                time.sleep(2)

            console.destroy() 

            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', raw_output)

            useful_lines = []
            for line in clean_text.split('\n'):
                if "[+]" in line or "[*]" in line or "[-]" in line:
                    if "msf6" not in line and "execution completed" not in line:
                        useful_lines.append(line.strip())

            final_details = "\n".join(useful_lines)
            
            if not final_details:
                # Dacă nu avem output standard cu [*], afișăm totuși ce s-a printat pe ecran curățat
                final_details = clean_text.strip() if clean_text.strip() else f"Modulul a rulat complet, dar nu a detectat/returnat informații."

            vuln = VulnerabilityResult(
                name=f"MSF: {module_name.split('/')[-1]}", 
                description=final_details,
                severity=Severity.INFO if "[-]" not in final_details else Severity.LOW,
                tool_used="metasploit"
            )
            results.append(vuln)
            self.log(f"MSF {module_name} execution finished!", level="success")

        except Exception as e:
            self.log(f"Error during MSF execution: {e}", level="error")

        return results