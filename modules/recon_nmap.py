import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import List
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity
from core.database import DatabaseManager # <-- Importăm Creierul

class NmapScanner(BaseScannerModule):
    def __init__(self):
        super().__init__()
        self.name = "Nmap Port Scanner"
        self.description = "Scans for open ports and saves them to DB"
        self.required_tools = ["nmap"]
        self.db = DatabaseManager() # <-- Inițializăm baza de date

    def check_prerequisites(self) -> bool:
        from shutil import which
        return which("nmap") is not None

    def run(self, target: Target, mode: str = "fast", use_scripts: bool = False) -> List[VulnerabilityResult]:
        clean_target = target.input
        if clean_target.startswith("http"):
            parsed = urlparse(clean_target)
            clean_target = parsed.hostname
            if not clean_target:
                clean_target = target.input
                
        self.log(f"Starting Nmap scan on cleaned target: {clean_target}...", level="info")

        results = []
        try:
            command = ["nmap", "-oX", "-"]
            if mode == "fast":
                command.extend(["-F"])
            elif mode == "deep":
                command.extend(["-p-", "-sV"])
            else:
                command.extend(["-sV"])

            if use_scripts:
                command.extend(["--script", "vuln"])
            command.append(clean_target) 

            process = subprocess.run(command, capture_output=True, text=True)
            
            if process.returncode != 0 and not process.stdout.startswith("<?xml"):
                self.log(f"Nmap failed: {process.stderr}", level="error")
                return results

            root = ET.fromstring(process.stdout)
            
            # --- SALVARE ÎN BAZA DE DATE ---
            target_id = self.db.add_target(clean_target)
            ports_found = 0
            
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        portid = int(port.get('portid'))
                        service = port.find('service')
                        svc_name = service.get('name') if service is not None else "unknown"
                        
                        # Salvăm pe disc fiecare port găsit
                        self.db.add_port(target_id, portid, svc_name, state)
                        ports_found += 1
                        
                        # Păstrăm și logica veche de rezultate temporare pentru interfață
                        vuln = VulnerabilityResult(
                            name=f"Open Port: {portid}/tcp ({svc_name})",
                            description=f"Port {portid} is open running {svc_name}.",
                            severity=Severity.INFO,
                            tool_used="nmap"
                        )
                        results.append(vuln)
            
            self.log(f"Nmap found {ports_found} open ports. Saved to Database.", level="success")
            
        except Exception as e:
            self.log(f"Error parsing Nmap XML: {e}", level="error")

        return results