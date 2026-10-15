import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse # <--- IMPORT NOU
from typing import List
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity

class NmapScanner(BaseScannerModule):
    def __init__(self):
        super().__init__()
        self.name = "Nmap Port Scanner"
        self.description = "Scans for open ports and services"
        self.required_tools = ["nmap"]

    def check_prerequisites(self) -> bool:
        from shutil import which
        return which("nmap") is not None

    def run(self, target: Target, mode: str = "fast", use_scripts: bool = False) -> List[VulnerabilityResult]:
        
        # --- LOGICA NOUĂ: Curățarea Țintei ---
        clean_target = target.input
        if clean_target.startswith("http"):
            # Transformă http://site.com/page?id=1 -> site.com
            parsed = urlparse(clean_target)
            clean_target = parsed.netloc
            # Dacă portul e inclus în URL (ex: site.com:8080), îl tăiem și pe ăla pentru Nmap
            if ":" in clean_target:
                clean_target = clean_target.split(":")[0]
                
        self.log(f"Starting Nmap scan on cleaned target: {clean_target}...", level="info")
        # -------------------------------------

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

            # IMPORTANT: Aici folosim clean_target în loc de target.input
            command.append(clean_target) 

            process = subprocess.run(command, capture_output=True, text=True)
            
            if process.returncode != 0 and not process.stdout.startswith("<?xml"):
                self.log(f"Nmap failed: {process.stderr}", level="error")
                return results

            root = ET.fromstring(process.stdout)
            
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        portid = port.get('portid')
                        service = port.find('service')
                        svc_name = service.get('name') if service is not None else "unknown"
                        
                        vuln = VulnerabilityResult(
                            name=f"Open Port: {portid}/tcp ({svc_name})",
                            description=f"Port {portid} is open running {svc_name}.",
                            severity=Severity.INFO,
                            tool_used="nmap"
                        )
                        results.append(vuln)
            
            self.log(f"Nmap found {len(results)} open ports.", level="success")
            
        except Exception as e:
            self.log(f"Error parsing Nmap XML: {e}", level="error")

        return results