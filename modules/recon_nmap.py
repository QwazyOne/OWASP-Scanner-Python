import subprocess
import xml.etree.ElementTree as ET
from typing import List
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity

class NmapScanner(BaseScannerModule):
    def __init__(self):
        super().__init__()
        self.name = "Nmap Port Scanner"
        self.description = "Scans ports and detects service versions with flexible options"
        self.required_tools = ["nmap"]

    def check_prerequisites(self) -> bool:
        from shutil import which
        return which("nmap") is not None

    # --- MODIFICARE: Adăugăm parametrii mode și use_scripts ---
    def run(self, target: Target, mode: str = "default", use_scripts: bool = False) -> List[VulnerabilityResult]:
        self.log(f"Scanning {target.input} [Mode: {mode}, Scripts: {use_scripts}]...", level="info")
        results = []

        try:
            # 1. Construcția Comenzii de Bază (Output XML la consolă)
            command = ["nmap", "-oX", "-"]
            
            # 2. Selectarea Modului de Scanare
            if mode == "fast":
                # -F: Fast mode (scanează top 100 porturi în loc de 1000)
                # -T4: Timing agresiv (mai rapid)
                command.extend(["-F", "-T4"])
            
            elif mode == "deep":
                # -p-: Scanează TOATE porturile (1-65535)
                # -sV: Versiuni servicii
                # -O: Detecție Sistem de Operare
                # Atenție: Asta durează mult!
                command.extend(["-p-", "-sV", "-O", "-T4"])
                
            else: # Default
                # --top-ports 1000: Cele mai comune 1000 porturi
                # -sV: Versiuni servicii
                command.extend(["--top-ports", "1000", "-sV"])

            # 3. Activarea Scripturilor (NSE)
            if use_scripts:
                # --script=vuln: Rulează o suită de scripturi care verifică vulnerabilități cunoscute
                command.append("--script=vuln")

            # Adăugăm ținta la final
            command.append(target.input)
            
            # Debug: Afișăm comanda exactă care se execută (util pentru depanare)
            print(f"DEBUG Executing: {' '.join(command)}")
            
            # Lansăm procesul
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Citim output-ul XML complet
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.log(f"Nmap failed: {stderr}", level="error")
                return []

            # Parsăm XML-ul (stdout acum conține tot textul)
            root = ET.fromstring(stdout)
            # 4. Execuția
            # Folosim 'sudo' automat doar dacă e deep scan (pentru OS detection), altfel rulăm normal
            # Notă: Pe Kali ești deja root de obicei, dar e bine de știut.
            process = subprocess.run(command, capture_output=True, text=True)
            
            if process.returncode != 0:
                self.log(f"Nmap failed: {process.stderr}", level="error")
                return []

            # 5. Parsarea XML
            root = ET.fromstring(process.stdout)
            
            for host in root.findall('host'):
                # Extragem OS-ul dacă există
                os_match = host.find('.//osmatch')
                os_name = os_match.get('name') if os_match is not None else "Unknown OS"

                for port in host.findall('.//port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else "unknown"
                        product = service.get('product') if service is not None else ""
                        version = service.get('version') if service is not None else ""
                        
                        full_service = f"{product} {version}".strip()
                        
                        # Verificăm dacă scripturile au găsit ceva specific pe acest port
                        script_output = ""
                        for script in port.findall('script'):
                            sid = script.get('id')
                            output = script.get('output')
                            script_output += f"\n[Script {sid}]: {output}"

                        description = f"Port {port_id}/{protocol} open. Service: {service_name} {full_service}."
                        if mode == "deep":
                            description += f" OS: {os_name}"
                        if script_output:
                            description += f"\nPotential Vulns: {script_output}"

                        # Determinăm severitatea
                        severity = Severity.INFO
                        if use_scripts and "VULNERABLE" in script_output:
                            severity = Severity.HIGH
                        
                        vuln = VulnerabilityResult(
                            name=f"Open Port: {port_id} ({service_name})",
                            description=description,
                            severity=severity,
                            tool_used="nmap"
                        )
                        results.append(vuln)

        except Exception as e:
            self.log(f"Error running nmap: {e}", level="error")

        return results