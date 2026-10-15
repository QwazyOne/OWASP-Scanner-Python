from pymetasploit3.msfrpc import MsfRpcClient
import time
from typing import List
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity

class MetasploitScanner(BaseScannerModule):
    def __init__(self, password="superparola123", port=55553):
        super().__init__()
        self.name = "Metasploit RPC Integration"
        self.description = "Communicates with msfrpcd to run auxiliary scanner modules"
        self.required_tools = ["msfrpcd"]
        self.password = password
        self.port = port
        self.client = None
        
    def get_scanner_modules(self) -> List[str]:
        """Extrage automat toate modulele de tip 'scanner' din Metasploit."""
        if not self.client:
            if not self.check_prerequisites():
                return ["scanner/http/title"] # Fallback de siguranță

        try:
            self.log("Fetching module list from MSF...", level="info")
            all_auxiliary = self.client.modules.auxiliary
            
            # Filtrăm doar modulele care încep cu "scanner/"
            scanners = [mod for mod in all_auxiliary if mod.startswith("scanner/")]
            return sorted(scanners) # Le sortăm alfabetic
        except Exception as e:
            self.log(f"Error fetching modules: {e}", level="error")
            return ["scanner/http/title", "scanner/portscan/tcp"]
    def check_prerequisites(self) -> bool:
        # Verificăm dacă ne putem conecta la serverul MSF
        try:
            self.client = MsfRpcClient(self.password, port=self.port, ssl=True)
            return True
        except Exception as e:
            self.log(f"Cannot connect to msfrpcd: {e}", level="error")
            return False

    def run(self, target: Target, module_type="auxiliary", module_name="scanner/http/title") -> List[VulnerabilityResult]:
        self.log(f"Connecting to MSF to run {module_type}/{module_name} on {target.input}...", level="info")
        results = []

        if not self.client:
            if not self.check_prerequisites():
                return results

        try:
            # 1. Încărcăm modulul specificat
            msf_module = self.client.modules.use(module_type, module_name)
            
            # 2. Setăm opțiunile (Target-ul)
            # Extragem IP-ul (Metasploit RHOSTS preferă IP-uri sau domenii simple, nu URL-uri complete)
            clean_target = target.input.replace("http://", "").replace("https://", "").split("/")[0]
            msf_module['RHOSTS'] = clean_target
            
            # 3. Creăm o consolă virtuală pentru a citi output-ul text (opțional, dar util)
            console_id = self.client.consoles.console().cid
            
            # 4. Rulăm modulul
            job = msf_module.execute()
            job_id = job.get('job_id')
            
            if job_id is None:
                self.log("Module failed to start.", level="error")
                return results

            # 5. Așteptăm să termine
            self.log(f"Job {job_id} started. Waiting for completion...", level="info")
            while job_id in self.client.jobs.list:
                time.sleep(1)

            # 6. Analizăm rezultatele (simplificat)
            # Pentru modulele complexe, va trebui să citim din baza de date MSF sau din consolă
            # Aici este un exemplu generic de preluare a succesului
            
            vuln = VulnerabilityResult(
                name=f"MSF Module: {module_name}",
                description=f"Successfully executed MSF module {module_name} against {clean_target}.",
                severity=Severity.INFO, # Depinde de modulul rulat (ex: un modul de verificare CVE ar returna HIGH)
                tool_used="metasploit"
            )
            results.append(vuln)
            self.log("MSF execution finished!", level="success")

        except Exception as e:
            self.log(f"Error during MSF execution: {e}", level="error")

        return results