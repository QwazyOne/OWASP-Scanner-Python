from pymetasploit3.msfrpc import MsfRpcClient
import time
from urllib.parse import urlparse # <--- IMPORTUL NOU
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

    def check_prerequisites(self) -> bool:
        try:
            self.client = MsfRpcClient(self.password, port=self.port, ssl=True)
            return True
        except Exception as e:
            self.log(f"Cannot connect to msfrpcd: {e}", level="error")
            return False

    def get_scanner_modules(self) -> List[str]:
        """Extrage automat toate modulele de tip 'scanner' din Metasploit."""
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

    def run(self, target: Target, module_type="auxiliary", module_name="scanner/http/title") -> List[VulnerabilityResult]:
        self.log(f"Connecting to MSF to run {module_type}/{module_name} on {target.input}...", level="info")
        results = []

        if not self.client:
            if not self.check_prerequisites():
                return results

        try:
            # --- LOGICA NOUĂ DE CURĂȚARE A ȚINTEI ---
            clean_target = target.input
            if clean_target.startswith("http"):
                parsed = urlparse(clean_target)
                # .hostname ia doar domeniul/IP-ul, ignorând căile sau porturile
                clean_target = parsed.hostname 
            
            # Măsură de siguranță: dacă parse-ul dă greș, folosim inputul brut
            if not clean_target:
                clean_target = target.input 
            # ----------------------------------------

            # 1. Încărcăm modulul ales de utilizator
            msf_module = self.client.modules.use(module_type, module_name)
            
            # 2. Setăm ținta curățată
            msf_module['RHOSTS'] = clean_target
            
            # 3. Executăm job-ul
            job = msf_module.execute()
            job_id = job.get('job_id')
            
            if job_id is None:
                self.log("Module failed to start.", level="error")
                return results

            # 4. Așteptăm să termine
            self.log(f"Job {job_id} started. Waiting for completion...", level="info")
            while job_id in self.client.jobs.list:
                time.sleep(1)

            # 5. Raportăm rezultatul
            vuln = VulnerabilityResult(
                name=f"MSF Module: {module_name}",
                description=f"Successfully executed MSF module {module_name} against {clean_target}.",
                severity=Severity.INFO,
                tool_used="metasploit"
            )
            results.append(vuln)
            self.log("MSF execution finished!", level="success")

        except Exception as e:
            self.log(f"Error during MSF execution: {e}", level="error")

        return results