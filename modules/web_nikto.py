import subprocess
import re
import shutil
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity

class NiktoScanner(BaseScannerModule):
    def __init__(self):
        super().__init__()
        self.name = "Nikto Web Scanner"
        self.description = "Scaneaza aplicatia web pentru fisiere periculoase si configurari gresite"

    def check_prerequisites(self) -> bool:
        """Verifica daca nikto este instalat si accesibil in sistem."""
        # Caută comanda 'nikto' in sistem (ca si cum ai scrie in terminal)
        if shutil.which("nikto") is not None:
            return True
        self.log("Nikto nu este instalat! Ruleaza: sudo apt install nikto", level="error")
        return False

    def run(self, target: Target) -> list:
        results = []
        
        # Oprim executia daca tool-ul nu exista pe sistem
        if not self.check_prerequisites():
            return results

        host = target.input.replace("http://", "").replace("https://", "").split('/')[0]
        
        self.log(f"Rulam Nikto pe {host}...", level="info")
        
        try:
            # -Tuning 123b7: un profil rapid si eficient
            process = subprocess.Popen(
                ["nikto", "-h", host, "-Tuning", "123b7", "-Display", "1", "-maxtime", "90s"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, _ = process.communicate()

            # Extragem constatarile
            findings = re.findall(r"\+ (.*)", stdout)
            
            for item in findings:
                # Filtram zgomotul
                if "0 host(s) tested" in item or "End Time" in item:
                    continue
                    
                sev = Severity.LOW
                item_lower = item.lower()
                if any(w in item_lower for w in ["vulnerable", "rce", "sql", "critical", "shell"]):
                    sev = Severity.HIGH
                elif any(w in item_lower for w in ["directory indexing", "outdated", "admin"]):
                    sev = Severity.MEDIUM

                results.append(VulnerabilityResult(
                    name="Web Misconfiguration (Nikto)",
                    description=item.strip(),
                    severity=sev,
                    tool_used="nikto"
                ))
                
        except Exception as e:
            self.log(f"Eroare la executia Nikto: {e}", level="error")
            
        return results