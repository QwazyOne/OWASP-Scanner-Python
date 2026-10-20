import subprocess
import re
import shutil
import os
import tempfile
from typing import Optional
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity, AuthConfig, AuthType

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

    def run(self, target: Target, auth: Optional[AuthConfig] = None) -> list:
        results = []

        # Oprim executia daca tool-ul nu exista pe sistem
        if not self.check_prerequisites():
            return results

        is_https = target.input.lower().startswith("https://")
        host = target.input.replace("http://", "").replace("https://", "").split('/')[0]

        self.log(f"Rulam Nikto pe {host} (ssl={is_https})...", level="info")

        tmp_config = None
        try:
            # -Tuning 123b7: un profil rapid si eficient
            command = ["nikto", "-h", host, "-Tuning", "123b7", "-Display", "1", "-maxtime", "90s"]
            # Pentru tinte HTTPS (ex. port non-standard :4280) fortam SSL
            if is_https:
                command.append("-ssl")

            # Autentificare. ATENTIE: in Nikto '-H' inseamna "extended help",
            # NU header. Cookie-ul de sesiune se trimite prin config (STATIC-COOKIE).
            if auth and auth.is_active():
                if auth.auth_type == AuthType.BASIC and auth.username:
                    command.extend(["-id", f"{auth.username}:{auth.password or ''}"])

                # Cookie de sesiune (sau FORM care a produs un cookie): Nikto trimite
                # cookie-ul doar prin directiva STATIC-COOKIE dintr-un fisier de config.
                # Un config minimal strica scanarea (pierde caile implicite), deci
                # pornim de la config-ul real al Nikto si adaugam cookie-ul la o copie.
                cookie_val = auth.cookie if auth.auth_type in (AuthType.COOKIE, AuthType.FORM) else None
                if cookie_val:
                    base_conf = next((p for p in [
                        "/etc/nikto/config.txt", "/etc/nikto.conf", "/etc/nikto/nikto.conf",
                    ] if os.path.isfile(p)), None)
                    fd, tmp_config = tempfile.mkstemp(prefix="nikto_", suffix=".conf")
                    with os.fdopen(fd, "w") as f:
                        if base_conf:
                            with open(base_conf) as src:
                                f.write(src.read())
                        f.write(f"\nSTATIC-COOKIE={cookie_val}\n")
                    command.extend(["-config", tmp_config])

                if auth.auth_type == AuthType.HEADER:
                    # Nikto nu suporta headere arbitrare din CLI (ex: Bearer token).
                    self.log("Nikto nu suporta headere custom; rulez neautentificat. "
                             "Foloseste SQLMap pentru scanarea autentificata prin header.", level="error")

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, _ = process.communicate()

            # Extragem constatarile (liniile Nikto incep cu "+ ")
            findings = re.findall(r"\+ (.*)", stdout)

            # Linii de banner/sumar care NU sunt vulnerabilitati
            noise_prefixes = (
                "target ip", "target hostname", "target port", "start time",
                "end time", "host(s) tested", "ssl info", "no cgi directories",
                "items checked", "robots.txt\" contains",
            )

            for item in findings:
                item = item.strip()
                item_lower = item.lower()
                if not item or item_lower.startswith(noise_prefixes):
                    continue
                if "host(s) tested" in item_lower or "items checked" in item_lower:
                    continue

                sev = Severity.LOW
                if any(w in item_lower for w in ["vulnerable", "rce", "sql injection", "critical", "shell", "traversal"]):
                    sev = Severity.HIGH
                elif any(w in item_lower for w in ["directory indexing", "outdated", "admin", "x-powered-by", "x-frame-options", "debug http"]):
                    sev = Severity.MEDIUM

                # Nume distinct per constatare: altfel deduplicarea din DB
                # (dupa vuln_name) ar pastra o singura linie Nikto.
                results.append(VulnerabilityResult(
                    name=f"Nikto: {item[:80]}",
                    description=item,
                    severity=sev,
                    tool_used="nikto"
                ))
                
        except Exception as e:
            self.log(f"Eroare la executia Nikto: {e}", level="error")
        finally:
            if tmp_config and os.path.exists(tmp_config):
                try:
                    os.remove(tmp_config)
                except OSError:
                    pass

        return results