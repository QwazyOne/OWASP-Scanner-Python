import subprocess
from typing import List
from typing import Optional
from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity, AuthConfig, AuthType

class SQLMapScanner(BaseScannerModule):
    def __init__(self):
        super().__init__()
        self.name = "SQLMap injection Scanner"
        self.description = "Detecs SQL Injection vulnerabilities in url parameters"
        self.required_tools = ["sqlmap"]

    def check_prerequisites(self) -> bool:
        from shutil import which
        return which("sqlmap") is not None
    
    def run(self, target: Target, level: int = 1, risk: int = 1,
            auth: Optional[AuthConfig] = None) -> List[VulnerabilityResult]:
        self.log(f"Testing {target.input} for SQL Injection...", level="info")
        results = []

        if not target.input.startswith(("http://", "https://")):
            self.log("Target must be a URL.", level="error")
            return []

        try:
            # Adăugăm --batch și --fail-fast (se oprește la prima eroare/succes ca să fie mai rapid)
            command = [
                "sqlmap",
                "-u", target.input,
                "--batch",
                "--dbs",
                f"--level={level}",
                f"--risk={risk}"
            ]

            # --- AUTENTIFICARE PE APLICATII WEB PROTEJATE ---
            if auth and auth.is_active():
                if auth.auth_type == AuthType.COOKIE and auth.cookie:
                    command.extend(["--cookie", auth.cookie])
                elif auth.auth_type == AuthType.BASIC and auth.username:
                    command.extend(["--auth-type", "Basic",
                                    "--auth-cred", f"{auth.username}:{auth.password or ''}"])
                elif auth.auth_type == AuthType.HEADER and auth.headers:
                    # SQLMap accepta mai multe headere separate prin '\n'
                    joined = "\\n".join(l.strip() for l in auth.headers.splitlines() if l.strip())
                    command.extend(["--headers", joined])
                elif auth.auth_type == AuthType.FORM:
                    # Login automat prin formular inainte de scanare
                    if auth.login_url and auth.login_data:
                        command.extend(["--auth-url", auth.login_url,
                                        "--auth-data", auth.login_data])
                    elif auth.cookie:
                        command.extend(["--cookie", auth.cookie])

            # Folosim PIPE pentru a capta tot
            process = subprocess.run(command, capture_output=True, text=True)
            output = process.stdout + process.stderr # Combinăm erorile cu output-ul standard

            # --- LOGICA NOUĂ DE DETECȚIE ---
            # Căutăm oricare dintre semnele de succes ale SQLMap
            success_markers = [
                "sqlmap identified the following injection point",
                "available databases",
                "Parameter:", 
                "Type: boolean-based blind",
                "Type: error-based",
                "Type: UNION query",
                "appears to be vulnerable"
            ]

            is_vulnerable = False
            for marker in success_markers:
                if marker.lower() in output.lower():
                    is_vulnerable = True
                    break

            if is_vulnerable:
                # Extragem bucăți relevante pentru raport
                # Căutăm liniile care conțin "Type:" sau "Title:" sau baza de date
                details = ""
                for line in output.split('\n'):
                    if "Type:" in line or "Title:" in line or "[*]" in line:
                        if len(details) < 1000: # Limita de text
                            details += line + "\n"

                vuln = VulnerabilityResult(
                    name="SQL Injection Detected",
                    description=f"SQLMap found injection points!\n\nExtract:\n{details}",
                    severity=Severity.CRITICAL,
                    tool_used="sqlmap",
                    remediation="Use prepared statements and input validation."
                )
                results.append(vuln)
                self.log("SQL Injection FOUND!", level="success")
            else:
                # Dacă nu găsim nimic, afișăm în consolă de ce (pentru debug)
                self.log("Scan finished. No common vulnerabilities found in output.", level="info")
                print(output[:500]) 

        except Exception as e:
            self.log(f"Error running sqlmap: {e}", level="error")

        return results