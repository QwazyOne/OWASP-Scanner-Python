import subprocess
import shutil
import os
import json
import tempfile
from typing import List, Optional

from modules.base import BaseScannerModule
from core.models import Target, VulnerabilityResult, Severity, AuthConfig, AuthType

# Maparea severitatii Vigolium (lowercase) -> enum-ul intern
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
}

# Flag pentru headere custom. Majoritatea scannerelor Go (stil nuclei) folosesc -H.
# DACA integrarea esueaza, verifica `vigolium scan --help` si corecteaza aici.
HEADER_FLAG = "-H"


class VigoliumScanner(BaseScannerModule):
    """
    Integrare cu Vigolium (https://github.com/vigolium/vigolium) - scanner
    de vulnerabilitati web in Go, mod determinist "Native Scan".

    Ruleaza:  vigolium scan -t <url> --strategy <s> --format jsonl -o <file> --silent
    si parseaza output-ul JSONL in VulnerabilityResult.
    """
    def __init__(self):
        super().__init__()
        self.name = "Vigolium Web Scanner"
        self.description = "Scaneaza aplicatii web cu Vigolium (Native Scan, JSONL)"
        self.required_tools = ["vigolium"]

    def check_prerequisites(self) -> bool:
        if shutil.which("vigolium") is not None:
            return True
        self.log("Vigolium nu este instalat! Ruleaza: curl -fsSL https://vigolium.com/install.sh | bash",
                 level="error")
        return False

    def run(self, target: Target, strategy: str = "balanced",
            auth: Optional[AuthConfig] = None, timeout: int = 600) -> List[VulnerabilityResult]:
        results: List[VulnerabilityResult] = []
        if not self.check_prerequisites():
            return results

        if not target.input.startswith(("http://", "https://")):
            self.log("Vigolium necesita un URL (http/https).", level="error")
            return results

        if strategy not in ("lite", "balanced", "deep"):
            strategy = "balanced"

        out_fd, out_path = tempfile.mkstemp(prefix="vigolium_", suffix=".jsonl")
        os.close(out_fd)

        try:
            command = [
                "vigolium", "scan",
                "-t", target.input,
                "--strategy", strategy,
                "--format", "jsonl",
                "-o", out_path,
                "--silent",
            ]

            # Autentificare: trimitem cookie-ul / headerele capturate ca headere HTTP.
            if auth and auth.is_active():
                if auth.auth_type in (AuthType.COOKIE, AuthType.FORM, AuthType.BROWSER) and auth.cookie:
                    command.extend([HEADER_FLAG, f"Cookie: {auth.cookie}"])
                elif auth.auth_type == AuthType.HEADER and auth.headers:
                    for line in auth.headers.splitlines():
                        if line.strip():
                            command.extend([HEADER_FLAG, line.strip()])
                elif auth.auth_type == AuthType.BASIC and auth.username:
                    import base64
                    token = base64.b64encode(
                        f"{auth.username}:{auth.password or ''}".encode()).decode()
                    command.extend([HEADER_FLAG, f"Authorization: Basic {token}"])

            self.log(f"Rulez Vigolium ({strategy}) pe {target.input}...", level="info")
            subprocess.run(command, capture_output=True, text=True, timeout=timeout)

            results = self._parse_jsonl(out_path)
            self.log(f"Vigolium a raportat {len(results)} constatari.", level="success")

        except subprocess.TimeoutExpired:
            self.log(f"Vigolium a depasit timpul alocat ({timeout}s).", level="error")
        except Exception as e:
            self.log(f"Eroare la executia Vigolium: {e}", level="error")
        finally:
            if os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except OSError:
                    pass

        return results

    def _parse_jsonl(self, path: str) -> List[VulnerabilityResult]:
        """Parseaza un fisier JSONL (un obiect JSON per linie) in rezultate.

        Schema Vigolium nu e documentata exhaustiv, deci citim campurile
        defensiv, cu mai multe denumiri posibile.
        """
        out: List[VulnerabilityResult] = []
        if not os.path.exists(path):
            return out

        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue

                # Ignoram liniile care sunt doar evenimente de progres, nu findings
                sev_raw = str(d.get("severity", "")).lower()
                name = d.get("title") or d.get("name") or d.get("module") or d.get("template-id")
                if not name and not sev_raw:
                    continue

                severity = SEVERITY_MAP.get(sev_raw, Severity.INFO)

                url = d.get("url") or d.get("matched_at") or d.get("host") or ""
                param = d.get("parameter") or d.get("param") or ""
                evidence = d.get("evidence") or d.get("extracted") or ""
                desc = d.get("description") or ""

                parts = []
                if url:
                    parts.append(f"URL: {url}")
                if param:
                    parts.append(f"Parametru: {param}")
                if desc:
                    parts.append(desc)
                if evidence:
                    parts.append(f"Evidenta: {evidence}")
                description = "\n".join(parts) or json.dumps(d)[:800]

                out.append(VulnerabilityResult(
                    name=f"Vigolium: {name or 'finding'}",
                    description=description,
                    severity=severity,
                    tool_used="vigolium",
                ))
        return out
