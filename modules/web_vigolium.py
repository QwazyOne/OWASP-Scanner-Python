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
    "suspect": Severity.INFO,   # semnal slab, sub 'low' in scara Vigolium
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
}

# Confirmat din `vigolium scan --help`: headerele custom se dau cu -H / --header
# (ex: -H "Authorization: Bearer token"). Cookie-ul il trimitem ca header Cookie.
HEADER_FLAG = "-H"


class VigoliumScanner(BaseScannerModule):
    """
    Integrare cu Vigolium (https://github.com/vigolium/vigolium) - scanner
    de vulnerabilitati web in Go, mod determinist "Native Scan".

    Ruleaza:  vigolium scan -t <url> --strategy <s> --stateless --format jsonl
              -o <file> --export-only findings --omit-response --silent
    si parseaza envelope-ul JSONL ({type, data}) in VulnerabilityResult.
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
            # --scanning-max-duration opreste scanarea gratios inainte de
            # kill-ul dur al subprocesului (lasam o marja de 30s)
            max_dur = max(timeout - 30, 60)
            command = [
                "vigolium", "scan",
                "-t", target.input,
                "--strategy", strategy,
                "--stateless",                 # DB temporar, nu polueaza baza reala
                "--format", "jsonl",
                "-o", out_path,
                "--export-only", "findings",   # envelope-ul contine DOAR findings
                "--omit-response",             # fisier mai mic (fara body-urile HTTP)
                "--scanning-max-duration", f"{max_dur}s",
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
        """Parseaza fisierul JSONL Vigolium in rezultate.

        Vigolium scrie un envelope de forma {"type": "...", "data": {...}} pe
        fiecare linie. Ne intereseaza doar inregistrarile de tip finding.
        Tratam si cazul (mai putin probabil) al unui finding plat, ca fallback.
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
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue

                # Envelope {type, data}: pastram doar findings
                if "data" in obj and "type" in obj:
                    if "finding" not in str(obj.get("type", "")).lower():
                        continue
                    d = obj["data"] if isinstance(obj["data"], dict) else {}
                else:
                    d = obj  # fallback: finding plat

                if not d:
                    continue

                # Ignoram liniile care nu sunt findings (fara severitate si fara nume)
                sev_raw = str(d.get("severity", "")).lower()
                # Nume prietenos: module_name e cel mai descriptiv in Vigolium
                name = (d.get("module_name") or d.get("module_id")
                        or d.get("title") or d.get("name") or d.get("module"))
                if not name and not sev_raw:
                    continue

                severity = SEVERITY_MAP.get(sev_raw, Severity.INFO)

                # URL: 'url' e string; 'matched_at' e o LISTA de URL-uri
                url = d.get("url") or ""
                if not url:
                    ma = d.get("matched_at")
                    if isinstance(ma, list) and ma:
                        url = str(ma[0])
                    elif isinstance(ma, str):
                        url = ma
                url = url or d.get("hostname") or ""

                param = d.get("parameter") or d.get("param") or ""

                # Evidenta: 'extracted_results' e o lista in Vigolium
                ev = d.get("extracted_results") or d.get("evidence") or d.get("extracted") or ""
                if isinstance(ev, list):
                    ev = ", ".join(str(x) for x in ev)

                desc = d.get("description") or ""
                confidence = d.get("confidence") or ""
                cvss = d.get("cvss_score")

                parts = []
                if url:
                    parts.append(f"URL: {url}")
                if param:
                    parts.append(f"Parametru: {param}")
                if confidence:
                    parts.append(f"Incredere: {confidence}")
                if cvss:
                    parts.append(f"CVSS: {cvss}")
                if desc:
                    parts.append(desc)
                if ev:
                    parts.append(f"Evidenta: {ev}")
                description = "\n".join(parts) or json.dumps(d)[:800]

                out.append(VulnerabilityResult(
                    name=f"Vigolium: {name or 'finding'}",
                    description=description,
                    severity=severity,
                    tool_used="vigolium",
                ))
        return out
