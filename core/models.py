from pydantic import BaseModel
from typing import List, Optional
from enum import Enum
from datetime import datetime

# Definim tipurile de ținte posibile
class TargetType(str, Enum):
    WEB = "web"
    DESKTOP = "desktop"
    NETWORK = "network"
    DIODE = "diode"

# Definim severitatea standardizată
class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# --- AICI ESTE CLASA CARE LIPSEA ---
class Target(BaseModel):
    input: str  
    type: TargetType
    output_dir: Optional[str] = "reports"
# -----------------------------------

# Configurare autentificare pentru scanarea aplicatiilor web protejate
class AuthType(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    BASIC = "basic"
    HEADER = "header"
    FORM = "form"

class AuthConfig(BaseModel):
    auth_type: AuthType = AuthType.NONE
    username: Optional[str] = None
    password: Optional[str] = None
    cookie: Optional[str] = None          # ex: "PHPSESSID=abc; token=xyz"
    headers: Optional[str] = None         # linii "Nume: valoare", una per rand
    login_url: Optional[str] = None       # pagina care primeste POST-ul de login
    login_data: Optional[str] = None      # ex: "user=admin&pass=1234"

    def is_active(self) -> bool:
        return self.auth_type != AuthType.NONE

# Asta este structura unică a unei vulnerabilități găsite
class VulnerabilityResult(BaseModel):
    name: str                   
    description: str            
    severity: Severity          
    tool_used: str              
    timestamp: datetime = datetime.now()
    remediation: Optional[str] = None 

    class Config:
        arbitrary_types_allowed = True