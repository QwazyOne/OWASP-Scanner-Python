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