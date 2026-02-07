from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Optional
import datetime

app = FastAPI(title="OWASP C2 Server")

# -- BAZA DE DATE (MEMORIE) --
# Aici ținem minte agenții conectați
active_agents: Dict[str, dict] = {}

# -- MODELE DE DATE --
class AgentRegistration(BaseModel):
    hostname: str
    os: str
    ip: str
    status: str = "online"

class Command(BaseModel):
    cmd: str

# -- ENDPOINTS (COMENZI) --

@app.get("/")
def read_root():
    return {"status": "C2 Server Running", "agents_online": len(active_agents)}

# 1. Heartbeat: Agentul ne spune "Sunt viu!"
@app.post("/agent/heartbeat")
def heartbeat(agent: AgentRegistration):
    agent_id = agent.hostname
    
    # Salvăm/Actualizăm agentul
    active_agents[agent_id] = {
        "os": agent.os,
        "ip": agent.ip,
        "last_seen": datetime.datetime.now().strftime("%H:%M:%S"),
        "status": "online"
    }
    return {"message": "Heartbeat received", "server_time": datetime.datetime.now()}

# 2. Listare Agenți: Pentru Dashboard
@app.get("/agents/list")
def list_agents():
    return active_agents

# 3. Trimitere Comandă (Placeholder pentru viitor)
@app.post("/agent/{hostname}/command")
def send_command(hostname: str, command: Command):
    if hostname not in active_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    # Aici vom implementa coada de comenzi mai târziu
    return {"status": "queued", "target": hostname, "cmd": command.cmd}