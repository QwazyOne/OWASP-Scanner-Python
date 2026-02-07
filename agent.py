import time
import socket
import platform
import requests
import os

# --- CONFIGURARE ---
# Aici pui IP-ul serverului KALI (ex: 192.168.1.X sau IP-ul Tailscale)
# Pentru test local pe Kali, lăsăm localhost
SERVER_URL = "http://127.0.0.1:8000" 

def get_system_info():
    """Detectează automat sistemul de operare"""
    hostname = socket.gethostname()
    os_type = f"{platform.system()} {platform.release()}"
    
    # Încercăm să aflăm IP-ul local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except:
        ip_address = "127.0.0.1"
        
    return hostname, os_type, ip_address

def run_agent():
    print(f"[*] Agent started on {platform.system()}...")
    print(f"[*] Connecting to C2 Server at {SERVER_URL}")

    hostname, os_type, ip = get_system_info()

    while True:
        try:
            # 1. Pregătim datele
            data = {
                "hostname": hostname,
                "os": os_type,
                "ip": ip,
                "status": "online"
            }

            # 2. Trimitem Heartbeat (Bătaia inimii)
            response = requests.post(f"{SERVER_URL}/agent/heartbeat", json=data)
            
            if response.status_code == 200:
                print(f"[+] Heartbeat sent. Server time: {response.json().get('server_time')}")
            else:
                print(f"[!] Server Error: {response.status_code}")

        except requests.exceptions.ConnectionError:
            print("[x] Could not connect to server. Retrying in 5s...")
        except Exception as e:
            print(f"[!] Error: {e}")

        # 3. Pauză (Ca să nu floodam rețeaua)
        time.sleep(5)

if __name__ == "__main__":
    run_agent()