import streamlit as st
import pandas as pd
import os
import requests
from core.models import Target, TargetType
from modules.recon_nmap import NmapScanner
from modules.web_sql import SQLMapScanner
# 1. Configurare Pagină
st.set_page_config(
    page_title="OWASP Scanner Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS Custom pentru a face interfața mai compactă pe iPad ---
st.markdown("""
    <style>
        .block-container {padding-top: 1rem; padding-bottom: 0rem;}
        h1 {margin-top: -3rem;}
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ OWASP & Multi-Vector Scanner")

# ==========================================
# SIDEBAR: SETĂRI GLOBALE & CONTROL
# ==========================================
with st.sidebar:
    st.header("🎯 Țintă & Vector")
    
    # Input Global
    target_input = st.text_input("Adresă IP / URL", value="scanme.nmap.org", help="Ex: 192.168.1.1 sau example.com")
    
    # Selectare Vector (Profil)
    scan_type = st.selectbox(
        "Vector de Atac",
        options=[t.value for t in TargetType],
        index=0,
        help="Selectează tipul de infrastructură pe care o ataci."
    )
    
    st.markdown("---")
    st.header("🛑 Emergency")
    
    # Kill Switch
    if st.button("💀 KILL ALL PROCESSES", type="primary", use_container_width=True):
        os.system("pkill -9 nmap")
        os.system("pkill -9 sqlmap")
        # Aici vom adăuga și alte tools pe viitor (ex: pkill sqlmap)
        st.toast("Toate procesele au fost terminate forțat!", icon="🛑")

# ==========================================
# ZONA PRINCIPALĂ: TAB-URI
# ==========================================

# Creăm tab-urile
tab_config, tab_results, tab_agents = st.tabs(["🛠️ Configurare", "📊 Rezultate", "🖥️ Agenți (C2)"])

# --- TAB 1: CONFIGURARE ---
with tab_config:
    st.info(f"Configurare activă pentru vectorul: **{scan_type.upper()}**")
    
  # --- NMAP CONFIG ---
    with st.expander("🌐 1. Nmap (Port Scanning)", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            nmap_enabled = st.checkbox("Activează Nmap", value=True)
        if nmap_enabled:
            mode_label = st.selectbox("Profil Nmap", ["Rapid", "Normal", "Deep"], index=0)
            use_scripts = st.checkbox("Scripturi Vuln", value=False)
            
            nmap_mode_map = {"Rapid": "fast", "Normal": "default", "Deep": "deep"}
            selected_nmap_mode = nmap_mode_map[mode_label]

    # --- SQLMAP CONFIG (NOU) ---
    with st.expander("💉 2. SQLMap (Web Injection)", expanded=False):
        col_sql_1, col_sql_2 = st.columns(2)
        with col_sql_1:
            sqlmap_enabled = st.checkbox("Activează SQLMap", value=False, help="Doar pentru URL-uri web!")
        
        if sqlmap_enabled:
            st.warning("⚠️ SQLMap poate dura mult și este agresiv!")
            risk_level = st.slider("Risk Level (1-3)", 1, 3, 1)
            intensity_level = st.slider("Intensity Level (1-5)", 1, 5, 1)

    st.markdown("---")
    start_scan = st.button("🚀 LANSEAZĂ SCANAREA COMPLETĂ", type="primary", use_container_width=True)
        

        
    # --- TAB-UL NOU: AGENTS ---
    with tab_agents:
        st.header("📡 Command & Control Center")
        
        if st.button("🔄 Refresh Agents List"):
            try:
                # Cerem lista de la API-ul nostru local
                response = requests.get("http://127.0.0.1:8000/agents/list")
                if response.status_code == 200:
                    agents = response.json()
                    
                    if agents:
                        st.success(f"Connectat: {len(agents)} agenți online.")
                        
                        # Creăm un tabel frumos
                        agent_data = []
                        for name, details in agents.items():
                            agent_data.append({
                                "Hostname": name,
                                "OS": details['os'],
                                "IP": details['ip'],
                                "Last Seen": details['last_seen'],
                                "Status": "🟢 ONLINE"
                            })
                        st.table(agent_data)
                    else:
                        st.warning("Niciun agent conectat. Rulează 'python agent.py' pe țintă.")
                else:
                    st.error("Eroare la comunicarea cu serverul C2.")
            except Exception as e:
                st.error(f"Serverul API nu răspunde! Rulează 'uvicorn server_api:app ...'. Eroare: {e}")

# --- LOGICA DE SCANARE ---
if start_scan:
    if not target_input:
        st.toast("Introdu o țintă!", icon="❌")
    else:
        with tab_results:
            results_container = st.container()
            status_text = st.empty()
            all_results = []
            
            current_target = Target(input=target_input, type=scan_type)

            # 1. Rulăm NMAP (Dacă e bifat)
            if nmap_enabled:
                with st.spinner("⏳ Rulat Nmap..."):
                    scanner_nmap = NmapScanner()
                    if scanner_nmap.check_prerequisites():
                        res = scanner_nmap.run(current_target, mode=selected_nmap_mode, use_scripts=use_scripts)
                        all_results.extend(res)
                        st.toast(f"Nmap terminat: {len(res)} rezultate")

            # 2. Rulăm SQLMAP (Dacă e bifat)
            if sqlmap_enabled:
                with st.spinner("⏳ Rulat SQLMap (Poate dura câteva minute)..."):
                    scanner_sql = SQLMapScanner()
                    if scanner_sql.check_prerequisites():
                        # SQLMap are nevoie de URL cu http
                        if not target_input.startswith("http"):
                            st.error("SQLMap necesită un URL complet (http://...)")
                        else:
                            res = scanner_sql.run(current_target, level=intensity_level, risk=risk_level)
                            all_results.extend(res)
                            st.toast(f"SQLMap terminat: {len(res)} rezultate")
                    else:
                        st.error("SQLMap nu este instalat!")

            # 3. AFIȘARE FINALĂ
            if all_results:
                status_text.success(f"Scanare Gata! Total probleme: {len(all_results)}")
                
                # Procesare date pentru tabel
                data = []
                for r in all_results:
                    data.append({
                        "Severitate": r.severity.value,
                        "Tip": r.name,
                        "Descriere": r.description,
                        "Tool": r.tool_used
                    })
                
                df = pd.DataFrame(data)
                st.dataframe(
                    df, 
                    use_container_width=True,
                    column_config={
                        "Descriere": st.column_config.TextColumn("Detalii", width="large")
                    }
                )
            else:
                status_text.warning("Nu au fost găsite vulnerabilități sau tool-urile nu au returnat date.")