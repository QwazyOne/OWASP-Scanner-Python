import streamlit as st
import pandas as pd
import os
import subprocess
import socket
import time
from core.models import Target, TargetType

# --- IMPORTURI MODULE ---
from modules.recon_nmap import NmapScanner
from modules.web_sql import SQLMapScanner
from modules.msf_scanner import MetasploitScanner

# --- CACHE PENTRU METASPLOIT ---
@st.cache_data(show_spinner=False)
def fetch_msf_modules():
    """Memorează lista de module ca să nu blocheze interfața"""
    scanner_msf = MetasploitScanner()
    if scanner_msf.check_prerequisites():
        return scanner_msf.get_scanner_modules()
    return ["scanner/http/title"]

st.set_page_config(page_title="OWASP Scanner Pro", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def start_msfrpcd(password="superparola123"):
    try:
        subprocess.Popen(["msfrpcd", "-P", password, "-n", "-a", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

st.markdown("""<style>.block-container {padding-top: 1rem;}</style>""", unsafe_allow_html=True)
st.title("🛡️ OWASP & Multi-Vector Scanner")

# ==========================================
# SIDEBAR
# ==========================================
with st.sidebar:
    st.header("🎯 Țintă & Vector")
    target_input = st.text_input("Adresă (URL/IP)", value="http://testphp.vulnweb.com")
    scan_type = st.selectbox("Vector", options=[t.value for t in TargetType], index=0)
    
    st.markdown("---")
    st.header("⚙️ Servicii de Fundal")
    
    msf_running = is_port_in_use(55553)
    if msf_running:
        st.success("🟢 Metasploit RPC: ONLINE")
    else:
        st.error("🔴 Metasploit RPC: OFFLINE")
        if st.button("🔌 Pornește Metasploit (msfrpcd)", use_container_width=True):
            with st.spinner("Pornesc serverul MSF... (~10 secunde)"):
                if start_msfrpcd():
                    time.sleep(8)
                    st.rerun()
                else:
                    st.error("Eroare: Comanda 'msfrpcd' nu a fost găsită.")

    st.markdown("---")
    if st.button("💀 KILL ALL SCANNERS", type="primary", use_container_width=True):
        os.system("pkill -9 nmap")
        os.system("pkill -9 sqlmap")
        st.toast("Procesele oprite forțat!", icon="🛑")

# ==========================================
# MAIN TABS & CONFIG
# ==========================================
tab_config, tab_results = st.tabs(["🛠️ Configurare Tool-uri", "📊 Rezultate"])

with tab_config:
    st.info(f"Ținta curentă: **{target_input}**")

    # 1. NMAP
    with st.expander("🌐 1. Nmap (Port Scanning)", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            nmap_enabled = st.checkbox("Activează Nmap", value=True)
        if nmap_enabled:
            mode_label = st.selectbox("Profil Nmap", ["Rapid", "Normal", "Deep"], index=0)
            use_scripts = st.checkbox("Scripturi Vuln", value=False)
            selected_nmap_mode = {"Rapid": "fast", "Normal": "default", "Deep": "deep"}[mode_label]

    # 2. SQLMAP
    with st.expander("💉 2. SQLMap (Web Injection)", expanded=False):
        col_sql_1, col_sql_2 = st.columns(2)
        with col_sql_1:
            sqlmap_enabled = st.checkbox("Activează SQLMap", value=False)
        if sqlmap_enabled:
            risk_level = st.slider("Risk Level (1-3)", 1, 3, 1)
            intensity_level = st.slider("Intensity Level (1-5)", 1, 5, 1)

    # 3. METASPLOIT
    with st.expander("🦇 3. Metasploit (Auxiliary & Validation)", expanded=False):
        col_msf_1, col_msf_2 = st.columns(2)
        with col_msf_1:
            msf_enabled = st.checkbox("Activează Metasploit", value=False)
        
        msf_module_choice = None
        if msf_enabled:
            if not msf_running:
                st.warning("⚠️ Pornește Serverul Metasploit din stânga mai întâi!")
            else:
                dynamic_modules = fetch_msf_modules()
                msf_module_choice = st.selectbox(
                    f"Selectează Modulul (din {len(dynamic_modules)} disponibile)", 
                    options=dynamic_modules,
                    index=dynamic_modules.index("scanner/http/title") if "scanner/http/title" in dynamic_modules else 0
                )

    st.markdown("---")
    # --- AICI ERA PROBLEMA TA: Butonul lipsea sau era ascuns! ---
    start_scan = st.button("🚀 LANSEAZĂ SCANAREA COMPLETĂ", type="primary", use_container_width=True)


# ==========================================
# LOGICA DE SCANARE
# ==========================================
if start_scan:
    if not target_input:
        st.toast("Introdu o țintă!", icon="❌")
    else:
        with tab_results:
            status_text = st.empty()
            all_results = []
            current_target = Target(input=target_input, type=scan_type)

            if nmap_enabled:
                with st.spinner("⏳ Rulat Nmap..."):
                    scanner_nmap = NmapScanner()
                    res = scanner_nmap.run(current_target, mode=selected_nmap_mode, use_scripts=use_scripts)
                    all_results.extend(res)

            if sqlmap_enabled:
                with st.spinner("⏳ Rulat SQLMap..."):
                    scanner_sql = SQLMapScanner()
                    res = scanner_sql.run(current_target, level=intensity_level, risk=risk_level)
                    all_results.extend(res)

            if msf_enabled and msf_running and msf_module_choice:
                with st.spinner(f"⏳ Rulat Metasploit ({msf_module_choice})..."):
                    scanner_msf = MetasploitScanner()
                    res = scanner_msf.run(current_target, module_type="auxiliary", module_name=msf_module_choice)
                    all_results.extend(res)

            if all_results:
                status_text.success(f"Scanare Gata! Total evenimente: {len(all_results)}")
                data = [{"Severitate": r.severity.value, "Tip": r.name, "Descriere": r.description, "Tool": r.tool_used} for r in all_results]
                st.dataframe(pd.DataFrame(data), use_container_width=True, column_config={"Descriere": st.column_config.TextColumn("Detalii", width="large")})
            else:
                status_text.warning("Nu au fost găsite date.")