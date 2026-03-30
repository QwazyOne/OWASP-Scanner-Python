import streamlit as st
import pandas as pd
import os
import time
import socket
from core.models import Target, TargetType
from core.database import DatabaseManager
from core.report_generator import generate_pdf_bytes

# --- IMPORTURI MODULE ---
from modules.recon_nmap import NmapScanner
from modules.web_sql import SQLMapScanner
from modules.web_nikto import NiktoScanner
from modules.msf_scanner import MetasploitScanner

# --- INITIALIZARE ---
db = DatabaseManager()

if 'msf_paths' not in st.session_state: st.session_state['msf_paths'] = []
if 'last_results' not in st.session_state: st.session_state['last_results'] = []
if 'search_performed' not in st.session_state: st.session_state['search_performed'] = False

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def start_msfrpcd(password="superparola123"):
    try:
        # Folosim 'nohup' si '&' pentru a detasa complet procesul de mediul virtual Python
        comanda = f"nohup msfrpcd -P {password} -a 127.0.0.1 > /dev/null 2>&1 &"
        os.system(comanda)
        return True
    except Exception as e:
        print(f"[!] Eroare MSF RPC: {e}")
        return False

@st.cache_data(show_spinner=False)
def fetch_msf_modules():
    scanner_msf = MetasploitScanner()
    if scanner_msf.check_prerequisites():
        return scanner_msf.get_scanner_modules()
    return ["scanner/http/title"]

def get_severity_str(obj):
    if "metasploit" in str(obj.tool_used).lower(): return "HIGH"
    if hasattr(obj.severity, 'name'): return str(obj.severity.name).upper()
    return str(obj.severity).upper()

def is_valid_vuln(obj):
    tool = str(obj.tool_used).lower()
    desc = str(obj.description).lower()
    
    # 1. Ignorăm erorile comune de conexiune sau mesaje de sistem
    noise_keywords = [
        "unable to connect", "could not connect", "failed to load", 
        "out of date", "usage:", "metasploit v6", "connection refused",
        "0 host(s) tested", "runtimeerror"
    ]
    if any(noise in desc for noise in noise_keywords):
        return False

    # 2. Reguli specifice pentru rezultate POZITIVE
    if "metasploit" in tool:
        # Metasploit confirmă rezultatele cu [+]
        return "[+]" in desc
        
    if "nikto" in tool:
        # Nikto marchează descoperirile cu + (fără paranteze)
        return "+" in desc and "target" not in desc.lower()

    if "sqlmap" in tool:
        # SQLMap este de obicei valid dacă ajunge în listă, dar filtrăm mesajele INFO
        if hasattr(obj.severity, 'name'):
            return obj.severity.name != "INFO"
        return "vulnerable" in desc or "injection" in desc

    return False

# --- CONFIG PAGINA ---
st.set_page_config(page_title="Professional VMS", layout="wide")
st.title("🛡️ Advanced Vulnerability Management Framework")

with st.sidebar:
    st.header("⚙️ System Status")
    msf_running = is_port_in_use(55553)
    if msf_running: st.success("🟢 Metasploit RPC: ONLINE")
    else:
        st.error("🔴 Metasploit RPC: OFFLINE")
        if st.button("🔌 Start MSF"):
            start_msfrpcd(); time.sleep(15); st.rerun()

    st.markdown("---")
    st.header("🛑 Emergency Controls")
    if st.button("💀 KILL ALL SCANNERS", type="primary", use_container_width=True):
        os.system("pkill -9 nmap"); os.system("pkill -9 sqlmap"); os.system("pkill -9 nikto")
        os.system("pkill -f msfrpcd"); os.system("pkill -f ruby")
        st.session_state['last_results'] = []
        st.toast("Procese oprite!", icon="🛑")
        time.sleep(1); st.rerun()

tab_recon, tab_attack = st.tabs(["🌐 1. Recon & Assets (Nmap)", "🎯 2. Attack Pipeline (Moștenit)"])

# ==========================================
# TAB 1: RECON & ASSETS
# ==========================================
with tab_recon:
    st.header("🔍 Asset Discovery")
    col_in, col_go = st.columns([3, 1])
    with col_in: target_input = st.text_input("Target IP/Domain", placeholder="ex: testphp.vulnweb.com")
    with col_go:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Start Nmap Recon", use_container_width=True):
            with st.spinner("Cartografiem rețeaua cu Nmap..."):
                scanner = NmapScanner()
                scanner.run(Target(input=target_input, type=list(TargetType)[0]))
                st.rerun()

    st.markdown("---")
    targets = db.get_all_targets()
    for t in targets:
        with st.expander(f"📌 {t['host']} (Last Scanned: {t['last_scanned']})"):
            c_info, c_actions = st.columns([4, 1])
            with c_info:
                p = db.get_ports_for_target(t['id'])
                if p: st.dataframe(pd.DataFrame(p), use_container_width=True, hide_index=True)
                v = db.get_vulnerabilities_for_target(t['id'])
                if v: 
                    st.markdown("**🚨 Vulnerabilități Salvate:**")
                    st.dataframe(pd.DataFrame(v), use_container_width=True, hide_index=True)
            with c_actions:
                pdf = generate_pdf_bytes(db, t['id'])
                if pdf: st.download_button("📄 PDF Report", data=pdf, file_name=f"Report_{t['host']}.pdf", mime="application/pdf", use_container_width=True, key=f"pdf_{t['id']}")
                if st.button("🗑️ Delete", key=f"del_{t['id']}", use_container_width=True):
                    db.delete_target(t['id']); st.rerun()

# ==========================================
# TAB 2: SMART ATTACK PIPELINE
# ==========================================
with tab_attack:
    if not targets:
        st.warning("Adaugă o țintă în Tab 1 mai întâi!")
    else:
        target_map = {t['id']: t['host'] for t in targets}
        sel_id = st.selectbox("🎯 Selectează Ținta pentru Atac:", options=list(target_map.keys()), format_func=lambda x: target_map[x])
        sel_host = target_map[sel_id]

        # ---------------------------------------------------------
        # INTELIGENȚA CONTEXTUALĂ: Analizăm istoricul Nmap
        # ---------------------------------------------------------
        target_ports = db.get_ports_for_target(sel_id)
        
        # Căutăm porturi web (80, 443, 8080, etc) sau servicii care conțin 'http'
        web_ports = [p['port'] for p in target_ports if p['port'] in [80, 443, 8000, 8080, 8443] or 'http' in str(p.get('service_name') or p.get('service') or '').lower()]
        st.markdown("### 🧬 Flux de Atac Moștenit (Pipeline)")
        
        # Stabilim URL-ul de bază
        base_url = ""
        if web_ports:
            st.success(f"🌐 S-au detectat servicii WEB pe porturile: **{web_ports}**. Fluxul web a fost activat!")
            port_to_use = web_ports[0]
            protocol = "https" if port_to_use in [443, 8443] else "http"
            
            if port_to_use in [80, 443]: base_url = f"{protocol}://{sel_host}"
            else: base_url = f"{protocol}://{sel_host}:{port_to_use}"
        else:
            st.warning("⚠️ Nmap nu a detectat porturi web standard. Poți introduce link-ul manual pentru a forța atacul web.")
            base_url = st.text_input("URL Web Manual:", value=f"http://{sel_host}")

        # ---------------------------------------------------------
        # CONFIGURAREA FLUXULUI (WIZARD)
        # ---------------------------------------------------------
        with st.form("pipeline_form"):
            st.markdown("#### Pasul 1: Aplicații Web (Nikto & SQLMap)")
            
            col_w1, col_w2 = st.columns(2)
            with col_w1:
                run_nikto = st.checkbox("Rulare Nikto (Vulnerabilități Web & Configurații)", value=bool(web_ports))
                st.caption(f"Ținta pentru Nikto: `{base_url}`")
                
            with col_w2:
                run_sqlmap = st.checkbox("Rulare SQLMap (Injecții Baze de Date)", value=False)
                sql_path = st.text_input("Cale vulnerabilă pentru SQLMap (Obligatoriu dacă e bifat)", placeholder="/pagina.php?id=1")
                if run_sqlmap and not sql_path:
                    st.error("❗ Ai bifat SQLMap, dar nu ai oferit o cale (ex: /index.php?id=1).")

            st.markdown("#### Pasul 2: Exploatare de Sistem (Metasploit)")
            run_msf = st.checkbox("Rulare Metasploit Auxiliary", value=False)
            msf_mods = st.multiselect("Selectează modulele MSF:", options=fetch_msf_modules() if msf_running else [], help="Selectează modulele bazat pe porturile găsite de Nmap.")
            if run_msf and not msf_running:
                st.error("Metasploit este offline! Pornește-l din stânga.")

            st.markdown("<br>", unsafe_allow_html=True)
            submit_pipeline = st.form_submit_button("🔥 LANSEAZĂ PIPELINE-UL", type="primary", use_container_width=True)

        # ---------------------------------------------------------
        # EXECUȚIA ÎN CASCADĂ (INHERITED EXECUTION)
        # ---------------------------------------------------------
        if submit_pipeline:
            pipeline_results = []
            
            # 1. NIKTO (Analiza generală web)
            if run_nikto:
                with st.spinner(f"🌐 [1/3] Nikto scanează {base_url}..."):
                    nikto_scanner = NiktoScanner()
                    res_nikto = nikto_scanner.run(Target(input=base_url, type=list(TargetType)[0]))
                    pipeline_results.extend(res_nikto)
            
            # 2. SQLMAP (Analiza bazelor de date)
            if run_sqlmap and sql_path:
                full_sql_url = f"{base_url}{sql_path}"
                with st.spinner(f"💉 [2/3] SQLMap atacă {full_sql_url}..."):
                    sql_scanner = SQLMapScanner()
                    res_sql = sql_scanner.run(Target(input=full_sql_url, type=list(TargetType)[0]))
                    pipeline_results.extend(res_sql)

            # 3. METASPLOIT (Exploatare finală / servicii de sistem)
            if run_msf and msf_running and msf_mods:
                with st.spinner("🦇 [3/3] Metasploit execută modulele..."):
                    msf = MetasploitScanner()
                    for m in msf_mods:
                        m_t, m_n = m.split('/', 1)
                        res_msf = msf.run(Target(input=sel_host, type=list(TargetType)[0]), m_t, m_n)
                        pipeline_results.extend(res_msf)

            # Salvare automată în baza de date
            salvate = 0
            for r in pipeline_results:
                if is_valid_vuln(r):
                    db.add_vulnerability(sel_id, str(r.tool_used), r.name, get_severity_str(r), r.description)
                    salvate += 1
            
            # Actualizare UI Fix
            st.session_state['last_results'] = [{"Tool": r.tool_used, "Nume": r.name, "Descriere": r.description, "Severitate": get_severity_str(r)} for r in pipeline_results]
            
            if salvate > 0: st.toast(f"Pipeline finalizat! Am salvat {salvate} vulnerabilități.", icon="✅")
            st.rerun()

        # ---------------------------------------------------------
        # AFIȘAREA REZULTATELOR PIPELINE-ULUI
        # ---------------------------------------------------------
        if st.session_state['last_results']:
            st.markdown("---")
            st.header("📋 Rezultatele Pipeline-ului")
            if st.button("🧹 Curăță Rezultatele"):
                st.session_state['last_results'] = []; st.rerun()

            df_res = pd.DataFrame(st.session_state['last_results'])
            st.dataframe(df_res[["Tool", "Nume", "Severitate"]], use_container_width=True)

            for item in st.session_state['last_results']:
                with st.expander(f"👁️ Detalii Tehnice: {item['Nume']} ({item['Tool'].upper()})"):
                    st.code(item['Descriere'], language="text")