import streamlit as st
import pandas as pd
import os
import subprocess
import socket
import time
from core.models import Target, TargetType
from core.database import DatabaseManager
from core.report_generator import generate_pdf_bytes

# --- IMPORTURI MODULE ---
from modules.recon_nmap import NmapScanner
from modules.web_sql import SQLMapScanner
from modules.msf_scanner import MetasploitScanner

db = DatabaseManager()

# --- HELPER FUNCTIONS ---
@st.cache_data(show_spinner=False)
def fetch_msf_modules():
    scanner_msf = MetasploitScanner()
    if scanner_msf.check_prerequisites():
        return scanner_msf.get_scanner_modules()
    return ["scanner/http/title"]

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def start_msfrpcd(password="superparola123"):
    try:
        subprocess.Popen(["msfrpcd", "-P", password, "-n", "-a", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError: return False

def is_real_vulnerability(result_obj) -> bool:
    try:
        text_desc = str(result_obj.description).lower()
        tool = str(result_obj.tool_used).lower()
        if hasattr(result_obj.severity, 'value'): sev = str(result_obj.severity.value).upper()
        elif hasattr(result_obj.severity, 'name'): sev = str(result_obj.severity.name).upper()
        else: sev = str(result_obj.severity).upper()
        if "sqlmap" in tool and sev != "INFO": return True
        if "metasploit" in tool and "[+]" in str(result_obj.description): return True
    except: pass
    return False

def get_severity_string(result_obj) -> str:
    if "metasploit" in str(result_obj.tool_used).lower(): return "HIGH"
    if hasattr(result_obj.severity, 'name'): return str(result_obj.severity.name).upper()
    return str(result_obj.severity).upper()

# --- UI CONFIG ---
st.set_page_config(page_title="VMS Framework", page_icon="🛡️", layout="wide")
st.title("🛡️ Advanced Vulnerability Management Framework")

# Initialize session states for UI persistence
if 'msf_paths' not in st.session_state: st.session_state['msf_paths'] = []
if 'last_attack_res' not in st.session_state: st.session_state['last_attack_res'] = None

with st.sidebar:
    st.header("⚙️ System Status")
    msf_running = is_port_in_use(55553)
    if msf_running: st.success("🟢 Metasploit RPC: ONLINE")
    else:
        st.error("🔴 Metasploit RPC: OFFLINE")
        if st.button("🔌 Start MSF"):
            start_msfrpcd(); time.sleep(15); st.rerun()

tab_recon, tab_attack = st.tabs(["🌐 Assets & History", "🎯 Targeted Attack"])

# ------------------------------------------
# TAB 1: ASSETS & RECON
# ------------------------------------------
with tab_recon:
    st.header("🔍 Asset Discovery")
    col_in, col_go = st.columns([3, 1])
    with col_in: target_input = st.text_input("New Target (IP/Domain)", placeholder="example.com")
    with col_go:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Run Nmap Scan", use_container_width=True):
            scanner = NmapScanner(); t_obj = Target(input=target_input, type=list(TargetType)[0])
            scanner.run(t_obj); st.rerun()

    st.markdown("---")
    targets = db.get_all_targets()
    for t in targets:
        with st.expander(f"📌 {t['host']} - Last Scanned: {t['last_scanned']}"):
            c_info, c_btn = st.columns([4, 1])
            with c_info:
                ports = db.get_ports_for_target(t['id'])
                if ports: st.dataframe(pd.DataFrame(ports), use_container_width=True, hide_index=True)
                v_list = db.get_vulnerabilities_for_target(t['id'])
                if v_list: 
                    st.markdown("**🚨 Vulnerabilities Saved:**")
                    st.dataframe(pd.DataFrame(v_list), use_container_width=True, hide_index=True)
            with c_btn:
                pdf_data = generate_pdf_bytes(db, t['id'])
                if pdf_data: st.download_button("📄 Download PDF", data=pdf_data, file_name=f"Report_{t['host']}.pdf", mime="application/pdf", use_container_width=True, key=f"p_{t['id']}")
                if st.button("🗑️ Delete", key=f"d_{t['id']}", use_container_width=True): db.delete_target(t['id']); st.rerun()

# ------------------------------------------
# TAB 2: TARGETED ATTACK
# ------------------------------------------
with tab_attack:
    if not targets: st.warning("Scan a target first!")
    else:
        target_map = {t['id']: t['host'] for t in targets}
        sel_id = st.selectbox("Select Target:", options=list(target_map.keys()), format_func=lambda x: target_map[x])
        selected_host = target_map[sel_id]
        
        # --- SECTION: MSF QUICK FIRE ---
        st.subheader("⚡ Quick Fire (Metasploit)")
        with st.container(border=True):
            col_search, col_sbtn = st.columns([4, 1])
            with col_search:
                search_q = st.text_input("Search (e.g., http_version)", key="search_input")
            with col_sbtn:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔎 Search MSF", use_container_width=True):
                    msf = MetasploitScanner(); res_text = msf.search_modules(search_q)
                    st.session_state['msf_paths'] = msf.extract_module_paths(res_text)
                    st.info(f"Found {len(st.session_state['msf_paths'])} modules.")

            if st.session_state['msf_paths']:
                col_m, col_lh, col_tid = st.columns([2, 1, 1])
                with col_m: sel_mod = st.selectbox("Choose Module:", options=st.session_state['msf_paths'])
                with col_lh: l_host = st.text_input("LHOST (Your IP)", placeholder="192.168.x.x")
                with col_tid: t_id = st.text_input("Target ID", value="0")
                
                if st.button("🔥 LAUNCH QUICK FIRE", type="primary", use_container_width=True):
                    with st.spinner("Executing..."):
                        msf = MetasploitScanner(); m_t, m_n = sel_mod.split('/', 1)
                        res = msf.run(Target(input=selected_host, type=list(TargetType)[0]), module_type=m_t, module_name=m_n, lhost=l_host, target_id=t_id)
                        for r in res:
                            if is_real_vulnerability(r):
                                db.add_vulnerability(sel_id, "metasploit", r.name, "HIGH", r.description)
                        # CRITICAL FIX: Save results to state and refresh
                        st.session_state['last_attack_res'] = [{"Severitate": get_severity_string(r), "Tip": r.name, "Descriere": r.description, "Tool": r.tool_used} for r in res]
                        st.rerun()

        st.markdown("---")
        # --- SECTION: BATCH ATTACK ---
        st.subheader("🚀 Batch Attack")
        col_sq, col_ms = st.columns(2)
        with col_sq:
            with st.expander("💉 SQLMap Settings"):
                sql_path = st.text_input("URL Path (/art.php?id=1)", key="sq_p_batch")
                intensity = st.slider("Intensity", 1, 5, 1)
        with col_ms:
            with st.expander("🦇 Metasploit Scanners"):
                msf_mods = st.multiselect("Select Auxiliary Modules:", options=fetch_msf_modules())

        if st.button("🚀 RUN BATCH ATTACK", use_container_width=True):
            all_res = []
            if sql_path:
                with st.spinner("Running SQLMap..."):
                    scanner_sql = SQLMapScanner()
                    all_res.extend(scanner_sql.run(Target(input=f"http://{selected_host}{sql_path}", type=list(TargetType)[0]), level=intensity))
            if msf_mods:
                msf = MetasploitScanner()
                for m in msf_mods:
                    with st.spinner(f"Running {m}..."):
                        m_t, m_n = m.split('/', 1)
                        all_res.extend(msf.run(Target(input=selected_host, type=list(TargetType)[0]), module_type=m_t, module_name=m_n))
            
            for r in all_res:
                if is_real_vulnerability(r):
                    db.add_vulnerability(sel_id, str(r.tool_used), r.name, get_severity_string(r), r.description)
            
            st.session_state['last_attack_res'] = [{"Severitate": get_severity_string(r), "Tip": r.name, "Descriere": r.description, "Tool": r.tool_used} for r in all_res]
            st.rerun()

        # --- UNIFIED RESULTS DISPLAY ---
        if st.session_state['last_attack_res']:
            st.markdown("### 📝 Recent Attack Output")
            if st.button("🧹 Clear Results"):
                st.session_state['last_attack_res'] = None; st.rerun()
            
            # We use a dataframe but with custom styling to see the description clearly
            df = pd.DataFrame(st.session_state['last_attack_res'])
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Show a detailed view for the terminal extract (Description)
            st.info("💡 Sfat: Extinde tabelul de mai sus sau citește detaliile brute aici:")
            for item in st.session_state['last_attack_res']:
                with st.expander(f"Detalii {item['Tip']} ({item['Tool']})"):
                    st.code(item['Descriere'], language="text")