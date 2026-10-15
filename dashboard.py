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

# --- INITIALIZĂRI ---
db = DatabaseManager()

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
    except FileNotFoundError:
        return False

# ==========================================
# FUNCȚII DE FILTRARE ȘI SALVARE 
# ==========================================
def is_real_vulnerability(result_obj) -> bool:
    try:
        text_desc = str(result_obj.description).lower()
        tool = str(result_obj.tool_used).lower()
        
        if hasattr(result_obj.severity, 'value'):
            severity_str = str(result_obj.severity.value).upper()
        elif hasattr(result_obj.severity, 'name'):
            severity_str = str(result_obj.severity.name).upper()
        else:
            severity_str = str(result_obj.severity).upper()

        if "sqlmap" in tool:
            if severity_str != "INFO": return True
                
        if "metasploit" in tool:
            if "[+]" in str(result_obj.description) and "failed" not in text_desc and "error" not in text_desc:
                return True
    except Exception as e:
        print(f"Eroare la filtrare: {e}")
    return False

def get_severity_string(result_obj) -> str:
    tool = str(result_obj.tool_used).lower()
    if "metasploit" in tool: return "HIGH"
    if hasattr(result_obj.severity, 'name'): return str(result_obj.severity.name).upper()
    if hasattr(result_obj.severity, 'value'): return str(result_obj.severity.value).upper()
    return str(result_obj.severity).upper()

# ==========================================
# CONFIGURARE PAGINĂ
# ==========================================
st.set_page_config(page_title="OWASP Framework", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""<style>.block-container {padding-top: 1rem;}</style>""", unsafe_allow_html=True)

st.title("🛡️ Advanced Vulnerability Management Framework")

with st.sidebar:
    st.header("⚙️ System Status")
    msf_running = is_port_in_use(55553)
    if msf_running:
        st.success("🟢 Metasploit RPC: ONLINE")
    else:
        st.error("🔴 Metasploit RPC: OFFLINE")
        if st.button("🔌 Start MSF Daemon", use_container_width=True):
            with st.spinner("Booting MSF RPC... (~20s)"):
                if start_msfrpcd():
                    time.sleep(20)
                    st.rerun()
                else:
                    st.error("Error: 'msfrpcd' not found.")

    st.markdown("---")
    st.header("🛑 Emergency Controls")
    if st.button("💀 KILL ALL SCANNERS", type="primary", use_container_width=True):
        os.system("pkill -9 nmap")
        os.system("pkill -9 sqlmap")
        st.toast("Toate procesele de scanare au fost oprite!", icon="🛑")


tab_recon, tab_attack = st.tabs(["🌐 1. Reconnaissance & Assets", "🎯 2. Targeted Attack & Exploitation"])

# ------------------------------------------
# TAB 1: RECON & ASSETS
# ------------------------------------------
with tab_recon:
    st.header("🔍 Discovery (Adaugă o țintă nouă)")
    
    col_input, col_btn = st.columns([3, 1])
    with col_input:
        new_target_input = st.text_input("IP sau Domeniu (ex: testphp.vulnweb.com)", placeholder="192.168.1.1")
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        run_recon = st.button("🚀 Run Nmap Discovery", use_container_width=True)

    with st.expander("⚙️ Setări Nmap Avanaste"):
        mode_label = st.selectbox("Profil Scanare", ["Rapid (-F)", "Normal (-sV)", "Deep (-p- -sV)"], index=0)
        use_scripts = st.checkbox("Rulează scripturi de vulnerabilitate Nmap (--script vuln)")
        nmap_mode_map = {"Rapid (-F)": "fast", "Normal (-sV)": "default", "Deep (-p- -sV)": "deep"}

    if run_recon and new_target_input:
        with st.spinner(f"Scaning {new_target_input} with Nmap. Saving to database..."):
            scanner = NmapScanner()
            target_obj = Target(input=new_target_input, type=list(TargetType)[0]) 
            scanner.run(target_obj, mode=nmap_mode_map[mode_label], use_scripts=use_scripts)
            st.success("Scanare completă! Datele au fost salvate în Istoric.")
            time.sleep(1)
            st.rerun()

    st.markdown("---")
    st.header("🗄️ Asset Inventory (Istoric Ținte)")
    
    targets = db.get_all_targets()
    
    if not targets:
        st.info("Baza de date este goală. Rulează o scanare Nmap pentru a adăuga ținte.")
    else:
        for t in targets:
            with st.expander(f"📌 {t['host']} (Ultima scanare: {t['last_scanned']})"):
                col_info, col_actions = st.columns([4, 1])
                
                with col_info:
                    # Afișăm Porturile
                    ports = db.get_ports_for_target(t['id'])
                    if ports:
                        st.markdown("**Porturi Deschise:**")
                        st.dataframe(pd.DataFrame(ports), use_container_width=True, hide_index=True)
                    else:
                        st.warning("Niciun port deschis găsit.")
                        
                    # Afișăm Vulnerabilitățile Salvate
                    vulns = db.get_vulnerabilities_for_target(t['id'])
                    if vulns:
                        st.markdown("**🚨 Vulnerabilități Confirmate (Salvate):**")
                        df_vulns = pd.DataFrame(vulns)
                        st.dataframe(df_vulns, use_container_width=True, hide_index=True)
                
                with col_actions:
                    # BUTONUL MAGIC DE PDF
                    pdf_data = generate_pdf_bytes(db, t['id'])
                    if pdf_data:
                        st.download_button(
                            label="📄 Descarcă PDF",
                            data=pdf_data,
                            file_name=f"Audit_Raport_{t['host']}.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                            key=f"pdf_{t['id']}"
                        )
                        
                    st.markdown("<br>", unsafe_allow_html=True) # Spațiere
                    
                    # Butonul de ștergere
                    if st.button("🗑️ Șterge Proiect", key=f"del_{t['id']}", type="secondary", use_container_width=True):
                        db.delete_target(t['id'])
                        st.toast(f"Ținta {t['host']} a fost ștearsă!", icon="✅")
                        time.sleep(0.5)
                        st.rerun()
                
# ------------------------------------------
# TAB 2: TARGETED ATTACK
# ------------------------------------------
with tab_attack:
    st.header("🎯 Targeted Exploitation")
    
    if not targets:
        st.warning("Nu ai nicio țintă în baza de date. Mergi la tab-ul 'Reconnaissance' și scanează o țintă mai întâi.")
    else:
        target_options = {t['id']: t['host'] for t in targets}
        selected_target_id = st.selectbox("Alege Ținta pentru atac:", options=list(target_options.keys()), format_func=lambda x: target_options[x])
        selected_host = target_options[selected_target_id]
        
        known_ports = db.get_ports_for_target(selected_target_id)
        open_ports_str = ", ".join([str(p['port']) for p in known_ports]) if known_ports else "Niciun port cunoscut"
        st.info(f"**Intel:** Ținta `{selected_host}` are porturile deschise: **{open_ports_str}**")

        st.markdown("---")
        with st.expander("🔍 MSF Exploit Suggester (Caută & Lansează)", expanded=True):
            col_search, col_sbtn = st.columns([4, 1])
            with col_search:
                search_query = st.text_input("Cuvânt cheie", placeholder="ex: nginx", label_visibility="collapsed")
            with col_sbtn:
                do_search = st.button("🔎 Caută în MSF", use_container_width=True)
                
            if do_search and search_query:
                if not msf_running:
                    st.error("Metasploit este OFFLINE.")
                else:
                    with st.spinner(f"Caut în baza de date MSF după '{search_query}'..."):
                        msf_scanner = MetasploitScanner()
                        search_result = msf_scanner.search_modules(search_query)
                        st.code(search_result, language="text")
                        extrase = msf_scanner.extract_module_paths(search_result)
                        st.session_state['msf_search_results'] = extrase

            if 'msf_search_results' in st.session_state and st.session_state['msf_search_results']:
                lista_module = st.session_state['msf_search_results']
                st.success(f"✅ Am extras automat {len(lista_module)} module din rezultate!")
                
                col_mod, col_lhost, col_tid = st.columns([2, 1, 1])
                with col_mod: modul_ales = st.selectbox("Alege modulul:", options=lista_module)
                with col_lhost: user_lhost = st.text_input("LHOST (IP-ul tău)", placeholder="ex: 192.168.1.100")
                with col_tid: user_target = st.text_input("Target ID", placeholder="ex: 1")

                # ==========================================
                # EXECUTIE: QUICK FIRE
                # ==========================================
                quick_fire = st.button("⚡ Quick Fire (Lansează)", type="primary", use_container_width=True)
                
                if quick_fire:
                    parti = modul_ales.split('/', 1)
                    with st.spinner(f"Execut {modul_ales} pe {selected_host}..."):
                        msf_scanner = MetasploitScanner()
                        attack_target_obj = Target(input=selected_host, type=list(TargetType)[0])
                        res = msf_scanner.run(attack_target_obj, module_type=parti[0], module_name=parti[1], lhost=user_lhost, target_id=user_target)
                        
                        salvate_qf = 0
                        for r in res:
                            if is_real_vulnerability(r):
                                sev_val = get_severity_string(r)
                                db.add_vulnerability(selected_target_id, str(r.tool_used), str(r.name), sev_val, str(r.description))
                                salvate_qf += 1
                        
                        # Salvăm statusul în sesiune și dăm rerun
                        st.session_state['qf_msg'] = f"Salvat în DB: {salvate_qf} descoperiri MSF! 💾" if salvate_qf > 0 else None
                        st.session_state['qf_table'] = [{"Tip": r.name, "Descriere": r.description} for r in res] if res else None
                        st.rerun()

                # Afișare din memorie (persistență după rerun)
                if st.session_state.get('qf_msg'):
                    st.success(st.session_state['qf_msg'])
                if st.session_state.get('qf_table') is not None:
                    if st.session_state['qf_table']:
                        st.table(pd.DataFrame(st.session_state['qf_table']))
                    else:
                        st.warning("Modulul a rulat, dar nu a generat niciun rezultat util.")


        st.markdown("---")
        st.subheader("Configurare Atac (Scanare Multiplă)")
        
        with st.expander("💉 SQLMap (Web Injection)"):
            sqlmap_enabled = st.checkbox("Activează SQLMap pe această țintă")
            sql_path = st.text_input("Cale vulnerabilă (Opțional)", placeholder="/artists.php?artist=1")
            col_s1, col_s2 = st.columns(2)
            with col_s1: risk_level = st.slider("Risk", 1, 3, 1)
            with col_s2: intensity_level = st.slider("Intensity", 1, 5, 1)

        with st.expander("🦇 Metasploit (Auxiliary Scanners)"):
            msf_enabled = st.checkbox("Activează Metasploit pe această țintă")
            msf_module_choices = []
            if msf_enabled and msf_running:
                dynamic_modules = fetch_msf_modules()
                msf_module_choices = st.multiselect("Alege Modulele:", options=dynamic_modules)

        # ==========================================
        # EXECUTIE: BATCH ATTACK
        # ==========================================
        start_attack = st.button("🔥 LANSEAZĂ ATACUL BATCH", type="primary", use_container_width=True)
        
        if start_attack:
            attack_results = []
            attack_url = f"http://{selected_host}{sql_path}" if sqlmap_enabled and sql_path else selected_host
            attack_target_obj = Target(input=attack_url, type=list(TargetType)[0])

            if sqlmap_enabled:
                with st.spinner("Executing SQLMap..."):
                    scanner_sql = SQLMapScanner()
                    attack_results.extend(scanner_sql.run(attack_target_obj, level=intensity_level, risk=risk_level))

            if msf_enabled and msf_running and msf_module_choices:
                for modul in msf_module_choices:
                    with st.spinner(f"Executing MSF ({modul})..."):
                        scanner_msf = MetasploitScanner()
                        parti_batch = modul.split('/', 1)
                        attack_results.extend(scanner_msf.run(attack_target_obj, module_type=parti_batch[0], module_name=parti_batch[1]))

            if attack_results:
                salvate_batch = 0
                for r in attack_results:
                    if is_real_vulnerability(r):
                        sev_val = get_severity_string(r)
                        db.add_vulnerability(selected_target_id, str(r.tool_used), str(r.name), sev_val, str(r.description))
                        salvate_batch += 1

                # Salvăm statusul în sesiune și dăm rerun
                if salvate_batch > 0:
                    st.session_state['batch_msg'] = f"Atac finalizat! Am salvat {salvate_batch} vulnerabilități confirmate în baza de date! 💾"
                    st.session_state['batch_msg_type'] = "success"
                else:
                    st.session_state['batch_msg'] = f"Atac finalizat. {len(attack_results)} verificări rulate, nicio vulnerabilitate salvată."
                    st.session_state['batch_msg_type'] = "info"
                
                st.session_state['batch_table'] = [{"Severitate": get_severity_string(r), "Tip": r.name, "Descriere": r.description, "Tool": r.tool_used} for r in attack_results]
            else:
                st.session_state['batch_msg'] = "Nu ai selectat niciun tool pentru atac, sau nu s-au generat rezultate."
                st.session_state['batch_msg_type'] = "warning"
                st.session_state['batch_table'] = None
                
            st.rerun()

        # Afișare din memorie (persistență după rerun)
        if 'batch_msg' in st.session_state:
            msg_type = st.session_state.get('batch_msg_type', 'info')
            if msg_type == "success": st.success(st.session_state['batch_msg'])
            elif msg_type == "warning": st.warning(st.session_state['batch_msg'])
            else: st.info(st.session_state['batch_msg'])
                
        if st.session_state.get('batch_table'):
            st.dataframe(pd.DataFrame(st.session_state['batch_table']), use_container_width=True)