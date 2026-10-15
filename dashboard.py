import streamlit as st
import pandas as pd
import os
from core.models import Target, TargetType
from modules.recon_nmap import NmapScanner

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
        # Aici vom adăuga și alte tools pe viitor (ex: pkill sqlmap)
        st.toast("Toate procesele au fost terminate forțat!", icon="🛑")

# ==========================================
# ZONA PRINCIPALĂ: TAB-URI
# ==========================================

# Creăm tab-urile
tab_config, tab_results = st.tabs(["🛠️ Configurare Tool-uri", "📊 Rezultate Scanare"])

# --- TAB 1: CONFIGURARE ---
with tab_config:
    st.info(f"Configurare activă pentru vectorul: **{scan_type.upper()}**")
    
    # Container pentru NMAP (Îl punem într-un Expander ca să nu ocupe loc dacă nu vrem)
    with st.expander("🌐 Nmap (Network Reconnaissance)", expanded=True):
        col_nmap_1, col_nmap_2 = st.columns(2)
        
        with col_nmap_1:
            scan_mode_label = st.selectbox(
                "Profil Scanare",
                options=["Rapid (Fast)", "Normal (Default)", "Adânc (Deep)"],
                index=1,
                key="nmap_mode"
            )
        
        with col_nmap_2:
            use_scripts = st.checkbox(
                "Activează Scripturi NSE (--script=vuln)", 
                value=False,
                help="Rulează scripturi de detectare CVE. Durează mai mult!"
            )
            
        # Mapping pentru codul intern
        mode_map = {
            "Rapid (Fast)": "fast",
            "Normal (Default)": "default",
            "Adânc (Deep)": "deep"
        }
        selected_mode = mode_map[scan_mode_label]

    # --- AICI VOM ADĂUGA VIITOARELE TOOL-URI ---
    # Exemplu pentru viitor (doar vizual acum):
    # with st.expander("💉 SQLMap (Database Injection)", expanded=False):
    #     st.text("Opțiunile SQLMap vor apărea aici...")

    st.markdown("---")
    
    # Butonul mare de START
    start_scan = st.button("🚀 LANSEAZĂ SCANAREA", type="primary", use_container_width=False)


# --- LOGICA DE SCANARE ---
if start_scan:
    if not target_input:
        st.toast("Te rog introdu o țintă validă!", icon="❌")
    else:
        # Mutăm focusul automat pe tab-ul de rezultate (vizual)
        
        with tab_results:
            status_container = st.empty() # Placeholder pentru status
            
            with st.spinner(f"Execut scanare pe {target_input}..."):
                try:
                    # 1. Pregătire
                    current_target = Target(input=target_input, type=scan_type)
                    
                    # 2. Execuție Module
                    # Aici putem selecta ce module rulăm bazat pe ce expandere sunt deschise (pe viitor)
                    scanner = NmapScanner()
                    
                    if scanner.check_prerequisites():
                        results = scanner.run(current_target, mode=selected_mode, use_scripts=use_scripts)
                        
                        # 3. Afișare Rezultate
                        if results:
                            status_container.success(f"Gata! Am găsit {len(results)} probleme.")
                            
                            # Pregătire date tabel
                            data = []
                            for res in results:
                                data.append({
                                    "Severitate": res.severity.value,
                                    "Vulnerabilitate": res.name,
                                    "Descriere": res.description,
                                    "Tool": res.tool_used
                                })
                            
                            df = pd.DataFrame(data)
                            
                            # Configurare culori pentru severitate (Opțional, vizual)
                            def color_severity(val):
                                color = 'green'
                                if val == 'HIGH' or val == 'CRITICAL': color = 'red'
                                elif val == 'MEDIUM': color = 'orange'
                                return f'color: {color}'

                            # Afișare Tabel
                            st.dataframe(
                                df,
                                use_container_width=True,
                                column_config={
                                    "Severitate": st.column_config.TextColumn("Sev.", width="small"),
                                    "Descriere": st.column_config.TextColumn("Detalii Tehnice", width="large"),
                                }
                            )
                            
                            # Metrici rapide
                            m1, m2, m3 = st.columns(3)
                            m1.metric("Total", len(results))
                            m2.metric("High/Crit", len([r for r in results if r.severity.value in ['HIGH', 'CRITICAL']]))
                            m3.metric("Tool", "Nmap")
                            
                        else:
                            status_container.warning("Scanare completă, dar nu au fost găsite vulnerabilități.")
                    else:
                        status_container.error("Nmap nu este instalat!")
                        
                except Exception as e:
                    st.error(f"Eroare execuție: {e}")

# --- TAB 2: REZULTATE (Placeholder dacă nu e scanare activă) ---
# Acest tab se va popula automat când rulează scanarea, dar punem un mesaj default
if not start_scan:
    with tab_results:
        st.info("Apasă 'Lansează Scanarea' pentru a vedea rezultatele aici.")