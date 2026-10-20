import streamlit as st
import pandas as pd
import os
import time
import socket

from core.models import Target, TargetType, AuthConfig, AuthType
from core.database import DatabaseManager
from core.report_generator import generate_pdf_bytes, generate_global_pdf_bytes
from core.auth_session import WebAuthenticator

# --- IMPORTURI MODULE ---
from modules.recon_nmap import NmapScanner
from modules.web_sql import SQLMapScanner
from modules.web_nikto import NiktoScanner
from modules.msf_scanner import MetasploitScanner

# ==========================================================
# INITIALIZARE
# ==========================================================
db = DatabaseManager()
MSF_PORT = 55553
MSF_PASSWORD = "superparola123"

for key, default in {
    'last_results': [],
    'msf_search_raw': "",
    'msf_search_paths': [],
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ==========================================================
# HELPERS SISTEM
# ==========================================================
def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def start_msfrpcd(password=MSF_PASSWORD):
    """Porneste daemon-ul Metasploit RPC detasat de procesul Python."""
    try:
        comanda = f"nohup msfrpcd -P {password} -a 127.0.0.1 > /dev/null 2>&1 &"
        os.system(comanda)
        return True
    except Exception as e:
        print(f"[!] Eroare MSF RPC: {e}")
        return False


def stop_msfrpcd():
    os.system("pkill -f msfrpcd")
    os.system("pkill -f ruby")


@st.cache_data(show_spinner=False, ttl=120)
def fetch_msf_scanner_modules():
    scanner_msf = MetasploitScanner()
    if scanner_msf.check_prerequisites():
        return scanner_msf.get_scanner_modules()
    return []


# ==========================================================
# HELPERS VULNERABILITATI
# ==========================================================
def get_severity_str(obj):
    # Severitatea reala pusa de fiecare scanner (MSF decide HIGH doar la [+])
    if hasattr(obj.severity, 'name'):
        return str(obj.severity.name).upper()
    return str(obj.severity).upper()


def is_valid_vuln(obj):
    tool = str(obj.tool_used).lower()
    desc = str(obj.description).lower()

    noise_keywords = [
        "unable to connect", "could not connect", "failed to load",
        "out of date", "usage:", "metasploit v6", "connection refused",
        "0 host(s) tested", "runtimeerror",
    ]
    if any(noise in desc for noise in noise_keywords):
        return False

    if "metasploit" in tool:
        return "[+]" in desc
    if "nikto" in tool:
        # Modulul Nikto filtreaza deja banner-ul; salvam orice constatare reala
        return len(desc.strip()) > 0
    if "sqlmap" in tool:
        if hasattr(obj.severity, 'name'):
            return obj.severity.name != "INFO"
        return "vulnerable" in desc or "injection" in desc
    return False


def build_auth_config(prefix: str) -> AuthConfig:
    """Randeaza un bloc de autentificare reutilizabil si intoarce AuthConfig."""
    label_map = {
        "Fara autentificare": AuthType.NONE,
        "Cookie de sesiune": AuthType.COOKIE,
        "HTTP Basic Auth": AuthType.BASIC,
        "Headers custom (Bearer/API Key)": AuthType.HEADER,
        "Login prin formular": AuthType.FORM,
    }
    choice = st.selectbox("🔐 Autentificare", options=list(label_map.keys()), key=f"{prefix}_auth_sel")
    atype = label_map[choice]
    cfg = AuthConfig(auth_type=atype)

    if atype == AuthType.COOKIE:
        cfg.cookie = st.text_input("Cookie de sesiune", placeholder="PHPSESSID=abc123; token=xyz", key=f"{prefix}_cookie")
    elif atype == AuthType.BASIC:
        c1, c2 = st.columns(2)
        cfg.username = c1.text_input("Utilizator", key=f"{prefix}_user")
        cfg.password = c2.text_input("Parola", type="password", key=f"{prefix}_pass")
    elif atype == AuthType.HEADER:
        cfg.headers = st.text_area("Headers (unul pe linie)", placeholder="Authorization: Bearer eyJ...\nX-API-Key: 12345", key=f"{prefix}_headers")
    elif atype == AuthType.FORM:
        cfg.login_url = st.text_input("URL pagina de login (primeste POST-ul)", placeholder="http://site/login.php", key=f"{prefix}_lurl")
        cfg.login_data = st.text_input("Date login (POST)", placeholder="username=admin&password=1234", key=f"{prefix}_ldata")
        st.caption("Alternativ, poti lipi direct un cookie autentificat mai jos.")
        cfg.cookie = st.text_input("Cookie (optional)", key=f"{prefix}_fcookie")

    return cfg


# ==========================================================
# CONFIG PAGINA + SIDEBAR
# ==========================================================
st.set_page_config(page_title="Advanced VMS", layout="wide")
st.title("🛡️ Advanced Vulnerability Management Framework")

msf_running = is_port_in_use(MSF_PORT)

with st.sidebar:
    st.header("⚙️ System Status")
    if msf_running:
        st.success("🟢 Metasploit RPC: ONLINE")
        if st.button("⏹️ Stop MSF", use_container_width=True):
            stop_msfrpcd()
            time.sleep(2)
            st.rerun()
    else:
        st.error("🔴 Metasploit RPC: OFFLINE")
        if st.button("🔌 Start MSF", use_container_width=True, type="primary"):
            with st.spinner("Pornim msfrpcd... (poate dura ~15s)"):
                start_msfrpcd()
                time.sleep(15)
            st.rerun()

    for tool, label in [("nmap", "Nmap"), ("nikto", "Nikto"), ("sqlmap", "SQLMap")]:
        from shutil import which
        ok = which(tool) is not None
        st.write(f"{'🟢' if ok else '🔴'} {label}: {'instalat' if ok else 'lipsa'}")

    st.markdown("---")
    st.header("🛑 Emergency Controls")
    if st.button("💀 KILL ALL SCANNERS", type="primary", use_container_width=True):
        for proc in ["nmap", "sqlmap", "nikto"]:
            os.system(f"pkill -9 {proc}")
        stop_msfrpcd()
        st.session_state['last_results'] = []
        st.toast("Procese oprite!", icon="🛑")
        time.sleep(1)
        st.rerun()


# ==========================================================
# TABS
# ==========================================================
tab_recon, tab_assets, tab_msf, tab_web, tab_report = st.tabs([
    "🌐 1. Recon (Nmap)",
    "🗂️ 2. Assets",
    "🦇 3. Metasploit",
    "🎯 4. Atac Web (+Auth)",
    "📊 5. Raportare",
])

targets = db.get_all_targets()
target_map = {t['id']: t['host'] for t in targets}


# ----------------------------------------------------------
# TAB 1: RECON NMAP
# ----------------------------------------------------------
with tab_recon:
    st.header("🔍 Asset Discovery (Nmap)")
    col_in, col_mode = st.columns([3, 2])
    with col_in:
        target_input = st.text_input("Target IP/Domain", placeholder="ex: testphp.vulnweb.com")
    with col_mode:
        mode_label = st.selectbox("Mod scanare", ["Fast (top porturi)", "Deep (toate porturile + versiuni)", "Service detection"])
        use_scripts = st.checkbox("Ruleaza scripturi `vuln` NSE", value=False)

    mode_map = {"Fast (top porturi)": "fast", "Deep (toate porturile + versiuni)": "deep", "Service detection": "service"}

    if st.button("🚀 Start Nmap Recon", use_container_width=True, type="primary"):
        if not target_input.strip():
            st.error("Introdu o tinta.")
        else:
            with st.spinner("Cartografiem reteaua cu Nmap..."):
                scanner = NmapScanner()
                if not scanner.check_prerequisites():
                    st.error("Nmap nu este instalat. Ruleaza: sudo apt install nmap")
                else:
                    scanner.run(Target(input=target_input, type=list(TargetType)[0]),
                                mode=mode_map[mode_label], use_scripts=use_scripts)
                    st.toast("Scanare Nmap finalizata!", icon="✅")
                    st.rerun()


# ----------------------------------------------------------
# TAB 2: ASSETS (vedere DB)
# ----------------------------------------------------------
with tab_assets:
    st.header("🗂️ Active & Vulnerabilitati salvate")
    if not targets:
        st.info("Nicio tinta scanata inca. Porneste cu un scan Nmap in Tab 1.")
    for t in targets:
        v = db.get_vulnerabilities_for_target(t['id'])
        with st.expander(f"📌 {t['host']}  —  {len(v)} vulnerabilitati  (ultima scanare: {t['last_scanned']})"):
            c_info, c_actions = st.columns([4, 1])
            with c_info:
                p = db.get_ports_for_target(t['id'])
                if p:
                    st.markdown("**Porturi deschise:**")
                    st.dataframe(pd.DataFrame(p), use_container_width=True, hide_index=True)
                if v:
                    st.markdown("**🚨 Vulnerabilitati:**")
                    st.dataframe(pd.DataFrame(v), use_container_width=True, hide_index=True)
            with c_actions:
                pdf = generate_pdf_bytes(db, t['id'])
                if pdf:
                    st.download_button("📄 PDF Report", data=pdf, file_name=f"Report_{t['host']}.pdf",
                                       mime="application/pdf", use_container_width=True, key=f"pdf_{t['id']}")
                if st.button("🗑️ Delete", key=f"del_{t['id']}", use_container_width=True):
                    db.delete_target(t['id'])
                    st.rerun()


# ----------------------------------------------------------
# TAB 3: METASPLOIT
# ----------------------------------------------------------
with tab_msf:
    st.header("🦇 Metasploit Framework")
    if not msf_running:
        st.warning("Metasploit RPC este OFFLINE. Porneste-l din bara laterala (🔌 Start MSF).")
    else:
        st.success("Conectat la msfrpcd.")

        st.subheader("🔎 Cautare module")
        kw = st.text_input("Keyword (ex: smb, http, apache, ssh)", key="msf_kw")
        if st.button("Cauta in Metasploit", disabled=not msf_running):
            with st.spinner(f"Caut '{kw}' in Metasploit..."):
                m = MetasploitScanner()
                raw = m.search_modules(kw)
                st.session_state['msf_search_raw'] = raw
                st.session_state['msf_search_paths'] = m.extract_module_paths(raw)

        if st.session_state['msf_search_raw']:
            with st.expander("Rezultate brute cautare", expanded=False):
                st.code(st.session_state['msf_search_raw'], language="text")

        st.markdown("---")
        st.subheader("▶️ Ruleaza un modul auxiliary pe o tinta")

        if not targets:
            st.info("Ai nevoie de cel putin o tinta (Tab 1) pentru a rula module.")
        else:
            sel_id = st.selectbox("Tinta", options=list(target_map.keys()),
                                  format_func=lambda x: target_map[x], key="msf_target")
            sel_host = target_map[sel_id]

            scanner_mods = fetch_msf_scanner_modules()
            options = sorted(set(scanner_mods) | set(st.session_state['msf_search_paths']))
            chosen = st.multiselect("Module de rulat", options=options,
                                    help="Module auxiliary/scanner + orice ai gasit prin cautare.")
            lhost = st.text_input("LHOST (optional, pentru module care au nevoie)", key="msf_lhost")

            if st.button("🔥 Ruleaza modulele MSF", type="primary", disabled=not chosen):
                results = []
                m = MetasploitScanner()
                for path in chosen:
                    if "/" not in path:
                        continue
                    m_type, m_name = path.split("/", 1)
                    # auxiliary/scanner/... -> type=auxiliary, name=scanner/...
                    if m_type not in ("auxiliary", "exploit", "post"):
                        m_type, m_name = "auxiliary", path
                    with st.spinner(f"Rulez {path}..."):
                        res = m.run(Target(input=sel_host, type=list(TargetType)[0]),
                                    module_type=m_type, module_name=m_name,
                                    lhost=lhost or None)
                        results.extend(res)

                saved = 0
                for r in results:
                    if is_valid_vuln(r):
                        db.add_vulnerability(sel_id, str(r.tool_used), r.name, get_severity_str(r), r.description)
                        saved += 1
                st.session_state['last_results'] = [
                    {"Tool": r.tool_used, "Nume": r.name, "Descriere": r.description, "Severitate": get_severity_str(r)}
                    for r in results
                ]
                st.toast(f"MSF finalizat. {saved} rezultate confirmate salvate.", icon="✅")
                st.rerun()

        if st.session_state['last_results']:
            st.markdown("---")
            st.subheader("📋 Ultimele rezultate")
            for item in st.session_state['last_results']:
                with st.expander(f"👁️ {item['Nume']} ({str(item['Tool']).upper()}) — {item['Severitate']}"):
                    st.code(item['Descriere'], language="text")


# ----------------------------------------------------------
# TAB 4: ATAC WEB + AUTENTIFICARE
# ----------------------------------------------------------
with tab_web:
    st.header("🎯 Pipeline Atac Web (Nikto + SQLMap)")
    if not targets:
        st.warning("Adauga o tinta in Tab 1 mai intai!")
    else:
        sel_id = st.selectbox("🎯 Tinta", options=list(target_map.keys()),
                              format_func=lambda x: target_map[x], key="web_target")
        sel_host = target_map[sel_id]

        target_ports = db.get_ports_for_target(sel_id)
        web_ports = [p['port'] for p in target_ports
                     if p['port'] in [80, 443, 8000, 8080, 8443]
                     or 'http' in str(p.get('service') or '').lower()]

        base_url = ""
        if web_ports:
            st.success(f"🌐 Servicii WEB detectate pe porturile: **{web_ports}**")
            port_to_use = web_ports[0]
            protocol = "https" if port_to_use in [443, 8443] else "http"
            base_url = f"{protocol}://{sel_host}" if port_to_use in [80, 443] else f"{protocol}://{sel_host}:{port_to_use}"
        else:
            st.warning("⚠️ Nmap nu a gasit porturi web standard. Introdu URL-ul manual.")
            base_url = st.text_input("URL Web Manual:", value=f"http://{sel_host}")

        # ----------------------------------------------------------
        # CAPTURA SESIUNE AUTENTIFICATA (motor intern, fara browser/proxy)
        # ----------------------------------------------------------
        st.markdown("### 🔐 Autentificare & captura sesiune")

        existing = db.get_session(sel_id)
        if existing:
            st.success(f"✅ Sesiune salvata ({existing['created']}) · cookie: `{existing['cookie'][:60]}...`")
            if st.button("🗑️ Sterge sesiunea"):
                db.delete_session(sel_id)
                st.rerun()
        else:
            st.info("Nicio sesiune salvata. Autentifica-te mai jos ca scannerele sa poata accesa zonele protejate.")

        with st.expander("🔑 Logare in aplicatie (captureaza cookie-urile automat)", expanded=not existing):
            auth_cfg = build_auth_config("web")
            if st.button("🔑 Login & captureaza sesiunea", use_container_width=True):
                with st.spinner("Ma autentific in aplicatie..."):
                    authn = WebAuthenticator(verify_ssl=False)
                    ok = authn.authenticate(auth_cfg)
                st.code("\n".join(authn.log), language="text")
                if ok and authn.cookie_string():
                    db.save_session(sel_id, authn.cookie_string(), base_url,
                                    auth_cfg.login_url or "")
                    st.success(f"Sesiune capturata: `{authn.cookie_string()}`")
                    st.rerun()
                elif ok:
                    st.warning("Autentificare OK, dar nu s-au capturat cookie-uri (poate e Basic/Header - se aplica la scanare).")
                    # pastram configul manual pt Basic/Header
                    db.save_session(sel_id, auth_cfg.cookie or "", base_url, auth_cfg.login_url or "")
                else:
                    st.error("Autentificare esuata. Verifica URL-ul de login, datele si token-ul CSRF.")

        # Determinam autentificarea efectiva folosita de scannere
        sess = db.get_session(sel_id)
        if sess and sess['cookie']:
            effective_auth = AuthConfig(auth_type=AuthType.COOKIE, cookie=sess['cookie'])
            st.caption("🔒 Scannerele vor folosi sesiunea autentificata salvata.")
        else:
            effective_auth = AuthConfig(auth_type=AuthType.NONE)
            st.caption("🔓 Scanare neautentificata (nicio sesiune salvata).")

        with st.form("pipeline_form"):
            st.markdown("#### Nikto — vulnerabilitati & misconfiguratii web")
            run_nikto = st.checkbox("Ruleaza Nikto", value=bool(web_ports))
            st.caption(f"Tinta Nikto: `{base_url}`")

            st.markdown("#### SQLMap — injectii SQL")
            run_sqlmap = st.checkbox("Ruleaza SQLMap", value=False)
            col_s1, col_s2, col_s3 = st.columns([3, 1, 1])
            sql_path = col_s1.text_input("Cale vulnerabila", placeholder="/pagina.php?id=1")
            sql_level = col_s2.number_input("Level", 1, 5, 1)
            sql_risk = col_s3.number_input("Risk", 1, 3, 1)

            submit_pipeline = st.form_submit_button("🔥 LANSEAZA PIPELINE-UL", type="primary", use_container_width=True)

        if submit_pipeline:
            pipeline_results = []

            if run_nikto:
                with st.spinner(f"🌐 Nikto scaneaza {base_url}..."):
                    res_nikto = NiktoScanner().run(
                        Target(input=base_url, type=list(TargetType)[0]), auth=effective_auth)
                    pipeline_results.extend(res_nikto)

            if run_sqlmap and sql_path:
                full_sql_url = f"{base_url}{sql_path}"
                with st.spinner(f"💉 SQLMap ataca {full_sql_url}..."):
                    res_sql = SQLMapScanner().run(
                        Target(input=full_sql_url, type=list(TargetType)[0]),
                        level=int(sql_level), risk=int(sql_risk), auth=effective_auth)
                    pipeline_results.extend(res_sql)
            elif run_sqlmap and not sql_path:
                st.error("Ai bifat SQLMap dar nu ai oferit o cale.")

            saved = 0
            for r in pipeline_results:
                if is_valid_vuln(r):
                    db.add_vulnerability(sel_id, str(r.tool_used), r.name, get_severity_str(r), r.description)
                    saved += 1
            st.session_state['last_results'] = [
                {"Tool": r.tool_used, "Nume": r.name, "Descriere": r.description, "Severitate": get_severity_str(r)}
                for r in pipeline_results
            ]
            st.toast(f"Pipeline finalizat! {saved} vulnerabilitati salvate.", icon="✅")
            st.rerun()

        if st.session_state['last_results']:
            st.markdown("---")
            st.subheader("📋 Rezultatele Pipeline-ului")
            if st.button("🧹 Curata rezultatele"):
                st.session_state['last_results'] = []
                st.rerun()
            df_res = pd.DataFrame(st.session_state['last_results'])
            st.dataframe(df_res[["Tool", "Nume", "Severitate"]], use_container_width=True, hide_index=True)
            for item in st.session_state['last_results']:
                with st.expander(f"👁️ {item['Nume']} ({str(item['Tool']).upper()})"):
                    st.code(item['Descriere'], language="text")


# ----------------------------------------------------------
# TAB 5: RAPORTARE AGREGATA
# ----------------------------------------------------------
with tab_report:
    st.header("📊 Raportare consolidata")

    # Agregam toate vulnerabilitatile
    all_rows = []
    for t in targets:
        for v in db.get_vulnerabilities_for_target(t['id']):
            all_rows.append({
                "Tinta": t['host'],
                "Tool": v['tool'],
                "Nume": v['name'],
                "Severitate": str(v['severity']).upper(),
                "Detalii": v['details'],
                "Data": v['timestamp'],
            })

    if not all_rows:
        st.info("Nicio vulnerabilitate salvata inca.")
    else:
        df = pd.DataFrame(all_rows)

        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        cols = st.columns(len(sev_order) + 1)
        cols[0].metric("Total", len(df))
        for i, s in enumerate(sev_order, 1):
            cols[i].metric(s.title(), int((df["Severitate"] == s).sum()))

        st.markdown("---")
        f1, f2 = st.columns(2)
        sev_filter = f1.multiselect("Filtru severitate", sev_order, default=sev_order)
        tool_filter = f2.multiselect("Filtru tool", sorted(df["Tool"].unique()),
                                     default=sorted(df["Tool"].unique()))

        filtered = df[df["Severitate"].isin(sev_filter) & df["Tool"].isin(tool_filter)]
        st.dataframe(filtered[["Tinta", "Tool", "Nume", "Severitate", "Data"]],
                     use_container_width=True, hide_index=True)

        st.markdown("---")
        c1, c2 = st.columns(2)
        with c1:
            global_pdf = generate_global_pdf_bytes(db)
            st.download_button("📄 Descarca RAPORT GLOBAL (PDF)", data=global_pdf,
                               file_name="Raport_Global_VMS.pdf", mime="application/pdf",
                               use_container_width=True, type="primary")
        with c2:
            st.download_button("⬇️ Export CSV", data=filtered.to_csv(index=False).encode("utf-8"),
                               file_name="vulnerabilitati.csv", mime="text/csv",
                               use_container_width=True)
