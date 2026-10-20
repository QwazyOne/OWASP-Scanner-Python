import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import os
import time
import socket
import shlex
from datetime import datetime, timedelta

from core.models import Target, TargetType, AuthConfig, AuthType
from core.database import DatabaseManager
from core.report_generator import generate_pdf_bytes, generate_global_pdf_bytes
from core.auth_session import WebAuthenticator, BrowserAuthenticator

# --- IMPORTURI MODULE ---
from modules.recon_nmap import NmapScanner
from modules.web_sql import SQLMapScanner
from modules.web_nikto import NiktoScanner
from modules.msf_scanner import MetasploitScanner
from modules.web_vigolium import VigoliumScanner, _vigolium_bin

# ==========================================================
# INITIALIZARE
# ==========================================================
db = DatabaseManager()
MSF_PORT = 55553
MSF_PASSWORD = "superparola123"
VIGOLIUM_UI_PORT = 9002

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


def start_vigolium_server(vig_bin: str):
    """Porneste interfata web nativa Vigolium (server mode) in fundal.
    -A dezactiveaza autentificarea (ok local, legat de 127.0.0.1)."""
    log = "/tmp/vigolium_server.log"
    cmd = (f"nohup {shlex.quote(vig_bin)} server --host 127.0.0.1 "
           f"--service-port {VIGOLIUM_UI_PORT} -A > {shlex.quote(log)} 2>&1 &")
    os.system(cmd)


def stop_vigolium_server():
    os.system("pkill -f 'vigolium server'")


@st.cache_data(show_spinner=False, ttl=120)
def fetch_msf_scanner_modules():
    scanner_msf = MetasploitScanner()
    if scanner_msf.check_prerequisites():
        return scanner_msf.get_scanner_modules()
    return []


# ==========================================================
# CATALOG METASPLOIT (nume prietenoase + sugestii pe porturi)
# ==========================================================
MSF_PRESETS = {
    "🔎 Recon general": [
        ("scanner/portscan/tcp", "Scanare porturi TCP", "Descopera porturi deschise via MSF."),
        ("scanner/discovery/udp_sweep", "UDP Sweep", "Descopera servicii UDP comune."),
    ],
    "🌐 HTTP / Web": [
        ("scanner/http/http_version", "Versiune server web", "Afla versiunea serverului HTTP."),
        ("scanner/http/title", "Titluri pagini", "Extrage titlul paginilor web."),
        ("scanner/http/robots_txt", "robots.txt", "Cauta si citeste robots.txt."),
        ("scanner/http/dir_scanner", "Scanare directoare", "Cauta directoare web comune."),
        ("scanner/http/options", "Metode HTTP (OPTIONS)", "Afla metodele HTTP permise."),
    ],
    "🗂️ SMB (Windows)": [
        ("scanner/smb/smb_version", "Versiune SMB / OS", "Detecteaza versiunea SMB si sistemul."),
        ("scanner/smb/smb_enumshares", "Enumerare share-uri", "Listeaza folderele partajate SMB."),
        ("scanner/smb/smb_ms17_010", "EternalBlue (MS17-010)", "Verifica vulnerabilitatea critica MS17-010."),
    ],
    "🔑 SSH": [
        ("scanner/ssh/ssh_version", "Versiune SSH", "Detecteaza versiunea serverului SSH."),
    ],
    "📁 FTP": [
        ("scanner/ftp/ftp_version", "Versiune FTP", "Detecteaza versiunea serverului FTP."),
        ("scanner/ftp/anonymous", "FTP anonim", "Verifica daca e permis login anonim."),
    ],
    "🗄️ Baze de date": [
        ("scanner/mysql/mysql_version", "Versiune MySQL", "Detecteaza versiunea MySQL."),
        ("scanner/postgres/postgres_version", "Versiune PostgreSQL", "Detecteaza versiunea PostgreSQL."),
    ],
}

# path -> (nume prietenos, descriere), construit din presets
MSF_FRIENDLY = {path: (name, desc)
                for mods in MSF_PRESETS.values()
                for (path, name, desc) in mods}

# port deschis -> module relevante sugerate
MSF_PORT_SUGGESTIONS = {
    80: ["scanner/http/http_version", "scanner/http/title", "scanner/http/robots_txt"],
    443: ["scanner/http/http_version", "scanner/http/title"],
    8080: ["scanner/http/http_version", "scanner/http/title", "scanner/http/dir_scanner"],
    8443: ["scanner/http/http_version", "scanner/http/title"],
    445: ["scanner/smb/smb_version", "scanner/smb/smb_enumshares", "scanner/smb/smb_ms17_010"],
    139: ["scanner/smb/smb_version"],
    22: ["scanner/ssh/ssh_version"],
    21: ["scanner/ftp/ftp_version", "scanner/ftp/anonymous"],
    3306: ["scanner/mysql/mysql_version"],
    5432: ["scanner/postgres/postgres_version"],
}


def msf_label(path: str) -> str:
    """Eticheta prietenoasa pentru un modul; fallback pe numele scurt."""
    if path in MSF_FRIENDLY:
        return f"{MSF_FRIENDLY[path][0]}  ·  {path}"
    return path


def suggest_msf_modules(ports) -> list:
    """Sugereaza module pe baza porturilor deschise ale tintei."""
    suggested = []
    for p in ports:
        for mod in MSF_PORT_SUGGESTIONS.get(p.get('port'), []):
            if mod not in suggested:
                suggested.append(mod)
    return suggested


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
    if "vigolium" in tool:
        # Vigolium filtreaza evenimentele la parsare; salvam orice finding cu continut
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
        "Login prin browser (Playwright/SPA)": AuthType.BROWSER,
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
    elif atype == AuthType.BROWSER:
        from core.auth_session import BrowserAuthenticator
        if not BrowserAuthenticator.is_available():
            st.error("Playwright nu e instalat. Ruleaza: pip install playwright && python -m playwright install chromium")
        cfg.login_url = st.text_input("URL pagina de login", placeholder="https://app/login", key=f"{prefix}_burl")
        c1, c2 = st.columns(2)
        cfg.username = c1.text_input("Utilizator", key=f"{prefix}_buser")
        cfg.password = c2.text_input("Parola", type="password", key=f"{prefix}_bpass")
        with st.expander("Selectoare CSS (optional - se auto-detecteaza daca le lasi goale)"):
            cfg.user_selector = st.text_input("Selector camp utilizator", placeholder="input[name=username]", key=f"{prefix}_bus") or None
            cfg.pass_selector = st.text_input("Selector camp parola", placeholder="input[type=password]", key=f"{prefix}_bps") or None
            cfg.submit_selector = st.text_input("Selector buton submit", placeholder="button[type=submit]", key=f"{prefix}_bsub") or None
            cfg.success_selector = st.text_input("Selector care apare DOAR dupa login", placeholder="a[href*=logout]", key=f"{prefix}_bsucc") or None

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

    from shutil import which
    from modules.web_vigolium import _vigolium_bin
    for tool, label in [("nmap", "Nmap"), ("nikto", "Nikto"), ("sqlmap", "SQLMap"), ("vigolium", "Vigolium")]:
        ok = (_vigolium_bin() is not None) if tool == "vigolium" else (which(tool) is not None)
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
tab_recon, tab_assets, tab_msf, tab_web, tab_report, tab_vigui = st.tabs([
    "🌐 1. Recon (Nmap)",
    "🗂️ 2. Assets",
    "🦇 3. Metasploit",
    "🎯 4. Atac Web (+Auth)",
    "📊 5. Raportare",
    "🧪 6. Vigolium UI",
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

    # --- Curatare in masa a tintelor vechi ---
    if targets:
        with st.expander("🧹 Curatare tinte vechi", expanded=False):
            col_old, col_all = st.columns(2)
            with col_old:
                days = st.number_input(
                    "Sterge tintele mai vechi de (zile)",
                    min_value=1, max_value=3650, value=30, step=1, key="cleanup_days")
                if st.button(f"🗑️ Sterge tinte mai vechi de {int(days)} zile",
                             use_container_width=True, key="del_old"):
                    cutoff = datetime.now() - timedelta(days=int(days))
                    removed = 0
                    for t in targets:
                        ls = t.get("last_scanned")
                        # Data lipsa sau invalida => tinta considerata veche
                        is_old = True
                        if ls:
                            try:
                                is_old = datetime.strptime(ls, "%Y-%m-%d %H:%M:%S") < cutoff
                            except ValueError:
                                is_old = True
                        if is_old:
                            db.delete_target(t['id'])
                            removed += 1
                    st.success(f"Am sters {removed} tinta/tinte mai vechi de {int(days)} zile.")
                    st.rerun()
            with col_all:
                st.caption("Sterge definitiv TOATE tintele si datele lor (porturi, vulns, sesiuni).")
                confirm_all = st.checkbox("Confirm stergerea tuturor", key="confirm_all")
                if st.button("💥 Sterge TOATE tintele", type="primary",
                             disabled=not confirm_all, use_container_width=True, key="del_all"):
                    for t in targets:
                        db.delete_target(t['id'])
                    st.success("Toate tintele au fost sterse.")
                    st.rerun()

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
    st.header("🦇 Metasploit")

    if not msf_running:
        st.warning("🔴 Metasploit RPC este OFFLINE.")
        st.info("Apasa **🔌 Start MSF** din bara laterala stanga ca sa pornesti motorul. "
                "Dureaza ~15 secunde, apoi revii aici.")
    elif not targets:
        st.info("Mai intai adauga o tinta cu un scan Nmap in **Tab 1 - Recon**.")
    else:
        st.success("🟢 Conectat la Metasploit. Alege o tinta si bifeaza ce vrei sa verifici.")

        sel_id = st.selectbox("🎯 Tinta", options=list(target_map.keys()),
                              format_func=lambda x: target_map[x], key="msf_target")
        sel_host = target_map[sel_id]
        tgt_ports = db.get_ports_for_target(sel_id)

        chosen = []  # module alese (cai complete)

        # --- 1. RECOMANDARI PE BAZA PORTURILOR ---
        st.markdown("### ✨ Recomandat pentru aceasta tinta")
        suggested = suggest_msf_modules(tgt_ports)
        if suggested:
            open_ports = [p['port'] for p in tgt_ports]
            st.caption(f"Pe baza porturilor deschise gasite de Nmap: {open_ports}")
            default_sel = st.multiselect(
                "Verificari sugerate (bifate automat)", options=suggested,
                default=suggested, format_func=msf_label, key="msf_suggested")
            chosen.extend(default_sel)
        else:
            st.caption("Nmap nu a gasit porturi care sa aiba verificari sugerate. "
                       "Foloseste catalogul de mai jos.")

        # --- 2. CATALOG PE CATEGORII ---
        with st.expander("📚 Catalog verificari (pe categorii)", expanded=not suggested):
            for category, mods in MSF_PRESETS.items():
                st.markdown(f"**{category}**")
                for path, name, desc in mods:
                    if st.checkbox(f"{name} — _{desc}_", key=f"msf_cat_{path}"):
                        if path not in chosen:
                            chosen.append(path)

        # --- 3. CAUTARE AVANSATA ---
        with st.expander("🔍 Cautare avansata in Metasploit"):
            kw = st.text_input("Keyword (ex: apache, tomcat, wordpress)", key="msf_kw")
            if st.button("Cauta", disabled=not kw):
                with st.spinner(f"Caut '{kw}'..."):
                    m = MetasploitScanner()
                    raw = m.search_modules(kw)
                    st.session_state['msf_search_raw'] = raw
                    st.session_state['msf_search_paths'] = m.extract_module_paths(raw)
            if st.session_state['msf_search_paths']:
                extra = st.multiselect("Module gasite", options=st.session_state['msf_search_paths'],
                                       key="msf_found")
                chosen.extend(m for m in extra if m not in chosen)

        # --- RULARE ---
        st.markdown("---")
        lhost = st.text_input("LHOST (doar pentru module care cer IP-ul tau; optional)", key="msf_lhost")
        st.caption(f"Vei rula **{len(chosen)}** verificari pe **{sel_host}**.")

        if st.button("🔥 Ruleaza verificarile selectate", type="primary", disabled=not chosen,
                     use_container_width=True):
            results = []
            m = MetasploitScanner()
            prog = st.progress(0.0)
            for i, path in enumerate(chosen, 1):
                if "/" not in path:
                    continue
                m_type, m_name = path.split("/", 1)
                if m_type not in ("auxiliary", "exploit", "post"):
                    m_type, m_name = "auxiliary", path
                with st.spinner(f"[{i}/{len(chosen)}] {msf_label(path)}..."):
                    res = m.run(Target(input=sel_host, type=list(TargetType)[0]),
                                module_type=m_type, module_name=m_name, lhost=lhost or None)
                    results.extend(res)
                prog.progress(i / len(chosen))

            saved = 0
            for r in results:
                if is_valid_vuln(r):
                    db.add_vulnerability(sel_id, str(r.tool_used), r.name, get_severity_str(r), r.description)
                    saved += 1
            st.session_state['last_results'] = [
                {"Tool": r.tool_used, "Nume": r.name, "Descriere": r.description, "Severitate": get_severity_str(r)}
                for r in results
            ]
            st.toast(f"Gata! {saved} rezultate confirmate salvate in raport.", icon="✅")
            st.rerun()

        if st.session_state['last_results']:
            st.markdown("---")
            st.subheader("📋 Rezultate")
            for item in st.session_state['last_results']:
                icon = "🔴" if item['Severitate'] in ("HIGH", "CRITICAL") else "⚪"
                with st.expander(f"{icon} {item['Nume']} — {item['Severitate']}"):
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

        # Ghicim un URL de pornire din porturile Nmap, dar lasam campul EDITABIL
        # (hostul din DB nu are port; tinte ca :4280 trebuie corectate manual).
        if web_ports:
            st.success(f"🌐 Servicii WEB detectate pe porturile: **{web_ports}**")
            port_to_use = web_ports[0]
            protocol = "https" if port_to_use in [443, 8443] else "http"
            guessed = f"{protocol}://{sel_host}" if port_to_use in [80, 443] else f"{protocol}://{sel_host}:{port_to_use}"
        else:
            st.warning("⚠️ Nmap nu a gasit porturi web standard. Verifica URL-ul de mai jos.")
            guessed = f"http://{sel_host}"

        base_url = st.text_input("🌐 URL tinta (editabil)", value=guessed,
                                 help="Corecteaza protocolul/portul daca e nevoie, ex: https://host:4280",
                                 key="web_base_url")

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
                    if auth_cfg.auth_type == AuthType.BROWSER:
                        authn = BrowserAuthenticator()
                    else:
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

            st.markdown("#### Vigolium — scanner web modern (Native Scan)")
            run_vigolium = st.checkbox("Ruleaza Vigolium", value=False)
            vig_strategy = st.selectbox("Strategie Vigolium", ["lite", "balanced", "deep"], index=1)
            st.caption(f"Tinta Vigolium: `{base_url}`")

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

            if run_vigolium:
                vig_scanner = VigoliumScanner()
                if not vig_scanner.check_prerequisites():
                    st.error("❌ Vigolium nu a fost gasit. Instaleaza-l si asigura-te ca `~/.local/bin` e in PATH "
                             "(sau porneste aplicatia cu `./run.sh`).")
                else:
                    with st.spinner(f"🧪 Vigolium ({vig_strategy}) scaneaza {base_url}..."):
                        res_vig = vig_scanner.run(
                            Target(input=base_url, type=list(TargetType)[0]),
                            strategy=vig_strategy, auth=effective_auth)
                        pipeline_results.extend(res_vig)
                    if not res_vig:
                        st.warning("Vigolium nu a returnat constatari. Jurnal:")
                        st.code("\n".join(vig_scanner.log[-8:]) or "(fara mesaje)", language="text")

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
    st.header("📊 Raportare")

    # --- RAPORT PER TINTA ---
    st.subheader("🎯 Raport pentru o tinta")
    if not targets:
        st.info("Nicio tinta disponibila.")
    else:
        r_id = st.selectbox("Selecteaza tinta", options=list(target_map.keys()),
                            format_func=lambda x: f"{target_map[x]} ({len(db.get_vulnerabilities_for_target(x))} vulns)",
                            key="report_target")
        r_host = target_map[r_id]
        r_vulns = db.get_vulnerabilities_for_target(r_id)

        if r_vulns:
            st.dataframe(pd.DataFrame(r_vulns)[["tool", "name", "severity", "timestamp"]],
                         use_container_width=True, hide_index=True)
        else:
            st.caption("Aceasta tinta nu are vulnerabilitati salvate.")

        rc1, rc2 = st.columns(2)
        with rc1:
            tgt_pdf = generate_pdf_bytes(db, r_id)
            st.download_button("📄 Genereaza raport PDF (aceasta tinta)", data=tgt_pdf,
                               file_name=f"Raport_{r_host}.pdf", mime="application/pdf",
                               use_container_width=True, type="primary", key="rep_pdf_target")
        with rc2:
            csv_target = pd.DataFrame(r_vulns).to_csv(index=False).encode("utf-8") if r_vulns else b""
            st.download_button("⬇️ Export CSV (aceasta tinta)", data=csv_target,
                               file_name=f"{r_host}_vulns.csv", mime="text/csv",
                               use_container_width=True, disabled=not r_vulns, key="rep_csv_target")

    st.markdown("---")
    st.subheader("🌐 Raport consolidat (toate tintele)")

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


# ----------------------------------------------------------
# TAB 6: INTERFATA NATIVA VIGOLIUM (inglobata prin iframe)
# ----------------------------------------------------------
with tab_vigui:
    st.header("🧪 Vigolium — interfata nativa")
    vig_bin = _vigolium_bin()

    if not vig_bin:
        st.error("Vigolium nu e instalat sau nu e in PATH. "
                 "Instaleaza: `curl -fsSL https://vigolium.com/install.sh | bash`")
    else:
        running = is_port_in_use(VIGOLIUM_UI_PORT)
        c1, c2 = st.columns([3, 1])
        if running:
            c1.success(f"🟢 Server Vigolium ONLINE pe http://localhost:{VIGOLIUM_UI_PORT}")
            if c2.button("⏹️ Opreste", use_container_width=True):
                stop_vigolium_server()
                time.sleep(1)
                st.rerun()
        else:
            c1.error("🔴 Server Vigolium OFFLINE")
            if c2.button("🚀 Porneste", type="primary", use_container_width=True):
                with st.spinner("Pornesc serverul Vigolium..."):
                    start_vigolium_server(vig_bin)
                    time.sleep(5)
                st.rerun()

        if running:
            url = f"http://localhost:{VIGOLIUM_UI_PORT}/"
            st.markdown(f"### 👉 [Deschide interfata Vigolium intr-un tab nou]({url})")
            st.caption(
                "Vigolium trimite `X-Frame-Options: DENY` (protectie anti-clickjacking), "
                "deci interfata lor NU poate fi inglobata direct intr-un iframe. "
                "Dashboard-ul nostru o porneste/opreste si o lanseaza; ea ruleaza local pe "
                f"127.0.0.1:{VIGOLIUM_UI_PORT}.")
            # Buton care deschide UI-ul in alt tab (JS, fiindca iframe-ul e interzis)
            components.html(
                f"""
                <a href="{url}" target="_blank" rel="noopener"
                   style="display:inline-block;padding:10px 18px;background:#2e86de;color:#fff;
                          border-radius:8px;text-decoration:none;font-family:sans-serif;">
                   🧪 Deschide Vigolium UI
                </a>
                """, height=60)
            st.markdown("---")
            st.markdown(f"- 🔎 Swagger / API: [http://localhost:{VIGOLIUM_UI_PORT}/swagger/](http://localhost:{VIGOLIUM_UI_PORT}/swagger/)")
            st.markdown(f"- ❤️ Health: [http://localhost:{VIGOLIUM_UI_PORT}/health](http://localhost:{VIGOLIUM_UI_PORT}/health)")
        else:
            st.info("Porneste serverul ca sa lansezi interfata web nativa Vigolium "
                    "(rezultate, trafic, API Swagger). Ruleaza local pe 127.0.0.1.")
