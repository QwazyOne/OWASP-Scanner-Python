# 🛡️ Advanced Vulnerability Management Framework

Platformă de scanare și management al vulnerabilităților, cu interfață web (Streamlit),
care orchestrează unelte consacrate de securitate: **Nmap**, **Nikto**, **SQLMap** și
**Metasploit**. Include scanarea aplicațiilor web **cu autentificare** (cookie, Basic,
headers, login prin formular și login prin browser headless cu Playwright) și raportare
PDF/CSV per-țintă și consolidată.

> ⚠️ **Folosire legală.** Scanează doar ținte proprii sau pentru care ai permisiune
> explicită, scrisă. Scanarea neautorizată este ilegală.

---

## Cuprins
- [Cerințe](#cerințe)
- [Instalare pe Debian](#instalare-pe-debian)
- [Pornire](#pornire)
- [Funcționalități](#funcționalități)
- [Structura proiectului](#structura-proiectului)
- [Depanare](#depanare)

---

## Cerințe

- **Debian** (sau derivat: Ubuntu, Kali)
- **Python 3.10+**
- Unelte de sistem: `nmap`, `nikto`, `sqlmap`, `metasploit-framework`

---

## Instalare pe Debian

### 1. Pachete de bază Python
Debian separă `venv` de Python, deci trebuie instalat explicit:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### 2. Uneltele de scanare
```bash
sudo apt install -y nmap nikto sqlmap
```

Metasploit nu este în repo-urile standard Debian — se instalează din installer-ul oficial Rapid7:
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod +x /tmp/msfinstall && sudo /tmp/msfinstall
```

**Vigolium** (opțional) — scanner web modern în Go, din installer-ul oficial:
```bash
curl -fsSL https://vigolium.com/install.sh | bash
```

### 3. Proiectul
```bash
git clone <URL-REPO>
cd OWASP-Scanner-Python
```

La **prima rulare**, `run.sh` creează automat mediul virtual, instalează dependențele
Python și browserul Chromium pentru Playwright. Nu trebuie să faci nimic manual.

Dacă vrei totuși setup manual:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

### 4. Dependențe de sistem pentru Playwright (login prin browser)
Pe Debian, Chromium headless are nevoie de câteva librării. Dacă login-ul prin browser
dă erori de dependențe, rulează o singură dată:
```bash
venv/bin/python -m playwright install-deps chromium
```

---

## Pornire

### Varianta 1 — o comandă (recomandat)
```bash
./run.sh
```
Scriptul își face singur setup-ul la prima rulare, verifică uneltele și deschide
aplicația în browser la **http://localhost:8501**.

### Varianta 2 — scurtătură în meniul de aplicații
```bash
cp vms.desktop ~/.local/share/applications/
```
Apoi pornești „Advanced VMS" din meniu.

### Varianta 3 — manual
```bash
source venv/bin/activate
streamlit run dashboard.py
```

Oprire: `Ctrl+C` în terminal.

---

## Funcționalități

Interfața are 5 tab-uri:

| Tab | Descriere |
|-----|-----------|
| **1. Recon (Nmap)** | Scanare porturi (fast / deep / service detection) + scripturi `vuln` NSE. Rezultatele se salvează în baza de date. |
| **2. Assets** | Toate țintele scanate, porturile și vulnerabilitățile salvate; raport PDF și ștergere per țintă. |
| **3. Metasploit** | Status + start/stop daemon. Recomandări de module pe baza porturilor găsite de Nmap, catalog de verificări cu nume prietenoase pe categorii, căutare avansată. |
| **4. Atac Web (+Auth)** | Nikto + SQLMap + **Vigolium** cu **autentificare**: cookie, Basic, headers, login prin formular (auto-CSRF) și login prin browser headless (Playwright, pentru aplicații SPA/JS). Sesiunea se capturează și se refolosește automat. |
| **5. Raportare** | Raport PDF/CSV per-țintă selectabilă + raport consolidat pe toate țintele, cu filtre pe severitate și tool. |

### Metasploit RPC
Pornește daemon-ul din bara laterală (**🔌 Start MSF**). Rulează pe `127.0.0.1:55553`
cu parola setată în `dashboard.py` (`MSF_PASSWORD`). Pe unele instalări poate necesita `sudo`.

---

## Structura proiectului

```
.
├── dashboard.py            # Interfața web Streamlit (punct de intrare principal)
├── main.py                 # Interfață CLI (Typer) – scanare Nmap din terminal
├── run.sh                  # Launcher: setup automat + pornire
├── vms.desktop             # Scurtătură de meniu
├── requirements.txt
├── core/
│   ├── models.py           # Modele Pydantic (Target, AuthConfig, VulnerabilityResult)
│   ├── database.py         # SQLite: ținte, porturi, vulnerabilități, sesiuni
│   ├── auth_session.py     # Motor de autentificare (requests + Playwright)
│   └── report_generator.py # Rapoarte PDF (per-țintă și global)
└── modules/
    ├── base.py             # Clasa de bază pentru scannere
    ├── recon_nmap.py       # Nmap
    ├── web_nikto.py        # Nikto (cu suport SSL + cookie)
    ├── web_sql.py          # SQLMap (cu autentificare)
    ├── web_vigolium.py     # Vigolium (Native Scan, JSONL)
    └── msf_scanner.py      # Integrare Metasploit RPC
```

Baza de date SQLite (`vulnscan.db`) se creează automat la prima rulare.

---

## Depanare

| Problemă | Soluție |
|----------|---------|
| `streamlit: command not found` | Ești în venv-ul greșit. Folosește `./run.sh` sau `venv/bin/streamlit run dashboard.py`. |
| `AttributeError` după modificări în `core/` | Repornește complet aplicația (`Ctrl+C` + din nou) — Streamlit nu reîncarcă mereu modulele importate. |
| `python3 -m venv` eșuează | `sudo apt install python3-venv`. |
| Login prin browser dă erori de librării | `venv/bin/python -m playwright install-deps chromium`. |
| Metasploit RPC rămâne OFFLINE | Pornește-l manual: `msfrpcd -P <parola> -a 127.0.0.1`; poate necesita `sudo`. |
| O țintă nu răspunde | Verifică conectivitatea (`curl`/`ping`) și dacă ținta e în spatele unui CDN (Cloudflare). |
