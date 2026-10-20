"""
Motor de sesiune autentificata (ca la scannerele dinamice gen AppScan/ZAP).

Gestioneaza intern un cookie jar (requests.Session), face login prin formular
cu extragerea automata a token-ului CSRF, si produce o configuratie de
autentificare (cookie) pe care o pot refolosi SQLMap, Nikto si Metasploit.

NU foloseste browser extern si NU foloseste proxy - totul se intampla in proces.
"""
import re
import requests
from typing import Optional, Tuple, List
from urllib.parse import urljoin

from core.models import AuthConfig, AuthType

# Dezactivam avertismentele pentru certificate self-signed (tinte de test)
try:
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    pass

# Nume frecvente de campuri ascunse pentru token-ul CSRF, pe framework-uri diferite
CSRF_FIELD_NAMES = [
    "user_token",              # DVWA
    "csrf_token", "_csrf", "_token",
    "authenticity_token",      # Rails
    "csrfmiddlewaretoken",     # Django
    "__RequestVerificationToken",  # ASP.NET
    "csrf", "xsrf", "_csrf_token",
]

# Indicii ca suntem autentificati / neautentificati (in-session detection)
LOGGED_IN_HINTS = ["logout", "log out", "sign out", "my account", "dashboard"]
LOGIN_FAIL_HINTS = ["login failed", "incorrect", "invalid credentials",
                    "authentication failed", "wrong password", "username and/or password"]


class WebAuthenticator:
    def __init__(self, verify_ssl: bool = False, timeout: int = 20):
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (VMS-Scanner authenticated session)"
        })
        self.timeout = timeout
        self.logged_in = False
        self.log: List[str] = []

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------
    def authenticate(self, auth: AuthConfig) -> bool:
        """Aplica orice tip de autentificare si retine sesiunea rezultata."""
        try:
            if auth.auth_type == AuthType.COOKIE and auth.cookie:
                self._apply_cookie_string(auth.cookie)
                self.logged_in = True
                self.log.append("Cookie de sesiune aplicat direct.")
                return True

            if auth.auth_type == AuthType.BASIC and auth.username:
                self.session.auth = (auth.username, auth.password or "")
                self.logged_in = True
                self.log.append(f"HTTP Basic Auth setat pentru '{auth.username}'.")
                return True

            if auth.auth_type == AuthType.HEADER and auth.headers:
                for line in auth.headers.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        self.session.headers[k.strip()] = v.strip()
                self.logged_in = True
                self.log.append("Headers custom aplicate.")
                return True

            if auth.auth_type == AuthType.FORM:
                return self._form_login(auth)

            self.log.append("Niciun tip de autentificare activ.")
            return False
        except requests.RequestException as e:
            self.log.append(f"Eroare de retea la autentificare: {e}")
            return False

    def _form_login(self, auth: AuthConfig) -> bool:
        if not auth.login_url or not auth.login_data:
            self.log.append("Login prin formular necesita login_url si login_data.")
            return False

        # 1. GET pagina de login -> primim cookie-ul initial + token CSRF
        r = self.session.get(auth.login_url, timeout=self.timeout)
        self.log.append(f"GET {auth.login_url} -> {r.status_code}")
        token_name, token_val = self._find_csrf(r.text)

        # 2. construim datele de POST din login_data ("user=a&pass=b")
        data = {}
        for pair in auth.login_data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                data[k] = v

        # 3. injectam automat token-ul CSRF daca exista si nu a fost dat deja
        if token_name and token_name not in data:
            data[token_name] = token_val
            self.log.append(f"Token CSRF detectat ('{token_name}') si inclus automat.")

        # 4. POST login
        r2 = self.session.post(auth.login_url, data=data,
                               timeout=self.timeout, allow_redirects=True)
        self.log.append(f"POST login -> {r2.status_code}")

        # 5. verificam daca suntem autentificati (in-session detection)
        self.logged_in = self._verify_session(r2)
        self.log.append("Autentificare REUSITA." if self.logged_in
                        else "Autentificare ESUATA (verifica user/parola/URL).")
        return self.logged_in

    # ------------------------------------------------------------------
    # Verificare sesiune activa (re-login daca a expirat)
    # ------------------------------------------------------------------
    def is_session_valid(self, check_url: str, success_regex: Optional[str] = None) -> bool:
        """Verifica daca sesiunea e inca valida pe o pagina protejata."""
        try:
            r = self.session.get(check_url, timeout=self.timeout)
            body = r.text.lower()
            if success_regex:
                return re.search(success_regex, r.text, re.I) is not None
            return any(h in body for h in LOGGED_IN_HINTS)
        except requests.RequestException:
            return False

    # ------------------------------------------------------------------
    # Helperi
    # ------------------------------------------------------------------
    def _apply_cookie_string(self, cookie_str: str):
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                self.session.cookies.set(k.strip(), v.strip())

    @staticmethod
    def _find_csrf(html: str) -> Tuple[Optional[str], Optional[str]]:
        """Extrage un token CSRF dintr-un input ascuns, indiferent de ordinea atributelor."""
        for name in CSRF_FIELD_NAMES:
            # name=... value=...
            m = re.search(
                r'name=["\']?' + re.escape(name) + r'["\']?[^>]*?value=["\']([^"\']*)["\']',
                html, re.I)
            if not m:
                # value=... name=...
                m = re.search(
                    r'value=["\']([^"\']*)["\'][^>]*?name=["\']?' + re.escape(name) + r'["\']?',
                    html, re.I)
            if m:
                return name, m.group(1)
        return None, None

    def _verify_session(self, resp: requests.Response) -> bool:
        body = resp.text.lower()
        if any(h in body for h in LOGIN_FAIL_HINTS):
            return False
        if any(h in body for h in LOGGED_IN_HINTS):
            return True
        # fallback: am primit cookie-uri si nu am ramas pe formularul de login
        return len(self.session.cookies) > 0 and "name='password'" not in body \
            and 'name="password"' not in body

    def cookie_string(self) -> str:
        """Cookie-urile capturate, in format 'a=1; b=2' - pentru SQLMap/Nikto."""
        return "; ".join(f"{c.name}={c.value}" for c in self.session.cookies)

    def to_auth_config(self) -> AuthConfig:
        """Transforma sesiunea capturata intr-un AuthConfig de tip COOKIE,
        refolosibil direct de scannere."""
        return AuthConfig(auth_type=AuthType.COOKIE, cookie=self.cookie_string())


class BrowserAuthenticator:
    """
    Login printr-un browser headless real (Playwright), pentru aplicatii
    moderne/SPA unde login-ul se face din JavaScript. Dupa autentificare
    extrage cookie-urile sesiunii, ca sa le refoloseasca SQLMap/Nikto.

    Necesita: pip install playwright && python -m playwright install chromium
    """
    def __init__(self, timeout: int = 30):
        self.timeout = timeout * 1000  # Playwright foloseste milisecunde
        self.logged_in = False
        self.log: List[str] = []
        self._cookies: List[dict] = []

    @staticmethod
    def is_available() -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def authenticate(self, auth: AuthConfig) -> bool:
        """Ruleaza login-ul intr-un thread dedicat: API-ul sync Playwright nu
        poate rula intr-un thread care are deja un event loop asyncio (Streamlit)."""
        import threading
        result = {}

        def _worker():
            result["ok"] = self._do_login(auth)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=(self.timeout / 1000) + 30)
        if t.is_alive():
            self.log.append("Login prin browser a depasit timpul alocat.")
            return False
        return result.get("ok", False)

    def _do_login(self, auth: AuthConfig) -> bool:
        if not auth.login_url:
            self.log.append("Login prin browser necesita un URL de login.")
            return False
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.log.append("Playwright nu e instalat: pip install playwright && "
                            "python -m playwright install chromium")
            return False

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx = browser.new_context(ignore_https_errors=True)
                page = ctx.new_page()

                self.log.append(f"Deschid {auth.login_url} in browser headless...")
                page.goto(auth.login_url, timeout=self.timeout)

                # Selectoare: folosim ce a dat userul, altfel auto-detectam
                user_sel = auth.user_selector or self._auto_user_selector(page)
                pass_sel = auth.pass_selector or "input[type=password]"
                submit_sel = auth.submit_selector or self._auto_submit_selector(page)

                if auth.username and user_sel:
                    page.fill(user_sel, auth.username)
                    self.log.append(f"Completat user ('{user_sel}').")
                if auth.password:
                    page.fill(pass_sel, auth.password)
                    self.log.append(f"Completat parola ('{pass_sel}').")

                if submit_sel:
                    page.click(submit_sel)
                    self.log.append(f"Trimis formularul ('{submit_sel}').")
                else:
                    page.keyboard.press("Enter")
                    self.log.append("Niciun buton submit gasit; am apasat Enter.")

                try:
                    page.wait_for_load_state("networkidle", timeout=self.timeout)
                except Exception:
                    pass

                # Verificare login reusit
                if auth.success_selector:
                    self.logged_in = page.locator(auth.success_selector).count() > 0
                else:
                    body = (page.content() or "").lower()
                    self.logged_in = any(h in body for h in LOGGED_IN_HINTS) \
                        or page.url != auth.login_url

                self._cookies = ctx.cookies()
                self.log.append(f"URL dupa login: {page.url}")
                self.log.append("Autentificare REUSITA." if self.logged_in
                                else "Login incert - verifica selectoarele sau datele.")
                browser.close()
            return self.logged_in
        except Exception as e:
            self.log.append(f"Eroare Playwright: {e}")
            return False

    @staticmethod
    def _auto_user_selector(page) -> Optional[str]:
        for sel in ["input[type=email]",
                    "input[name*=user i]", "input[name*=email i]", "input[name*=login i]",
                    "input[id*=user i]", "input[type=text]"]:
            try:
                if page.locator(sel).count() > 0:
                    return sel
            except Exception:
                continue
        return None

    @staticmethod
    def _auto_submit_selector(page) -> Optional[str]:
        for sel in ["button[type=submit]", "input[type=submit]",
                    "button:has-text('Login')", "button:has-text('Sign in')",
                    "button:has-text('Log in')"]:
            try:
                if page.locator(sel).count() > 0:
                    return sel
            except Exception:
                continue
        return None

    def cookie_string(self) -> str:
        return "; ".join(f"{c['name']}={c['value']}" for c in self._cookies)
