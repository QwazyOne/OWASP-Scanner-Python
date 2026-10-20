#!/usr/bin/env bash
#
# Launcher pentru Advanced VMS - porneste aplicatia fara VS Code.
# Isi face singur setup-ul la prima rulare (venv + dependente + Playwright).
#
# Folosire:  ./run.sh
#
set -e

# Ne mutam in folderul scriptului, indiferent de unde e apelat
cd "$(dirname "$(readlink -f "$0")")"

VENV_DIR="venv"
PYTHON_BIN="python3"

echo "==> Advanced VMS - pornire"

# 1. Cream venv-ul daca lipseste
if [ ! -x "$VENV_DIR/bin/streamlit" ]; then
    echo "==> Prima rulare: configurez mediul (dureaza cateva minute)..."
    if [ ! -d "$VENV_DIR" ]; then
        "$PYTHON_BIN" -m venv "$VENV_DIR"
    fi
    "$VENV_DIR/bin/python" -m pip install --upgrade pip -q
    "$VENV_DIR/bin/pip" install -r requirements.txt
    # Browserul pentru login-ul Playwright (login in aplicatii SPA/JS)
    "$VENV_DIR/bin/python" -m playwright install chromium || \
        echo "!! Playwright chromium nu s-a instalat (login prin browser va fi indisponibil)."
fi

# 2. Avertizam daca lipsesc uneltele de sistem
echo "==> Verific uneltele de scanare:"
for tool in nmap nikto sqlmap msfrpcd; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "   [OK]   $tool"
    else
        echo "   [LIPSA] $tool  (instaleaza cu: sudo apt install $tool)"
    fi
done

# 3. Pornim aplicatia si deschidem browserul
echo "==> Deschid aplicatia in browser: http://localhost:8501"
exec "$VENV_DIR/bin/streamlit" run dashboard.py --server.headless false
