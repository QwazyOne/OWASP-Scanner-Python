from fpdf import FPDF
from datetime import datetime

class AuditReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(41, 128, 185)
        # Am eliminat diacriticele din titlu
        self.cell(0, 10, "Raport de Securitate", border=False, align="C")
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Pagina {self.page_no()} / {{nb}} | OWASP Automation Framework", align="C")

def clean_text(text):
    """
    Transforma caracterele romanesti in echivalentele lor Latin-1 
    pentru a evita crash-ul fontului Helvetica.
    """
    if not text:
        return ""
    
    replacements = {
        "ț": "t", "Ț": "T",
        "ș": "s", "Ș": "S",
        "ă": "a", "Ă": "A",
        "î": "i", "Î": "I",
        "â": "a", "Â": "A",
        "„": '"', "”": '"', "–": "-"
    }
    for original, replacement in replacements.items():
        text = text.replace(original, replacement)
    
    # Inlaturam orice alt caracter non-latin-1 ramas
    return text.encode('latin-1', 'replace').decode('latin-1')

def get_remediation(vuln_name, tool):
    """Recomandari fara diacritice pentru compatibilitate PDF."""
    name = vuln_name.lower()
    if "sql" in name or "injection" in name:
        return "RECOMANDARE: Utilizati interogari parametrizate (Prepared Statements), implementati validarea stricta a intrarilor si utilizati un WAF."
    if "http_version" in name or "nginx" in name or "apache" in name:
        return "RECOMANDARE: Versiunea serverului a fost expusa. Actualizati software-ul la ultima versiune stabila si dezactivati 'Server Tokens'."
    if "dir_listing" in name:
        return "RECOMANDARE: Dezactivati optiunea 'Directory Browsing' din configuratia serverului web."
    if tool == "sqlmap":
        return "RECOMANDARE CRITICA: S-au detectat puncte de injectie active. Revizuiti codul sursa al aplicatiei imediat."
    return "RECOMANDARE: Efectuati o analiza manuala detaliata si aplicati patch-urile de securitate specifice."

def generate_pdf_bytes(db_manager, target_id: int) -> bytes:
    targets = db_manager.get_all_targets()
    target_info = next((t for t in targets if t['id'] == target_id), None)
    if not target_info: return b""
        
    ports = db_manager.get_ports_for_target(target_id)
    vulns = db_manager.get_vulnerabilities_for_target(target_id)

    pdf = AuditReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # 1. DETALII TINTA
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, clean_text("1. Informatii Identificare Tinta"), ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 6, clean_text(f"Host Principal: {target_info['host']}"), ln=True)
    pdf.cell(0, 6, clean_text(f"Data Generare: {datetime.now().strftime('%Y-%m-%d %H:%M')}"), ln=True)
    pdf.ln(5)

    # 2. EXECUTIVE SUMMARY
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, clean_text("2. Rezumat Executiv"), ln=True)
    pdf.set_font("Helvetica", "", 11)
    
    crit_count = sum(1 for v in vulns if str(v['severity']).upper() == 'CRITICAL')
    
    summary_text = f"In urma testelor asupra {target_info['host']}, s-au identificat {len(vulns)} vulnerabilitati."
    if crit_count > 0:
        summary_text += " ATENTIE: Au fost detectate probleme CRITICE care necesita remediere imediata."
    pdf.multi_cell(0, 6, clean_text(summary_text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # 3. PORTURI
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, clean_text("3. Analiza Porturilor si Serviciilor"), ln=True)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(30, 8, "Port", border=1, align="C")
    pdf.cell(40, 8, "Stat", border=1, align="C")
    pdf.cell(120, 8, "Serviciu", border=1, align="C")
    pdf.ln()
    pdf.set_font("Helvetica", "", 10)
    for p in ports:
        p_name = p.get('service_name') or p.get('service') or "Unknown"
        pdf.cell(30, 8, str(p.get('port', 'N/A')), border=1, align="C")
        pdf.cell(40, 8, str(p.get('state', 'N/A')), border=1, align="C")
        pdf.cell(120, 8, clean_text(str(p_name)[:60]), border=1, align="L")
        pdf.ln()

    # 4. VULNERABILITATI
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, clean_text("4. Constatari Tehnice si Recomandari"), ln=True)
    pdf.ln(5)

    if not vulns:
        pdf.cell(0, 10, "Nu s-au identificat vulnerabilitati majore.", ln=True)
    else:
        for idx, v in enumerate(vulns, 1):
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(0, 8, clean_text(f"Vulnerabilitate #{idx}: {v['name']}"), ln=True, fill=True)
            
            pdf.set_font("Helvetica", "", 10)
            sev = str(v['severity']).upper()
            if sev == 'CRITICAL': pdf.set_text_color(200, 0, 0)
            elif sev == 'HIGH': pdf.set_text_color(255, 100, 0)
            pdf.cell(40, 6, f"Severitate: {sev}", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5, clean_text(f"Detalii: {v['details']}"), wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT")
            
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(46, 139, 87)
            remed = get_remediation(v['name'], v['tool'])
            pdf.multi_cell(0, 5, clean_text(remed), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)

    return bytes(pdf.output())


def generate_global_pdf_bytes(db_manager) -> bytes:
    """Raport agregat: toate vulnerabilitatile din toate tintele scanate."""
    targets = db_manager.get_all_targets()

    pdf = AuditReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # 1. REZUMAT GLOBAL
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {s: 0 for s in sev_order}
    total_vulns = 0
    for t in targets:
        for v in db_manager.get_vulnerabilities_for_target(t['id']):
            total_vulns += 1
            sev = str(v['severity']).upper()
            counts[sev] = counts.get(sev, 0) + 1

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, clean_text("1. Rezumat Executiv Global"), ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(0, 6, clean_text(
        f"Au fost analizate {len(targets)} tinte, identificand in total {total_vulns} "
        f"vulnerabilitati. Distributia pe severitate este prezentata mai jos."),
        new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Tabel distributie severitate
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(60, 8, "Severitate", border=1, align="C")
    pdf.cell(40, 8, "Numar", border=1, align="C")
    pdf.ln()
    pdf.set_font("Helvetica", "", 10)
    colors = {"CRITICAL": (200, 0, 0), "HIGH": (255, 100, 0),
              "MEDIUM": (230, 180, 0), "LOW": (46, 139, 87), "INFO": (100, 100, 100)}
    for s in sev_order:
        r, g, b = colors[s]
        pdf.set_text_color(r, g, b)
        pdf.cell(60, 8, s, border=1, align="L")
        pdf.cell(40, 8, str(counts.get(s, 0)), border=1, align="C")
        pdf.ln()
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # 2. DETALII PE FIECARE TINTA
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, clean_text("2. Constatari pe Tinte"), ln=True)
    pdf.ln(2)

    for t in targets:
        vulns = db_manager.get_vulnerabilities_for_target(t['id'])
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(41, 128, 185)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, clean_text(f"Tinta: {t['host']}  ({len(vulns)} vulnerabilitati)"),
                 ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)

        if not vulns:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "Nu s-au identificat vulnerabilitati confirmate.", ln=True)
            pdf.ln(3)
            continue

        for idx, v in enumerate(vulns, 1):
            pdf.set_font("Helvetica", "B", 10)
            sev = str(v['severity']).upper()
            r, g, b = colors.get(sev, (0, 0, 0))
            pdf.set_text_color(r, g, b)
            pdf.multi_cell(0, 6, clean_text(f"[{sev}] {idx}. {v['name']} ({v['tool']})"), wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5, clean_text(f"Detalii: {str(v['details'])[:600]}"), wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        pdf.ln(3)

    return bytes(pdf.output())