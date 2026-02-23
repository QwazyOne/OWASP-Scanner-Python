import sqlite3
import os
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="vulnscan.db"):
        self.db_path = os.path.join(os.getcwd(), db_name)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT UNIQUE NOT NULL,
                last_scanned TEXT
            )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                port INTEGER,
                service TEXT,
                state TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                tool TEXT,
                vuln_name TEXT,
                severity TEXT,
                details TEXT,
                timestamp TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )''')
        conn.commit()
        conn.close()

    # --- SCRIERE ---
    def add_target(self, host: str):
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('INSERT OR IGNORE INTO targets (host, last_scanned) VALUES (?, ?)', (host, now))
        cursor.execute('UPDATE targets SET last_scanned = ? WHERE host = ?', (now, host))
        cursor.execute('SELECT id FROM targets WHERE host = ?', (host,))
        target_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return target_id

    def add_port(self, target_id: int, port: int, service: str, state: str):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM ports WHERE target_id = ? AND port = ?', (target_id, port))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO ports (target_id, port, service, state) VALUES (?, ?, ?, ?)', 
                           (target_id, port, service, state))
        conn.commit()
        conn.close()

    # --- CITIRE ---
    def get_all_targets(self):
        """Returnează toate țintele scanate vreodată."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, host, last_scanned FROM targets ORDER BY last_scanned DESC')
        rows = cursor.fetchall()
        conn.close()
        return [{"id": r[0], "host": r[1], "last_scanned": r[2]} for r in rows]

    def get_ports_for_target(self, target_id: int):
        """Returnează porturile deschise pentru o țintă."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT port, service, state FROM ports WHERE target_id = ? ORDER BY port ASC', (target_id,))
        rows = cursor.fetchall()
        conn.close()
        return [{"port": r[0], "service": r[1], "state": r[2]} for r in rows]
    # --- VULNERABILITĂȚI (SCRIERE ȘI CITIRE) ---
    def add_vulnerability(self, target_id: int, tool: str, vuln_name: str, severity: str, details: str):
        """Salvează o vulnerabilitate confirmată în baza de date."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Verificăm să nu o duplicăm (dacă scanezi de 2 ori același lucru)
        cursor.execute('SELECT id FROM vulnerabilities WHERE target_id = ? AND vuln_name = ?', (target_id, vuln_name))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO vulnerabilities (target_id, tool, vuln_name, severity, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (target_id, tool, vuln_name, severity, details, now))
        conn.commit()
        conn.close()

    def get_vulnerabilities_for_target(self, target_id: int):
        """Extrage toate vulnerabilitățile reale ale unei ținte."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT tool, vuln_name, severity, details, timestamp FROM vulnerabilities WHERE target_id = ? ORDER BY timestamp DESC', (target_id,))
        rows = cursor.fetchall()
        conn.close()
        return [{"tool": r[0], "name": r[1], "severity": r[2], "details": r[3], "timestamp": r[4]} for r in rows]
        
    # --- ȘTERGERE ---
    def delete_target(self, target_id: int):
        """Șterge un proiect (ținta) și toate datele asociate (porturi, vulns)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        # Ștergem în cascadă ca să nu lăsăm "gunoi" în baza de date
        cursor.execute('DELETE FROM ports WHERE target_id = ?', (target_id,))
        cursor.execute('DELETE FROM vulnerabilities WHERE target_id = ?', (target_id,))
        cursor.execute('DELETE FROM targets WHERE id = ?', (target_id,))
        conn.commit()
        conn.close()