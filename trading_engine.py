"""
Capital Markets Trading Engine
WARNING: Intentionally vulnerable code for SENTINEL pipeline testing.
"""

import sqlite3
import os
import hashlib
import subprocess
import pickle
import requests


# ── VULNERABILITY 1: SQL Injection (OWASP A03, MiFID II) ──────────────────────
def get_trade_by_id(trade_id):
    """Fetch trade record — VULNERABLE: raw string interpolation → SQL injection."""
    conn = sqlite3.connect("trades.db")
    query = f"SELECT * FROM trades WHERE id = '{trade_id}'"   # DANGER
    return conn.execute(query).fetchone()


def search_orders(client_name, status):
    """Search orders — VULNERABLE: multiple injections."""
    conn = sqlite3.connect("trades.db")
    query = "SELECT * FROM orders WHERE client='" + client_name + "' AND status='" + status + "'"
    return conn.execute(query).fetchall()


# ── VULNERABILITY 2: Hardcoded Secrets (OWASP A02, PCI-DSS) ──────────────────
BLOOMBERG_API_KEY  = "blp-prod-a1b2c3d4e5f6g7h8"       # DANGER: hardcoded
REUTERS_SECRET     = "rtr-secret-xK9mP2qR5vN8wL1"      # DANGER: hardcoded
DB_PASSWORD        = "TradingDB@Prod#2024"               # DANGER: hardcoded
AWS_ACCESS_KEY     = "AKIAIOSFODNN7EXAMPLE"              # DANGER: hardcoded
AWS_SECRET         = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # DANGER


# ── VULNERABILITY 3: OS Command Injection (OWASP A01) ────────────────────────
def generate_report(report_name, date_range):
    """Generate trade report — VULNERABLE: unvalidated input to os.system."""
    os.system(f"generate_report.sh {report_name} {date_range}")             # DANGER
    subprocess.call(f"mail -s 'Report' compliance@firm.com < {report_name}", shell=True)  # DANGER


# ── VULNERABILITY 4: Insecure Deserialization (OWASP A08) ────────────────────
def load_trade_config(config_bytes):
    """Load config — VULNERABLE: pickle deserialization of untrusted data."""
    return pickle.loads(config_bytes)   # DANGER: arbitrary code execution


# ── VULNERABILITY 5: No Auth / Missing Access Control (MiFID II, SEBI) ───────
def execute_large_trade(order_id, quantity, price):
    """Execute trade — VULNERABLE: no authentication, no authorisation check."""
    # Should verify: user role, trade limits, client mandate
    total_value = quantity * price
    conn = sqlite3.connect("trades.db")
    conn.execute(
        f"INSERT INTO executions VALUES ('{order_id}', {quantity}, {price}, {total_value})"
    )
    conn.commit()
    return {"status": "executed", "order_id": order_id, "value": total_value}


# ── VULNERABILITY 6: Sensitive Data Exposure (PCI-DSS, DORA) ─────────────────
def log_payment(card_number, cvv, amount):
    """Log payment — VULNERABLE: logs raw card data."""
    print(f"Processing card: {card_number} CVV: {cvv} amount: {amount}")   # DANGER
    with open("/tmp/payments.log", "a") as f:
        f.write(f"card={card_number},cvv={cvv},amount={amount}\n")          # DANGER


# ── VULNERABILITY 7: Weak Cryptography (OWASP A02) ───────────────────────────
def hash_client_id(client_id):
    """Hash client ID — VULNERABLE: MD5 is cryptographically broken."""
    return hashlib.md5(client_id.encode()).hexdigest()   # DANGER: use SHA-256+


# ── VULNERABILITY 8: SSRF (OWASP A10) ────────────────────────────────────────
def fetch_market_data(data_url):
    """Fetch market data — VULNERABLE: unvalidated URL allows SSRF."""
    response = requests.get(data_url, timeout=10)   # DANGER: no URL validation
    return response.json()


# ── CODE SMELL: Division by zero, no error handling ──────────────────────────
def calculate_pnl(trades):
    total = sum(t["pnl"] for t in trades)
    return total / len(trades)   # BUG: ZeroDivisionError if trades is empty


def read_config(path):
    with open(path) as f:   # BUG: no exception handling
        return f.read()
# trigger Sat May  2 23:53:57 IST 2026
