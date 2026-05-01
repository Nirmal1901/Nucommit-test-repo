"""
Order Management System
Capital Markets — SENTINEL test target (intentionally vulnerable)
"""

import sqlite3
import jwt
import os

# ── VULNERABILITY: JWT with hardcoded secret + no expiry check ───────────────
JWT_SECRET = "super-secret-trading-key-123"   # DANGER: hardcoded

def verify_token(token):
    """Verify JWT — VULNERABLE: no expiry, weak secret, no alg check."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None   # DANGER: silently returns None on invalid token


def create_token(user_id, role):
    """Create JWT — VULNERABLE: no expiry set."""
    return jwt.encode({"user_id": user_id, "role": role}, JWT_SECRET)


# ── VULNERABILITY: Path traversal ────────────────────────────────────────────
def get_client_doc(filename):
    """Get client document — VULNERABLE: path traversal."""
    base_path = "/var/app/client_docs/"
    return open(base_path + filename).read()   # DANGER: ../../etc/passwd


# ── VULNERABILITY: Race condition on shared position ─────────────────────────
_position = 0

def update_position(delta):
    """Update position — VULNERABLE: race condition, no lock."""
    global _position
    current = _position          # read
    current += delta             # modify — another thread can interleave here
    _position = current          # write


# ── VULNERABILITY: SQL injection in order book ───────────────────────────────
def cancel_order(order_id, reason):
    conn = sqlite3.connect("orders.db")
    conn.execute(f"UPDATE orders SET status='CANCELLED', reason='{reason}' WHERE id={order_id}")
    conn.commit()


# ── VULNERABILITY: Unvalidated redirect ──────────────────────────────────────
def redirect_to_dashboard(next_url):
    """VULNERABLE: open redirect — no validation of next_url."""
    return {"redirect": next_url}   # attacker can set next_url=https://evil.com
