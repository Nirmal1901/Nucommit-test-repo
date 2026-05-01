"""
Basic tests for trading_engine.py
These tests will run in the Jenkins pipeline (pytest stage).
Some tests are intentionally minimal — the real value is SENTINEL's scan.
"""

import pytest
from unittest.mock import patch, MagicMock


# ── trading_engine tests ──────────────────────────────────────────────────────

def test_calculate_pnl_basic():
    from trading_engine import calculate_pnl
    trades = [{"pnl": 100}, {"pnl": 200}, {"pnl": -50}]
    result = calculate_pnl(trades)
    assert result == pytest.approx(83.33, rel=0.01)


def test_calculate_pnl_empty_raises():
    from trading_engine import calculate_pnl
    with pytest.raises(ZeroDivisionError):
        calculate_pnl([])


def test_hash_client_id_returns_string():
    from trading_engine import hash_client_id
    result = hash_client_id("CLIENT-001")
    assert isinstance(result, str)
    assert len(result) == 32   # MD5 hex digest length


def test_execute_large_trade_returns_dict():
    from trading_engine import execute_large_trade
    with patch("trading_engine.sqlite3.connect") as mock_conn:
        mock_conn.return_value.execute.return_value = MagicMock()
        mock_conn.return_value.commit.return_value = None
        result = execute_large_trade("ORD-001", 100, 50.0)
    assert result["status"] == "executed"
    assert result["value"] == 5000.0


def test_fetch_market_data_calls_url():
    from trading_engine import fetch_market_data
    with patch("trading_engine.requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"price": 100}
        result = fetch_market_data("http://example.com/data")
    assert result["price"] == 100


# ── order_manager tests ───────────────────────────────────────────────────────

def test_verify_token_invalid_returns_none():
    from order_manager import verify_token
    result = verify_token("not-a-valid-token")
    assert result is None


def test_create_and_verify_token():
    from order_manager import create_token, verify_token
    token = create_token("user-123", "trader")
    result = verify_token(token)
    assert result is not None
    assert result["user_id"] == "user-123"
    assert result["role"] == "trader"


def test_redirect_to_dashboard():
    from order_manager import redirect_to_dashboard
    result = redirect_to_dashboard("http://dashboard.internal/home")
    assert "redirect" in result


def test_update_position_basic():
    from order_manager import update_position, _position
    import order_manager
    order_manager._position = 0
    update_position(100)
    assert order_manager._position == 100
    update_position(-30)
    assert order_manager._position == 70
