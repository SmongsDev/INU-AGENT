import pytest
from agents.rag.supabase_client import get_supabase_client
from supabase.client import Client
import os

def test_get_supabase_client_env(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://dummy.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "dummy-key")
    client = get_supabase_client()
    assert isinstance(client, Client)

def test_get_supabase_client_no_env(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
    with pytest.raises(ValueError):
        get_supabase_client()
