"""Testes do cliente MalwareBazaar em modo real (HTTP mockado com respx)."""
from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest
import respx

from app.mb_client import MalwareBazaarClient, MBAuthError, MBError

from .conftest import TARGET_HASH, make_settings

URL = "https://mb-api.abuse.ch/api/v1/"


@pytest.fixture
def real_mb(tmp_path) -> MalwareBazaarClient:
    return MalwareBazaarClient(make_settings(str(tmp_path / "x.db"), mb_api_key="mb-key"))


@respx.mock
async def test_get_info_ok(real_mb: MalwareBazaarClient) -> None:
    route = respx.post(URL).mock(
        return_value=httpx.Response(
            200, json={"query_status": "ok", "data": [{"sha256_hash": TARGET_HASH, "signature": "Phexia"}]}
        )
    )
    info = await real_mb.get_info(TARGET_HASH)
    request = route.calls[0].request
    assert request.headers["Auth-Key"] == "mb-key"
    assert parse_qs(request.content.decode()) == {"query": ["get_info"], "hash": [TARGET_HASH]}
    assert info is not None and info["data"]["signature"] == "Phexia"
    assert real_mb.source == "malwarebazaar"


@respx.mock
async def test_hash_not_found_returns_none(real_mb: MalwareBazaarClient) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"query_status": "hash_not_found"}))
    assert await real_mb.get_info(TARGET_HASH) is None


@pytest.mark.parametrize(
    ("response", "exc"),
    [
        (httpx.Response(200, json={"query_status": "unknown_auth_key"}), MBAuthError),
        (httpx.Response(401, text="unauthorized"), MBAuthError),
        (httpx.Response(200, json={"query_status": "illegal_hash"}), MBError),
        (httpx.Response(502, text="bad gateway"), MBError),
        (httpx.Response(200, text="<html>not json</html>"), MBError),
    ],
)
@respx.mock
async def test_error_mapping(real_mb: MalwareBazaarClient, response: httpx.Response, exc: type[Exception]) -> None:
    respx.post(URL).mock(return_value=response)
    with pytest.raises(exc):
        await real_mb.get_info(TARGET_HASH)


@respx.mock
async def test_network_error(real_mb: MalwareBazaarClient) -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(MBError):
        await real_mb.get_info(TARGET_HASH)


@pytest.mark.parametrize(
    ("overrides", "mode"),
    [
        ({}, "mock"),  # app todo simulado
        ({"vt_api_key": "k", "vt_mock": False}, "disabled"),  # VT real sem chave do MB
        ({"vt_api_key": "k", "vt_mock": False, "mb_api_key": "m"}, "real"),
        ({"mb_api_key": "m", "mb_mock": True}, "mock"),
    ],
)
async def test_modes(tmp_path, overrides: dict, mode: str) -> None:
    client = MalwareBazaarClient(make_settings(str(tmp_path / "m.db"), **overrides))
    assert client.mode == mode
    if mode == "disabled":
        assert await client.get_info(TARGET_HASH) is None
