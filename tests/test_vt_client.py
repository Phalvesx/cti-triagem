"""Testes do cliente VirusTotal em modo real (HTTP mockado com respx)."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.vt_client import VirusTotalClient, VTAuthError, VTError, VTNotFoundError, VTRateLimitError

from .conftest import TARGET_HASH, make_settings

BASE = "https://www.virustotal.com/api/v3"


@pytest.fixture
def real_client(tmp_path) -> VirusTotalClient:
    return VirusTotalClient(make_settings(str(tmp_path / "x.db"), vt_api_key="k", vt_mock=False))


@respx.mock
async def test_file_report_with_relationships(real_client: VirusTotalClient) -> None:
    route = respx.get(f"{BASE}/files/{TARGET_HASH}").mock(
        return_value=httpx.Response(200, json={"data": {"id": TARGET_HASH, "attributes": {}}})
    )
    respx.get(f"{BASE}/files/{TARGET_HASH}/contacted_domains").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "evil.com", "type": "domain"}]})
    )
    respx.get(f"{BASE}/files/{TARGET_HASH}/contacted_ips").mock(
        return_value=httpx.Response(403, json={"error": {"code": "ForbiddenError", "message": "premium"}})
    )
    respx.get(f"{BASE}/files/{TARGET_HASH}/contacted_urls").mock(return_value=httpx.Response(200, json={"data": []}))

    report = await real_client.get_file_report(TARGET_HASH)
    assert route.calls[0].request.headers["x-apikey"] == "k"
    assert report["relationships"]["contacted_domains"][0]["id"] == "evil.com"
    assert report["relationships"]["contacted_ips"] == []  # erro de relacionamento é tolerado
    assert real_client.source == "virustotal"


@pytest.mark.parametrize(
    ("status", "exc"),
    [(404, VTNotFoundError), (429, VTRateLimitError), (401, VTAuthError), (500, VTError)],
)
@respx.mock
async def test_error_mapping(real_client: VirusTotalClient, status: int, exc: type[Exception]) -> None:
    respx.get(f"{BASE}/domains/evil.com").mock(
        return_value=httpx.Response(status, json={"error": {"code": "X", "message": "y"}})
    )
    with pytest.raises(exc):
        await real_client.get_domain_report("evil.com")


@respx.mock
async def test_network_error(real_client: VirusTotalClient) -> None:
    respx.get(f"{BASE}/ip_addresses/1.1.1.1").mock(side_effect=httpx.ConnectTimeout("timeout"))
    with pytest.raises(VTError):
        await real_client.get_ip_report("1.1.1.1")


async def test_mock_mode_without_key(tmp_path) -> None:
    client = VirusTotalClient(make_settings(str(tmp_path / "m.db")))
    assert client.source == "mock"
    assert (await client.get_file_report(TARGET_HASH))["_simulated"] is True
    with pytest.raises(VTNotFoundError):
        await client.get_file_report("0" * 64)
