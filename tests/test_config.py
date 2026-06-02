import pytest


@pytest.mark.asyncio
async def test_config_page(client):
    response = await client.get("/config/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Notification Routing Configuration" in response.text


@pytest.mark.asyncio
async def test_upsert_routing_config(client):
    response = await client.put(
        "/api/config/routing/ciso",
        json={"role": "ciso", "email_address": "ciso@example.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "ciso"
    assert data["email_address"] == "ciso@example.com"


@pytest.mark.asyncio
async def test_list_routing_configs(client):
    await client.put(
        "/api/config/routing/ciso",
        json={"role": "ciso", "email_address": "ciso@example.com"},
    )
    await client.put(
        "/api/config/routing/devlead",
        json={"role": "devlead", "email_address": "devlead@example.com"},
    )
    response = await client.get("/api/config/routing")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


@pytest.mark.asyncio
async def test_delete_routing_config(client):
    await client.put(
        "/api/config/routing/ciso",
        json={"role": "ciso", "email_address": "ciso@example.com"},
    )
    response = await client.delete("/api/config/routing/ciso")
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_delete_nonexistent(client):
    response = await client.delete("/api/config/routing/nonexistent")
    assert response.status_code == 404
