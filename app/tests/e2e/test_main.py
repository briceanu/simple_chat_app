import pytest
import httpx
 

PREFIX = "http://localhost:8000/api/v1/user"

@pytest.mark.asyncio
async def test_sign_up_user():
    data = {'username':'gsswdfoiegd','password':'apw12f1','scopes':'user'}
    async with httpx.AsyncClient() as client:
        response = await  client.post(f"{PREFIX}/sign-up", json=data)

        assert response.status_code == 201
        assert response.json()["success"] == "your account has been created."


@pytest.mark.asyncio
async def test_get_new_access_token_from_refresh_token():
    refresh_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnaWdpIiwic2NvcGVzIjpbInVzZXIiXSwiZXhwIjoxNzU2NzQxODgzLCJqdGkiOiIwZDEyMTIxOC03ZTczLTRkMWItYTIzYS02ZGQzOWY3NmEyMTgifQ.MsL_XJdG067PzClXHcEZmSnRQtQLr_znFkH5XGnFCKc"
    headers = {"refresh-token": refresh_token}

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{PREFIX}/new-access-token", headers=headers)

        assert response.status_code == 200
        assert "access_token" in response.json()
        assert isinstance(response.json()["access_token"], str) == True
        assert response.json()["access_token"].startswith("ey")
