from app.utils.user_logic import authenticate_user, sign_up_user
import pytest
from app.schemas import user_schema
from app.db.db_connection import get_async_db
from app.schemas import user_schema
from app.utils.user_logic import get_current_user
from fastapi.security import SecurityScopes
import pytest


@pytest.mark.asyncio
async def test_authenticate_user():
    db = await anext(get_async_db())
    try:
        response = await authenticate_user(
            async_session=db,
            username="gigi",
            password="gigi123",
            scopes=["user"],
        )

        assert response.username == "gigi"
        assert response.is_active == True
    finally:
        await db.aclose()


@pytest.mark.asyncio
async def test_sign_up_user():
    db = await anext(get_async_db())
    try:
        data = user_schema.UserSchemaIn(username="lsdawa", password="ladudra123", scopes="user")
        response = await sign_up_user(user_data=data, async_session=db)
        assert response.success == "your account has been created."
        assert isinstance(response, user_schema.UserSchemaOut) == True
    finally:
        await db.aclose()



 
security = SecurityScopes(scopes=['user'])
@pytest.mark.asyncio
async def test_get_current_user():
    db = await anext(get_async_db())
    try:
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnaWdpIiwic2NvcGVzIjpbInVzZXIiXSwiZXhwIjoxNzU2NzI1MDQxfQ.--vgkLzF__phY--yiZivrMVhqAQq-hZdrcoFNeJEggo'
        response = await get_current_user(token=token,security_scopes=security, async_session=db)
        assert response.username == 'gigi'
    finally:
        await db.aclose()
