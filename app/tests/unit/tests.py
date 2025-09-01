from app.utils.user_logic import create_access_token
from datetime import timedelta



def test_create_access_token():
    expires = timedelta(minutes=20)
    data = {"sub": "gigi", "scopes": ["user"]}

    result = create_access_token(data=data, expires_delta=expires)
    assert isinstance(result, str) == True
    assert result.startswith("ey") == True


