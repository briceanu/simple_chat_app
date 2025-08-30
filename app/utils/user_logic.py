from app.schemas import user_schema
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
from sqlalchemy import insert
from app.models.user_model import User
from app.schemas import user_schema
from sqlalchemy.orm import load_only
from sqlalchemy import select
import os
from dotenv import load_dotenv
from datetime import timedelta, datetime, timezone
from fastapi.security import (
    OAuth2PasswordRequestForm,
    OAuth2PasswordBearer,
    SecurityScopes,
)
import jwt
from fastapi import HTTPException, status, Depends
import uuid
from typing import Annotated
from app.db.db_connection import get_async_db
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from pydantic import ValidationError

from app.utils.redis_client import redis_client


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


load_dotenv()


REFRESH_SECRET = os.getenv("REFRESH_SECRET")
SECRET = os.getenv("SECRET")
ALGORITHM = os.getenv("ALGORITHM")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/user/sign-in",
    scopes={"user": "user privileges", "admin": "admin privileges"},
)


async def authenticate_user(
    username: str, password: str, scopes: list[str], async_session: AsyncSession
) -> User | None:
    """
    Authenticate a user by verifying credentials and scopes.

    This function checks whether the given username exists, the password
    matches the stored hash, and the user has all required scopes.
    If all checks pass, the authenticated user object is returned.

    Args:
        username (str): The username of the user attempting to log in.
        password (str): The plain-text password to verify against the stored hash.
        scopes (list[str]): A list of required scopes for authorization.
        async_session (AsyncSession): SQLAlchemy async database session.

    Returns:
        User | None: The authenticated user object if valid;
        otherwise, `False`.

    Notes:
        - Returns `False` instead of `None` when authentication fails.
          Consider normalizing to `None` for clearer semantics.

    """

    user = (
        await async_session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if not user:
        return False
    if not pwd_context.verify(password, user.password):
        return False
    if not scopes:
        return False
    for scope in scopes:
        if scope not in user.scopes:
            return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Generates a JWT access token containing the provided user data.

    The token is encoded using a secret key and a specified algorithm,
    and includes an expiration time based on the given time delta.

    Args:
        expires_delta (timedelta): The duration after which the token should expire.
        data (dict): The payload data to include in the token (e.g., user identity).

    Returns:
        str: The encoded JWT access token.
    """
    to_encode = data.copy()
    expires = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expires})
    access_token = jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
    return access_token


def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Returns an refresh token after encoding the username, the secret,
    and the algorithm.
    The expiration time for the refresh token is longer than the access
    token
    """
    to_encode = data.copy()
    expires = datetime.now(timezone.utc) + expires_delta
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expires, "jti": jti})
    refresh_token = jwt.encode(to_encode, REFRESH_SECRET, algorithm=ALGORITHM)
    return refresh_token


async def sign_up_user(user_data: user_schema.UserSchemaIn, async_sesion: AsyncSession):
    stmt = insert(User).values(
        username=user_data.username,
        password=pwd_context.hash(user_data.password),
        is_active=True,
        scopes=user_data.scopes.value,
    )
    await async_sesion.execute(stmt)
    await async_sesion.commit()
    return user_schema.UserSchemaOut(success="your account has been created.")


async def sign_in_user(
    form_data: OAuth2PasswordRequestForm, async_session: AsyncSession
) -> user_schema.TokensSchemaOut:
    """
    Authenticate a user and generate JWT access and refresh tokens.

    - Verifies user credentials via `user_logic.authenticate_user`.
    - Raises HTTP 401 Unauthorized if authentication fails.
    - Creates an access token valid for 30 minutes and a refresh token valid for 8 hours.
    - Includes user scopes in the token payload for authorization purposes.

    Returns:
        Token: An object containing the bearer token type, access token, and refresh token.

    Raises:
        HTTPException: If username or password is invalid (401 Unauthorized).
    """
    unauthorized_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user = await authenticate_user(
        username=form_data.username,
        password=form_data.password,
        scopes=form_data.scopes,
        async_session=async_session,
    )
    if not user:
        raise unauthorized_exception

    data = {"sub": user.username, "scopes": [user.scopes]}

    access_token = create_access_token(data=data, expires_delta=timedelta(minutes=60))
    refresh_token = create_refresh_token(data=data, expires_delta=timedelta(hours=8))
    return user_schema.TokensSchemaOut(
        access_token=access_token, refresh_token=refresh_token
    )


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    security_scopes: SecurityScopes,
    async_session: AsyncSession = Depends(get_async_db),
) -> User | None:
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET, algorithms=ALGORITHM)
        username = payload.get("sub")
        if not username:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = user_schema.TokenData(scopes=token_scopes, username=username)
    except (InvalidTokenError, ValidationError):
        raise credentials_exception
    user_in_db = (
        await async_session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if not user_in_db:
        raise credentials_exception

    # Check if the user has at least one of the required scopes.
    # `security_scopes_set & user_scopes_set` computes the intersection of the two sets.
    # If the intersection is empty, the user has none
    # of the required permissions, so we raise an error.
    security_scopes_set = set(security_scopes.scopes)
    user_scopes_set = set(token_data.scopes)
    if not (security_scopes_set & user_scopes_set):  # intersection is empty
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": authenticate_value},
        )
    return user_in_db


def get_current_active_user(
    user: Annotated[User, Depends(get_current_user)],
):
    """
    Ensures the currently authenticated user is active.

    This function is typically used as a FastAPI dependency to enforce that
    only active users can access certain routes.

    Args:
        current_user (User): The authenticated user, provided by `get_current_user`.

    Returns:
        User: The current active user.

    Raises:
        HTTPException 400: If the user is not active.
    """

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive account"
        )
    return user


def black_list_token(jti: str, ttl: int) -> None:
    """
    blacklists the token using the token's id and setting
    and setting a time to live.
    """
    redis_client.setex(f"blacklist:{jti}", ttl, "true")


def is_token_blacklisted(jti: str) -> bool:
    """checks to see if the token is already blacklisted"""
    return redis_client.exists(f"blacklist:{jti}") == 1


async def logout(token: str) -> user_schema.LogoutSchema:
    """
    Logs out the user by blacklisting the provided JWT token.

    This function extracts the unique token identifier (JTI) from the given
    JWT, calculates its remaining time-to-live (TTL), and stores it in a
    Redis blacklist. This ensures that the token can no longer be used for
    authentication, effectively logging the user out.

    Args:
        token (str): The JWT access or refresh token to be invalidated.

    Returns:
        dict: A confirmation message indicating successful logout.

    Raises:
        HTTPException: If the token is invalid or malformed.
    """

    invalid_token = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token"
    )
    try:
        payload = jwt.decode(
            token,
            REFRESH_SECRET,
            algorithms=ALGORITHM,
        )
        jti = payload.get("jti")
        exp = payload.get("exp")
        if not jti or not exp:
            raise invalid_token

        if is_token_blacklisted(jti) == 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token already blacklisted",
            )

        ttl = exp - int(datetime.now(timezone.utc).timestamp())
        black_list_token(jti, ttl)
        return user_schema.LogoutSchema(success="Logged out successfully")
    except InvalidTokenError:
        raise invalid_token


async def access_token_from_refresh(
    refresh_token: str, async_session: AsyncSession
) -> user_schema.NewAccessToken:
    """
    Generate a new access token from a valid refresh token.

    This method performs the following steps:
    1. Decodes the provided refresh JWT token using the REFRESH_SECRET and algorithm.
    2. Validates the existence of the token's JWT ID (`jti`) and associated user (`sub`).
    3. Checks whether the refresh token has been blacklisted.
    4. Verifies that the token's scopes are present and still permitted for the user.
    5. Issues a new access token with the user's current scopes and returns it.

    Returns:
        NewAccessTokenResponseSchema: A Pydantic response schema containing the new access token.

    Raises:
        HTTPException (400): If the token is malformed or the user doesn't exist.
        HTTPException (401): If the token is expired, revoked, or permissions are insufficient.
    """
    try:
        payload = jwt.decode(
            refresh_token,
            REFRESH_SECRET,
            algorithms=ALGORITHM,
        )
        jti = payload.get("jti")
        token_scopes = payload.get("scopes", [])
        username = payload.get("sub")
        # If the token does not contain a jwt id or the user is
        # not a valid user saved in the db raise  400 error
        user_in_db = (
            await async_session.execute(
                select(User)
                .options(load_only(User.username, User.scopes))
                .where(User.username == username)
            )
        ).scalar_one_or_none()
        if not jti or not user_in_db:
            raise HTTPException(status_code=400, detail="Invalid refresh token")

        if is_token_blacklisted(jti) == 1:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        if not token_scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
            )
        for scope in token_scopes:
            if scope not in user_in_db.scopes:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not enough permissions",
                )
        access_token = create_access_token(
            data={"sub": user_in_db.username, "scopes": [user_in_db.scopes]},
            expires_delta=timedelta(minutes=60),
        )
        return user_schema.NewAccessToken(access_token=access_token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")