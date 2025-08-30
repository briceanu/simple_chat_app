from fastapi import APIRouter, status, HTTPException, Depends, Security, Header
from sqlalchemy.exc import IntegrityError
from app.utils import user_logic
from app.schemas import user_schema
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.db_connection import get_async_db
from fastapi.security import OAuth2PasswordRequestForm


from typing import Annotated

router = APIRouter(tags=["user"], prefix="/api/v1/user")


@router.post(
    "/sign-up",
    response_model=user_schema.UserSchemaOut,
    status_code=status.HTTP_201_CREATED,
)
async def sign_up_user(
    user_data: user_schema.UserSchemaIn,
    async_session: AsyncSession = Depends(get_async_db),
) -> user_schema.UserSchemaOut:
    """
    Register a new user account.

    This endpoint creates a new user in the system by validating the input data,
    hashing the password, and persisting the record in the database.

    Args:
        user_data (UserSchemaIn): Input schema containing the username,
            password, and date of birth for the new user.
        async_session (AsyncSession): Database session dependency used
            for performing asynchronous queries.

    Returns:
        UserSchemaOut: A success message indicating that the account was created.

    Raises:
        HTTPException 400: If an integrity constraint is violated
            (e.g., duplicate username or value too long for a column).
        HTTPException 500: For any unexpected server-side error
            during the user creation process.
    """
    try:
        result = await user_logic.sign_up_user(user_data, async_session)
        return result
    except HTTPException:
        raise
    except IntegrityError as e:
        # Detect unique violation on username
        if "uq_user_username" in str(e.orig) or "username" in str(e.orig):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Username '{user_data.username}' is already taken.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Database integrity error."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"{str(e)}"
        )


@router.post(
    "/sign-in",
    response_model=user_schema.TokensSchemaOut,
    status_code=status.HTTP_200_OK,
)
async def sign_in_user(
    form_data: Annotated[str, Depends(OAuth2PasswordRequestForm)],
    async_session: AsyncSession = Depends(get_async_db),
) -> user_schema.TokensSchemaOut:
    """
    Authenticate a user and return access/refresh tokens.

    This endpoint verifies the provided username and password.
    If authentication is successful, it returns a new access
    token and refresh token pair.

    Args:
        user_data_sign_in (OAuth2PasswordRequestForm):
            Form data containing `username` and `password`.
        async_session (AsyncSession):
            SQLAlchemy async database session provided via dependency injection.

    Returns:
        schemas.Token: An object containing the access token and refresh token.

    Raises:
        HTTPException (401): If the credentials are invalid.
        HTTPException (500): If an unexpected server error occurs.
    """

    try:
        result = await user_logic.sign_in_user(form_data, async_session)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"{str(e)}"
        )


@router.post(
    "/logout",
    response_model=user_schema.LogoutSchema,
    status_code=status.HTTP_200_OK,
)
async def logout_user(
    token: Annotated[str, Header(description="pass the refresh token in the headers")],
) -> user_schema.LogoutSchema:
    """
    Logs out a user by invalidating their refresh token.

    Args:
        token (str): The refresh token provided in the request headers.

    Returns:
        LogoutSchema: A response indicating successful logout with a message.

    Raises:
        HTTPException:
            - 500 Internal Server Error: If any unexpected error occurs during logout.
            - Propagates any HTTPException raised in the logout logic.
    """

    try:
        result = await user_logic.logout(token)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"{str(e)}"
        )


@router.post(
    "/new-access-token",
    # response_model=user_schema.LogoutSchema,
    status_code=status.HTTP_200_OK,
)
async def get_new_access_token_from_refresh_token(
    refresh_token: Annotated[str, Header(description="pass the refresh token in the headers")],
    async_session:Annotated[AsyncSession,Depends(get_async_db)]
):
    try:
        result = await user_logic.access_token_from_refresh(refresh_token,async_session)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"{str(e)}"
        )