from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Annotated
import re
from enum import Enum


class UserScopes(str, Enum):
    user = "user"
    admin = "admin"


class UserSchemaIn(BaseModel):
    username: Annotated[str, Field(title="username of the curent user", max_length=100)]
    password: Annotated[str, Field(title="password of the user", max_length=100)]
    scopes: Annotated[UserScopes,Field(title='user privilege: admin / user')]

    # model_config = ConfigDict(extra="forbid")

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        if len(value) < 6:
            raise ValueError("Password must contain 6 characters.")
        if not re.search(r"[A-Za-z]", value):
            raise ValueError("Password must include at least one letter.")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number.")
        return value


class UserSchemaOut(BaseModel):
    success: str


class TokensSchemaOut(BaseModel):
    access_token: str
    refresh_token :str


class TokenData(BaseModel):
    token:str|None = None
    scopes:list[str] = []


class LogoutSchema(BaseModel):
    success:str

class NewAccessToken(BaseModel):
    access_token: str