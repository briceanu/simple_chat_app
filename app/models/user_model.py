from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy import DateTime
from datetime import datetime
from sqlalchemy import MetaData, String, CheckConstraint,JSON, Boolean
from sqlalchemy.orm import mapped_column, Mapped, DeclarativeBase
import uuid


class Base(DeclarativeBase, AsyncAttrs):
    """Base class for all models"""

    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_`%(constraint_name)s`",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )
    type_annotation_map = {
        datetime: DateTime(timezone=True),
    }


class User(Base):
    __tablename__ = 'user'
    
    user_id: Mapped[uuid.UUID] = mapped_column(
        default=lambda: uuid.uuid4(), primary_key=True, nullable=False, unique=True
    )
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(100),nullable=False)
    scopes:Mapped[list[str]] = mapped_column(JSON,nullable=False,default=[])
    is_active:Mapped[bool] = mapped_column(Boolean,nullable=False,default=False)

    __table_args__ = (
        CheckConstraint("length(password) >= 10", name="password_min_length"),
    )