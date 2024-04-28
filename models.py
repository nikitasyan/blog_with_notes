from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, Text
from sqlalchemy.orm import relationship

from database import Base


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, unique=True)
    password = Column(String(100), nullable=False)

    all_posts = relationship(argument="Posts",
                             back_populates="users")


class Posts(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    head = Column(String(100))
    text_message = Column(Text)
    last_update = Column(DateTime, server_default=func.now(), onupdate=func.now())

    users = relationship(argument="Users",
                         back_populates="all_posts")
