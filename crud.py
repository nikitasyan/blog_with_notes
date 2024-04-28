import models
from sqlalchemy.orm import Session
import hashlib
from config import PASSWORD_SALT


def create_post(db: Session, header: str, text_message: str, user_id: int) -> models.Posts:
    """Создает новую запись и возвращает её"""
    new_post = models.Posts(head=header, text_message=text_message, user_id=user_id)
    db.add(new_post)
    db.commit()
    return new_post


def get_posts(db: Session):
    """Получаем все записи"""
    all_posts = db.query(models.Posts).all()
    return all_posts


def get_post_and_username_by_id(db: Session, post_id: str):
    """Получить данные записи и автора этотй записи"""
    data = db.query(models.Posts).join(models.Users).filter(models.Posts.id == post_id).first()
    if data:
        return data


def update_post(db: Session, old_header: str, new_header: str, new_text_message: str):
    """Обновить данные записи"""
    post = db.query(models.Posts).filter(models.Posts.head == old_header).first()
    post.head = new_header
    post.text_message = new_text_message
    db.commit()
    return post


def create_user(db: Session, username: str, password: str) -> models.Users:
    """Создать нового пользователя"""
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    new_user = models.Users(username=username, password=password_hash)
    db.add(new_user)
    db.commit()
    return new_user


def get_username_by_id(db: Session, user_id: int) -> str:
    """Полуить имя пользователя по его id"""
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    return user.username


def get_id_by_username(db: Session, username: str) -> int:
    """Получить id пользователя по его username"""
    user = db.query(models.Users).filter(models.Users.username == username).first()
    return user.id


def is_user_exist(db: Session, username: str) -> bool:
    """Проверка на существование пользователя с именем username"""
    user = db.query(models.Users).filter(models.Users.username == username).first()
    if user:
        return True
    return False


def verify_password(db: Session, username: str, password: str) -> bool:
    """Возвращает True, если пользователь с логином username и паролем password верифицирован.
    Иначе -- False."""
    user_in_db = db.query(models.Users).filter(models.Users.username == username).first()
    stored_password_hash = user_in_db.password.lower()
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    return password_hash == stored_password_hash
