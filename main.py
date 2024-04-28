import hmac
import hashlib
import base64
import binascii
from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import FastAPI, Form, Depends, Cookie, Body, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import crud
from database import SessionLocal, Base, engine
from config import SECRET_KEY


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI()
templates = Jinja2Templates(directory="templates")


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        key=SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> bool | str:
    """Возвращает username, если имя пользователя username_signed, взятое из cookie валидное
    Иначе -- False"""
    try:
        username_base64, sign = username_signed.split(".")
        username = base64.b64decode(username_base64.encode()).decode()
        valid_sign = sign_data(username)
        if hmac.compare_digest(valid_sign, sign):
            return username
        return False
    except binascii.Error:
        return False


def check_validation_username(name: str) -> bool:
    """Проверка логина на разумные ограничения:
    - длина логина."""
    return 2 <= len(name) <= 50


def check_validation_password(password: str) -> bool:
    """Проверка пароля на разумные ограничения:
    - пароль должен соответствовать определённой длине,
    - пароль должен содержать хотя бы одну цифру,
    - пароль должен содержать хотя бы одну букву в верхнем регистре,
    - пароль должен содержать хотя бы одну букву в нижнем регистре."""
    digits = set("0123456789")
    upper_letters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    lower_letters = set("abcdefghijklmnopqrstuvwxyz")
    digit_exist, upper_exist, lower_exist = False, False, False
    len_correct = 8 <= len(password) <= 100
    for char in password:
        if char in digits:
            digit_exist = True
        elif char in upper_letters:
            upper_exist = True
        elif char in lower_letters:
            lower_exist = True
    return all((digit_exist, upper_exist, lower_exist, len_correct))


def check_validation_header(header: str) -> bool:
    """Проверка заголовка поста на разумные ограничения:
    - длина логина."""
    return 4 < len(header) < 100


def check_validation_text_message(text_message: str) -> bool:
    """Проверка текста поста на разумные ограничения:
    - количество символов в тексте,
    - количество слов в тексте."""
    return 10 < len(text_message) < 1000 and 3 < len(text_message.split()) < 250


@app.get("/", response_class=HTMLResponse)
def index_page(
        request: Request,
        db: Session = Depends(get_db),
        username: Annotated[str | None, Cookie()] = None
):
    if not username:
        return templates.TemplateResponse("login.html",
                                          {"request": request})

    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = templates.TemplateResponse("login.html",
                                              {"request": request})
        response.delete_cookie(key="username")
        return response

    is_user_exist = crud.is_user_exist(db, valid_username)
    if is_user_exist:
        return templates.TemplateResponse("index_page.html",
                                          {"request": request,
                                           "username": valid_username})
    response = templates.TemplateResponse("login.html",
                                          {"request": request})
    response.delete_cookie(key="username")
    return response


@app.post("/login", response_class=HTMLResponse)
def process_login_page(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        db: Session = Depends(get_db)
):
    is_user_exist = crud.is_user_exist(db, username)
    if not is_user_exist or not crud.verify_password(db, username, password):
        return templates.TemplateResponse("error_login.html",
                                          {"request": request})
    response = templates.TemplateResponse("success_login.html",
                                          {"request": request,
                                           "username": username})
    username_signed = (base64.b64encode(username.encode()).decode() + "." + sign_data(username))
    response.set_cookie(key="username", value=username_signed, expires=60*60*24)
    return response


@app.get("/posts", response_class=HTMLResponse)
def get_all_posts(
        request: Request,
        db: Session = Depends(get_db)
):
    all_posts = crud.get_posts(db)
    return templates.TemplateResponse("posts.html",
                                      {"request": request,
                                       "posts": all_posts})


@app.get("/authorization", response_class=HTMLResponse)
def authorization(
        request: Request,
        username: Annotated[str | None, Cookie()] = None
):
    if username:
        return RedirectResponse("/posts")
    return templates.TemplateResponse("authorization.html",
                                      {"request": request})


@app.post("/auth", response_class=HTMLResponse)
def process_autorization(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        db: Session = Depends(get_db)
):
    username_is_valid = check_validation_username(username)
    password_is_valid = check_validation_password(password)
    if (not username_is_valid
            or not password_is_valid
            or crud.is_user_exist(db, username)):
        return templates.TemplateResponse("authorization.html",
                                          {"request": request})
    crud.create_user(db, username, password)
    response = templates.TemplateResponse("success_login.html",
                                          {"request": request,
                                           "username": username})
    username_signed = (base64.b64encode(username.encode()).decode() + "." + sign_data(username))
    response.set_cookie(key="username", value=username_signed, expires=60 * 60 * 24)
    return response


@app.get("/create_post", response_class=HTMLResponse)
def create_post(
        request: Request,
        username: Annotated[str | None, Cookie()] = None
):
    if not username:
        return templates.TemplateResponse("login.html",
                                          {"request": request})

    return templates.TemplateResponse("create_post.html",
                                      {"request": request})


@app.post("/create_post", response_class=HTMLResponse)
def process_create_post(
        header: Annotated[str, Body(embed=True)],
        text_message: Annotated[str, Body(embed=True)],
        db: Session = Depends(get_db),
        username: Annotated[str | None, Cookie()] = None
):
    header_is_valid = check_validation_header(header)
    text_message_is_valid = check_validation_text_message(text_message)
    if not header_is_valid or not text_message_is_valid:
        reference_info = "Ошибка! Вы ввели некорректные данные. Попробуйте снова"
        return JSONResponse({"reference_info": reference_info})

    username = username.split(".")[0]
    username = base64.b64decode(username.encode()).decode()
    user_id = crud.get_id_by_username(db, username)
    post = crud.create_post(db, header, text_message, user_id)
    return JSONResponse({"message": f"Поздравляю! Вы опубликовали запись с заколовком '{post.head}'",
                         "all_posts": f"Данные новой записи: {post.text_message}"})


@app.get("/post", response_class=HTMLResponse)
def get_post(
        request: Request,
        post_id: Annotated[str, Query()],
        db: Session = Depends(get_db),
        username: Annotated[str | None, Cookie()] = None
):
    post_join_user = crud.get_post_and_username_by_id(db, post_id)
    if not post_join_user:
        return RedirectResponse("/posts")
    author_this_post = crud.get_username_by_id(db, post_join_user.user_id)
    post_belongs_to_username = False
    if username:
        user_from_cookie_base64, sign = username.split(".")
        user_from_cookie = base64.b64decode(user_from_cookie_base64.encode()).decode()
        if hmac.compare_digest(user_from_cookie, author_this_post):
            post_belongs_to_username = True
        else:
            post_belongs_to_username = False
    return templates.TemplateResponse(name="post.html",
                                      context={"request": request,
                                               "head": post_join_user.head,
                                               "text_message": post_join_user.text_message,
                                               "author_this_post": author_this_post,
                                               "post_belongs_to_username": post_belongs_to_username,
                                               "last_update": post_join_user.last_update})


@app.put("/edit_post")
def edit_post(
        old_header: Annotated[str, Body(embed=True)],
        new_header: Annotated[str, Body(embed=True)],
        new_text_message: Annotated[str, Body(embed=True)],
        db: Session = Depends(get_db)
):
    header_is_valid = check_validation_header(new_header)
    text_message_is_valid = check_validation_text_message(new_text_message)
    if not header_is_valid or not text_message_is_valid:
        reference_info = "Ошибка! Вы ввели некорректные данные. Попробуйте снова"
        return JSONResponse({"reference_info": reference_info})
    update_post = crud.update_post(db, old_header, new_header, new_text_message)
    return JSONResponse({"message": f"Поздравляю! Вы обновили запись. Новый заголовок: {update_post.head}",
                         "all_posts": f"Данные обновлённой записи: {update_post.text_message}"})
