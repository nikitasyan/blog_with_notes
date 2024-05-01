from dotenv import load_dotenv
import os


load_dotenv()

DIALECT = os.environ.get("POSTGRES_DIALECT")
DB_NAME = os.environ.get("POSTGRES_DB")
USER = os.environ.get("POSTGRES_USER")
PASSWORD = os.environ.get("POSTGRES_PASSWORD")
HOST = os.environ.get("POSTGRES_HOST")
PORT = os.environ.get("POSTGRES_PORT")

SECRET_KEY = os.environ.get("SECRET_KEY")
PASSWORD_SALT = os.environ.get("PASSWORD_SALT")
