FROM python:3.11

WORKDIR /fastapi_app

COPY ./requirements.txt /fastapi_app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /fastapi_app/requirements.txt

COPY . .

CMD sleep 20 && uvicorn main:app --host 0.0.0.0 --port 8000
