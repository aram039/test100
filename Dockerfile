
FROM python:3.9-alpine

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY . /app

RUN python3 --version

EXPOSE 443

CMD ["python", "app.py"]
