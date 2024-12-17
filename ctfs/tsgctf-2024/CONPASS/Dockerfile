FROM python:3.12-slim

ENV DEBIAN_FRONTEND noninteractive

WORKDIR /home/user/

COPY requirements.txt /home/user/requirements.txt
RUN pip install -r requirements.txt
COPY ./server.py /home/user/server.py

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
