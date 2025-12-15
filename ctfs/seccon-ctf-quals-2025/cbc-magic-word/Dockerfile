FROM python:3.14-rc-slim-bookworm
USER root
RUN apt-get update && apt-get install socat -y
RUN pip install pycryptodome

COPY server.py .
ENV FLAG="SECCON{dummy}"

CMD ["socat", "TCP-L:3333,fork,reuseaddr", "EXEC:'python3 server.py'"]
