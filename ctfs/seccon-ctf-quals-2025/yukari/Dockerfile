FROM python:3.13.9-alpine@sha256:e5fa639e49b85986c4481e28faa2564b45aa8021413f31026c3856e5911618b1 as app

RUN pip install pycryptodome==3.23.0

FROM pwn.red/jail
COPY --from=app / /srv

RUN mkdir /srv/app

COPY chal.py /srv/app/run
COPY ./flag.txt /srv/app/

RUN chmod 555 /srv/app/run
RUN chmod 444 /srv/app/flag.txt

ENV JAIL_CPU=500 JAIL_MEM=20M JAIL_TIME=600 JAIL_PORT=15809
EXPOSE 15809