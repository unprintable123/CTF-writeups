FROM sagemath/sagemath:10.8@sha256:e2e4747b0e1ea8753a9cb5a399314a8b2c25fcefaf69ba85b22ee075829d09ea

RUN sudo apt-get -y update --fix-missing
RUN sudo apt-get -y upgrade
RUN sudo apt-get -y install socat

USER sage
WORKDIR /app

COPY chal.sage ./chal.sage
COPY flag.txt ./flag.txt

CMD ["socat", "tcp-l:13520,reuseaddr,fork", "EXEC:'sage chal.sage'"]