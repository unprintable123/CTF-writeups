FROM sagemath/sagemath:10.5

RUN sudo apt-get update && sudo apt-get install -y hashcash xinetd python3

RUN sudo mkdir /server && sudo mkdir /hashcash && sudo chown sage:sage /server /hashcash && sage -c "print('')"

COPY ./src/*.sh /server
COPY ./src/*.py /server
COPY ./src/*.sage /server
COPY ./src/xinetd.conf /etc/xinetd.d/ctf

RUN sudo chown sage:sage -R /server &&  chmod +x /server/*.sh /server/*.py /server/*.sage && sudo chmod o+r /etc/xinetd.d/ctf

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV SHELL /bin/bash
ENV HOME /server/

WORKDIR /server/
EXPOSE 16180

CMD ["xinetd", "-dontfork", "-f", "/etc/xinetd.d/ctf"]
