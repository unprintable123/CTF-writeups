FROM ubuntu:24.04
RUN apt update && apt upgrade -y && apt install -y python3-pip curl git
RUN python3 -m pip install --break-system-packages web3==6.20.3 py-solc-x==2.0.3
RUN python3 -c "from solcx import install_solc; install_solc(version='0.8.28')"
ENV PATH="$PATH:/root/.foundry/bin"
RUN curl -L https://foundry.paradigm.xyz | bash && foundryup
COPY main.py challenge1.sol challenge2.sol challenge3.sol compile.py /
RUN python3 compile.py
CMD ["/usr/bin/python3", "-u", "/main.py"]
