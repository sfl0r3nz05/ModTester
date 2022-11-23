FROM ubuntu:22.04

WORKDIR /src/app
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y python2.7 python-pip libpcap-dev hping3 && pip2 install --pre scapy[basic]
COPY . /src/app
CMD ["python2", "modTester.py"]
