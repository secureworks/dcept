# Domain Controller Enticing Password Tripwire (DCEPT) - Dockerfile



FROM ubuntu:14.04
MAINTAINER James Bettke

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get upgrade -yf
RUN apt-get install -y wget build-essential libssl-dev python-pip
RUN apt-get install -y tcpreplay

RUN apt-get install -y tshark python-dev libxml2-dev libxslt1-dev
RUN pip install pyshark
RUN pip install pyiface

# Download community-enhanced version of John the Ripper password cracker
# Version must support krb5pa-sha1 

RUN wget -O /tmp/john.tar.gz http://www.openwall.com/john/j/john-1.8.0-jumbo-1.tar.gz
RUN mkdir /tmp/john && tar -xvf /tmp/john.tar.gz -C /tmp/john --strip-components=1

# Compile John the Ripper from source

RUN cd /tmp/john/src && ./configure && make clean && make -s

RUN mkdir -p /opt/dcept/var
RUN cp /tmp/john/run/john /opt/dcept/john
RUN touch /opt/dcept/john.ini

ADD ./dcept.py /opt/dcept/dcept.py
ADD ./GenerationServer.py /opt/dcept/GenerationServer.py
ADD ./ConfigReader.py /opt/dcept/ConfigReader.py
ADD ./alert.py /opt/dcept/alert.py
ADD ./dcept.cfg /opt/dcept/dcept.cfg
