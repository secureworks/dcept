# Domain Controller Enticing Password Tripwire (DCEPT) - Dockerfile



FROM ubuntu:16.04
MAINTAINER James Bettke

ENV DEBIAN_FRONTEND noninteractive

# Set the default shell to bash inside the container
RUN rm /bin/sh && ln -sf /bin/bash /bin/sh

# Ensure we have the latest packages
RUN apt-get update && apt-get upgrade -yf

RUN apt-get install -y cron wget build-essential libssl-dev python-pip python-setuptools
RUN apt-get install -y tcpreplay

# Install dependencies for sniffer component
RUN apt-get install -y tshark python-dev libxml2-dev libxslt1-dev
RUN pip install pyshark
RUN pip install pyiface

# Download community-enhanced version of John the Ripper password cracker
# Version must support krb5pa-sha1 

RUN wget -O /tmp/john.tar.gz http://www.openwall.com/john/j/john-1.8.0-jumbo-1.tar.gz

# Verify integrity of download
RUN sha1sum -c <<< '31c8246d3a12ab7fd7de0d1070dda4654f5397a7 /tmp/john.tar.gz'

# Extract John the Ripper source files
RUN mkdir /tmp/john && tar -xvf /tmp/john.tar.gz -C /tmp/john --strip-components=1

# Fix bug with GCC v5 when compiling JtR - May not be needed after 1.8.0 update
# https://github.com/magnumripper/JohnTheRipper/issues/1093
RUN sed -i 's/#define MAYBE_INLINE_BODY MAYBE_INLINE/#define MAYBE_INLINE_BODY/g' /tmp/john/src/MD5_std.c

# Compile John the Ripper from source
RUN cd /tmp/john/src && ./configure && make clean && make -s

RUN mkdir -p /opt/dcept/var
RUN cp /tmp/john/run/john /opt/dcept/john
RUN touch /opt/dcept/john.ini

# Copy DCEPT source code into the container
ADD ./dcept.py /opt/dcept/dcept.py
ADD ./Cracker.py /opt/dcept/Cracker.py
ADD ./GenerationServer.py /opt/dcept/GenerationServer.py
ADD ./ConfigReader.py /opt/dcept/ConfigReader.py
ADD ./alert.py /opt/dcept/alert.py
ADD ./dcept.cfg /opt/dcept/dcept.cfg


# Add a cron job to keep the container up-to-date (does not apply to DCEPT code)
RUN echo '0 0 * * * root apt-get update && apt-get upgrade -yf' > /etc/cron.d/update-cron
RUN chmod 0644 /etc/cron.d/update-cron
CMD cron; /opt/dcept/dcept.py 
