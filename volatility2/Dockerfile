FROM ubuntu:18.04

RUN apt-get update && apt-get install -y python2.7 python-pip \
&& ln -sf /usr/bin/python2.7 /usr/bin/python

RUN pip2 install distorm3 yara-python pycrypto volatility261

ENTRYPOINT [ "vol.py" ]