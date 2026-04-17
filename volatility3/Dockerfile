FROM python:3.10-slim

WORKDIR /opt

RUN apt update && apt install git wget curl unzip -y \
&& git clone https://github.com/volatilityfoundation/volatility3.git --branch stable 

WORKDIR /opt/volatility3
RUN pip3 install -e ".[full]"

WORKDIR /opt/volatility3/volatility3/symbols
RUN wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip && unzip windows.zip
RUN wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip && unzip mac.zip
RUN wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip && unzip linux.zip

WORKDIR /opt/volatility3
ENTRYPOINT [ "vol" ]