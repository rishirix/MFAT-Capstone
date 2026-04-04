FROM python:3.10-slim

WORKDIR /app

RUN apt update && apt install git vim wget curl -y
RUN git clone https://github.com/volatilityfoundation/volatility3.git --branch stable
WORKDIR /app/volatility3
RUN pip3 install -e ".[full]"
RUN curl -O https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
RUN curl -O https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
RUN curl -O https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
RUN mv *.zip ./volatility3/symbols/

WORKDIR /

CMD ["/bin/bash"]
