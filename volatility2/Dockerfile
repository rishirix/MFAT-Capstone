FROM python:3.10-slim 

ENV DEBIAN_FRONTEND=noninteractive

# System deps required to build Python via pyenv
RUN apt update && apt install -y \
    git curl build-essential \
    libssl-dev zlib1g-dev \
    libbz2-dev libreadline-dev libsqlite3-dev \
    wget llvm libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev liblzma-dev \
    ca-certificates make

# Copy script
COPY install_pyenv_py2.py /root/install_pyenv_py2.py

# Run script
RUN python3 /root/install_pyenv_py2.py

# Ensure pyenv loads in interactive shells
RUN echo 'export PYENV_ROOT="$HOME/.pyenv"' >> /root/.bashrc && \
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> /root/.bashrc && \
    echo 'eval "$(pyenv init -)"' >> /root/.bashrc

# Make python default in non-login shells too
ENV PYENV_ROOT="/root/.pyenv"
ENV PATH="/root/.pyenv/bin:/root/.pyenv/shims:$PATH"

WORKDIR /workspace
RUN git clone https://github.com/volatilityfoundation/volatility.git
WORKDIR /workspace/volatility
RUN make build && make install
RUN pip2 install distorm3 yara-python pycrypto

CMD ["/bin/bash"]
