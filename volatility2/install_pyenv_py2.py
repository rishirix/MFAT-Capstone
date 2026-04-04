#!/usr/bin/env python3
import os
import subprocess
import sys

PYENV_ROOT = "/root/.pyenv"
BASHRC = "/root/.bashrc"

def run(cmd):
    print(f"[+] Running: {cmd}")
    subprocess.check_call(cmd, shell=True)

def append_if_missing(file, text):
    if os.path.exists(file):
        with open(file, "r") as f:
            if text in f.read():
                return
    with open(file, "a") as f:
        f.write("\n" + text + "\n")

def main():
    # Install pyenv
    if not os.path.exists(PYENV_ROOT):
        run("curl http://pyenv.run | bash")

    # Setup environment in bashrc
    append_if_missing(BASHRC, 'export PYENV_ROOT="$HOME/.pyenv"')
    append_if_missing(BASHRC, 'export PATH="$PYENV_ROOT/bin:$PATH"')
    append_if_missing(BASHRC, 'eval "$(pyenv init -)"')

    # Load pyenv in this script session
    os.environ["PYENV_ROOT"] = PYENV_ROOT
    os.environ["PATH"] = f"{PYENV_ROOT}/bin:" + os.environ["PATH"]

    # Initialize pyenv for subprocess
    init_cmd = 'export PYENV_ROOT="$HOME/.pyenv"; export PATH="$PYENV_ROOT/bin:$PATH"; eval "$(pyenv init -)"; '

    # Install Python 2.7.18
    run(init_cmd + 'CFLAGS="-std=c11" pyenv install 2.7.18')

    # Set global default
    run(init_cmd + "pyenv global 2.7.18")

    print("[+] Python 2.7.18 installed and set as global default")

if __name__ == "__main__":
    main()
