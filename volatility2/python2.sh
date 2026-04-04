#!/bin/bash

export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"


eval "$(pyenv virtualenv-init -)"

CFLAGS="-std=c11" pyenv install 2.7.18
pyenv shell 2.7.18
