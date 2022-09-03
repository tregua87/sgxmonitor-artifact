#!/bin/bash

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
ENV=.pyenv

#------------------------------------------------------------------------
# Create Environment
#------------------------------------------------------------------------
if ! [[ -f ${ENV}/.done ]]; then
  LOAD_PYENV_INTERPRETER=/usr/bin/python3.5
  virtualenv -p ${LOAD_PYENV_INTERPRETER} ${ENV} || exit 1
  source ${ENV}/bin/activate
  pip install -U pip
  pip install -U setuptools
  pip install -r requirements.txt || exit 1
  touch ${ENV}/.done
fi
source ${ENV}/bin/activate
