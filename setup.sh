#!/bin/bash

sudo apt install python3-pip
pip3 install virtualenv
python3 -m virtualenv venv
source venv/bin/activate

pip install -r requirements.txt
sudo flask run
