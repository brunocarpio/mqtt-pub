#!/bin/bash

mkdir charm-install && cd charm-install
curl -LO https://raw.githubusercontent.com/brunocarpio/charm-install-script/main/script.sh && bash script.sh
cd ../ && sudo rm -rf charm-install

sudo apt install --yes python3-pip
pip3 install paho-mqtt
pip3 install requests
pip3 install pytz
pip3 install matplotlib
pip3 install pycryptodome
