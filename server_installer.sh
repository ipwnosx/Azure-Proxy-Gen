#!/usr/bin/env bash
sudo apt update && sudo apt install -y python3-pip build-essential python3-dev python3-setuptools gcc sshpass
sudo apt-get install apt-transport-https lsb-release software-properties-common dirmngr -y
AZ_REPO=$(lsb_release -cs)
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | \
    sudo tee /etc/apt/sources.list.d/azure-cli.list
sudo apt-key --keyring /etc/apt/trusted.gpg.d/Microsoft.gpg adv \
     --keyserver packages.microsoft.com \
     --recv-keys BC528686B50D79E339D3721CEB3E94ADBE1229CF
sudo apt-get update
sudo apt-get install azure-cli -y
pip3 install -U pip
pip install -r requirements.txt
pip uninstall cryptography -y && pip install cryptography
echo "alias pyazure-create='/usr/bin/python3 $(pwd)/create_servers.py'" >> ~/.bashrc
echo "alias pyazure-delete='/usr/bin/python3 $(pwd)/delete_servers.py'" >> ~/.bashrc
echo "alias pyazure-list='/usr/bin/python3 $(pwd)/list_servers.py'" >> ~/.bashrc
az login
exec bash
