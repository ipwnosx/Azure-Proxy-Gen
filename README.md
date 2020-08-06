# Azure-Proxy-Gen

**Instructions for installation on Ubuntu 16+:

* Transfer project to an Ubuntu Server.
* From within the project folder, run `sh server_installer.sh`
* The server_installer.sh script runs `az login` command to login to Azure. Open the link in the output and paste the verification key in the link opened to verify Azure login.
* After login succeeds, you can run the following commands.
* For Creating virtual machines, open terminal in the folder location and run `pyazure-create`
* For Deleting virtual machine, from the folder in the terminal and run `pyazure-delete`
* For Listing the virtual machines, from the folder open the terminal and run `pyazure-list`

**Requirements:**

requests,
tqdm,
tabulate,
colorama,
ansible,
paramiko,
passlib,
SQLAlchemy
