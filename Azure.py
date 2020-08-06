import configparser
import datetime
import json
import os
import socket
import subprocess
import sys
import time
import uuid
import warnings
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor as Executor
from pathlib import Path

import paramiko
from colorama import Fore
from paramiko import BadHostKeyException, SSHException, AuthenticationException
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from tabulate import tabulate
from tqdm import tqdm

from datacenters import datacenter_regions

warnings.filterwarnings("ignore")
FNULL = open(os.devnull, 'w')


class AzureError(Exception):
    pass


Base = declarative_base()


class VirtualMachines(Base):
    __tablename__ = 'virtual_machines'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    ip_address = Column(String, unique=True, nullable=False)
    location = Column(String, nullable=False)
    data_center = Column(String, nullable=False)
    resource_group = Column(String, nullable=False)
    server_user = Column(String, nullable=False)
    server_password = Column(String, nullable=False)
    squid_user = Column(String, nullable=True)
    squid_password = Column(String, nullable=True)
    squid_port = Column(String, nullable=True)
    created_date = Column(DateTime, default=datetime.datetime.utcnow, nullable=True)
    login_type = Column(String, nullable=False)
    status = Column(String, nullable=False)


class Azure:
    def __init__(self):
        self.TIMEOUT = None
        self.SQUID_USER = None
        self.SQUID_PASS = None
        self.SQUID_PORT = None
        self.INSTALL_PROXIES = None
        self.SAVE_PROXIES = None
        self.MAX_ALLOWED_SERVERS = None
        self.CURRENTLY_RUNNING_SERVERS = None
        self.SERVER_CREATION_LIMIT = None
        self.LIMITS_LIST = None
        self.VM_SIZE = None
        self.SERVER_SLUG = None
        self.SERVER_USER = None
        self.SERVER_PASSWORD = None
        self.AUTH_TYPE = None
        self.IPS_TO_AUTHENTICATE = None
        self.VmDetail = namedtuple("VmDetail", ["resource_group_name", "server_name", "username", "password"])
        self.VmPortDetail = namedtuple("VmPortDetail", ["server_name", "resource_group_name", "squid_port", ])
        self.SCRIPT_PATH = Path(__file__).resolve().parent
        self.load_config()
        self.data_center_dict = self.get_data_center_key_val()

        self.get_and_display_account_server_limits()
        os.environ['ANSIBLE_CONFIG'] = str(self.SCRIPT_PATH)
        self.get_tabular_datacenter()
        self.SSH_TUPLE = namedtuple("SSH_TUPLE",
                                    ["ip", "user", "password", "key_file", "initial_wait", "interval", "retries"])
        self.engine = create_engine('sqlite:///{}'.format(self.SCRIPT_PATH.joinpath('vms.db')), echo=False)
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        self.session = self.Session()

    def load_config(self):
        config_parser = configparser.RawConfigParser()
        config_file_path = str(self.SCRIPT_PATH.joinpath('config.ini'))
        config_parser.read(config_file_path)
        self.TIMEOUT = int(config_parser['extras']['TIMEOUT'])

        self.SQUID_USER = config_parser['essentials']['SQUID_USER']
        self.SQUID_PASS = config_parser['essentials']['SQUID_PASS']
        self.SQUID_PORT = config_parser['essentials']['SQUID_PORT']
        self.INSTALL_PROXIES = config_parser.getboolean('essentials', 'INSTALL_PROXIES')
        self.SAVE_PROXIES = config_parser.getboolean('essentials', 'SAVE_PROXIES_TO_FILE')
        self.VM_SIZE = config_parser['essentials']['VM_SIZE']
        self.SERVER_SLUG = config_parser['essentials']['SERVER_SLUG']
        self.SERVER_USER = config_parser['essentials']['SERVER_USER']
        self.SERVER_PASSWORD = config_parser['essentials']['SERVER_PASSWORD']
        self.AUTH_TYPE = config_parser['essentials']['AUTH_TYPE'].upper()
        if self.AUTH_TYPE == 'IP':
            self.SQUID_USER = None
            self.SQUID_PASS = None
            with open('ips.txt', 'r') as r:
                self.IPS_TO_AUTHENTICATE = ' '.join([x.strip() for x in r.readlines()])

    def get_data_center_key_val(self):
        return {str(k + 1): (v['region'], v['location']) for k, v in enumerate(datacenter_regions)}

    def return_current_limit_and_active_vms(self, data_center_name):
        while True:
            process = subprocess.Popen("az vm list-usage -l {}".format(data_center_name), shell=True,
                                       stdout=subprocess.PIPE,
                                       universal_newlines=True)
            s = process.communicate()
            limits_json = [x for x in json.loads(s[0]) if x['localName'] == 'Total Regional vCPUs'][0]
            if process.returncode == 0:
                break
            else:
                time.sleep(1)
        return data_center_name, int(limits_json['currentValue']), int(limits_json['limit'])

    def get_and_display_account_server_limits(self):

        print("Getting Server Information..\n")

        regions = [x['region'] for x in datacenter_regions]
        results = []
        with Executor(10) as executor:
            for res in tqdm(executor.map(self.return_current_limit_and_active_vms, regions), total=len(regions),
                            unit="Queries", desc="Querying limits."):
                results.append(res)
        self.LIMITS_LIST = [{k: v for k, v in zip(["region", "current_value", "limit"], res)} for res in list(results)]
        for res in self.LIMITS_LIST:
            res['creatable_servers'] = int(res['limit']) - int(res['current_value'])

        # self.CURRENTLY_RUNNING_SERVERS, self.MAX_ALLOWED_SERVERS = self.return_current_limit_and_active_vms(
        #     data_center_name=data_center_name)
        # self.CURRENTLY_RUNNING_SERVERS = len(self.server_names_and_ips())
        # self.SERVER_CREATION_LIMIT = self.MAX_ALLOWED_SERVERS - self.CURRENTLY_RUNNING_SERVERS
        data_centers = [Fore.LIGHTCYAN_EX + x['region'] + Fore.WHITE for x in self.LIMITS_LIST]
        current_value = [Fore.YELLOW + str(x['current_value']) + Fore.WHITE for x in self.LIMITS_LIST]
        limit = [Fore.RED + str(x['limit']) + Fore.WHITE for x in self.LIMITS_LIST]
        creatable_servers = [Fore.GREEN + str(x['creatable_servers']) + Fore.WHITE for x in self.LIMITS_LIST]
        keys = range(1, len(data_centers) + 1)
        max_allowed_servers = []
        print(tabulate(zip(keys, data_centers, limit, current_value, creatable_servers),
                       headers=[Fore.WHITE + "KEY", Fore.CYAN + "Data Center" + Fore.WHITE,
                                Fore.RED + 'MAX SERVER LIMIT' + Fore.WHITE,
                                Fore.YELLOW + 'SERVERS CURRENTLY RUNNING' + Fore.WHITE,
                                Fore.GREEN + 'CREATABLE SERVERS' + Fore.WHITE],
                       tablefmt='fancy_grid'))

    def get_tabular_datacenter(self, sort_by_continent=False):
        data_to_display = [(k, v[0], v[1]) for k, v in self.data_center_dict.items()]
        data_to_display.sort(key=lambda x: int(x[0]))
        if sort_by_continent:
            data_to_display.sort(key=lambda x: x[2])
        return tabulate(data_to_display,
                        headers=("Key", "DataCenter", "Region"), tablefmt='fancy_grid')

    def create_resource_group(self, resource_group_name, data_center_region):
        cmd = "az group create --name " + resource_group_name + " --location " + data_center_region
        result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
        out, err = result.communicate()
        return_code = result.returncode
        return return_code

    def check_if_resource_group_is_active(self, resource_group_name):
        print(Fore.LIGHTYELLOW_EX + "Checking if resource group `{}` is active..".format(
            resource_group_name) + Fore.WHITE)
        retries = 10
        s = subprocess.Popen("az group list", shell=True, stdout=subprocess.PIPE, universal_newlines=True)
        s = s.communicate()
        while True:
            resource_json = json.loads(s[0])
            if len(resource_json) > 0:
                resource_names = [x['name'] for x in json.loads(s[0])]
                if resource_group_name in resource_names:
                    print(
                        Fore.LIGHTGREEN_EX + "Resource Group `{}` is active.".format(resource_group_name) + Fore.WHITE)
                    return True
                else:
                    time.sleep(5)
            else:
                time.sleep(5)
            retries -= 1
            if retries == 0:
                sys.exit(Fore.RED + "Resource group did not initalise. Exiting Program" + Fore.WHITE)

    def sku_allowed_with_vm_size(self, sku, size):
        print(Fore.LIGHTYELLOW_EX + "Checking if VM_SIZE==`{}` is allowed in DataCenter Region `{}`".format(size,
                                                                                                            sku) + Fore.WHITE)
        s = subprocess.Popen("az vm list-skus  --size {size}".format(size=size), shell=True, stdout=subprocess.PIPE,
                             universal_newlines=True)
        s = s.communicate()
        s = json.loads(s[0])
        skus = [x['locations'][0].lower() for x in s]
        if sku.lower() not in skus:
            return False
        return True

    def create_server(self, vm_details):
        return_code = -1
        retry_limit = 10
        while True:
            if return_code == 0:
                return True
            if return_code == 1:
                return False
            if retry_limit == 0:
                return False
            cmd = 'az vm create --resource-group {resourceGroupName} --name  "{serverName}" --image "UbuntuLTS" --admin-username {user_name} --admin-password "{password}" --size "{vm_size}" --custom-data  "" --no-wait'.format(
                resourceGroupName=vm_details.resource_group_name, serverName=vm_details.server_name,
                user_name=vm_details.username, password=vm_details.password, vm_size=self.VM_SIZE)
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
            out, err = result.communicate()
            return_code = result.returncode
            # print(out,err,return_code)
            retry_limit -= 1

    def server_inputs_for_threading(self, num_servers, resource_group_name):
        vm_details = []
        for i in range(num_servers):
            serverName = "{}-{}".format(self.SERVER_SLUG, str(uuid.uuid4())[:8])
            vm_dtl = self.VmDetail(resource_group_name=resource_group_name, server_name=serverName,
                                   username=self.SERVER_USER,
                                   password=self.SERVER_PASSWORD)
            vm_details.append(vm_dtl)
        return vm_details

    def get_total_active_ips(self):
        s = subprocess.Popen("az vm list -d --query \"[?powerState=='VM running']\" ", shell=True,
                             stdout=subprocess.PIPE, universal_newlines=True)
        s = s.communicate()
        s = json.loads(s[0])
        return len(s)

    def server_names_and_ips(self, skip_list=None):
        if skip_list is None:
            skip_list = []
        s = subprocess.Popen("az vm list-ip-addresses", shell=True, stdout=subprocess.PIPE, universal_newlines=True)
        s = s.communicate()
        s = json.loads(s[0])
        server_names_and_ips = [
            (x['virtualMachine']['name'], x['virtualMachine']['network']['publicIpAddresses'][0]['ipAddress']) for x in
            s if
            x is not None and x['virtualMachine']['network']['publicIpAddresses'][0]['ipAddress'] not in skip_list]
        return server_names_and_ips

    def list_running_servers(self, num_servers):
        starting_time = datetime.datetime.now()
        time.sleep(5)
        previous_server_running_value = 0
        with tqdm(total=num_servers, desc="Checking for running Servers", unit="IPs Active") as pbar:
            while True:
                time.sleep(1)
                running_servers = self.get_total_active_ips()
                if previous_server_running_value == 0 and running_servers > 0:
                    previous_server_running_value = running_servers
                    pbar.update(running_servers)
                elif previous_server_running_value == running_servers:
                    # print("Waiting for 10 seconds to retry..")
                    time.sleep(1)
                else:
                    pbar.update(running_servers - previous_server_running_value)
                    previous_server_running_value = running_servers
                    # print("running servers:: ", len(running_servers))
                # if running_servers == self.CURRENTLY_RUNNING_SERVERS + num_servers:
                if running_servers == num_servers:
                    time.sleep(1)
                    print('\n')
                    print(Fore.GREEN + "All servers running OK." + Fore.WHITE)
                    break

                # print("{} Ips Active".format(running_servers))
                loop_time = datetime.datetime.now()
                elapsed_time = loop_time - starting_time
                if elapsed_time.seconds > self.TIMEOUT:
                    print("\nFailed to start `{}` Machine/s.".format(num_servers - running_servers))
                    break
        return running_servers

    def multi_threaded_vm_initializer(self, vms_to_create):
        with Executor(10) as executor:
            flag_list = []
            for flag in tqdm(executor.map(self.create_server, vms_to_create),
                             desc="Sending Create signals to Azure API",
                             unit="Server Initialized", total=len(vms_to_create)):
                flag_list.append(flag)
        time.sleep(1)
        print("{}/{} VMs were sent an init signal successfully.".format(sum(flag_list), len(vms_to_create)))

    def open_ports_on_server(self, port_details):
        res = subprocess.Popen(
            "az vm open-port --port {squid_port} --resource-group {resource_group_name} --name {server_name}".format(
                server_name=port_details.server_name, resource_group_name=port_details.resource_group_name,
                squid_port=port_details.squid_port, ), shell=True,
            stdout=subprocess.PIPE, universal_newlines=True)
        res.communicate()
        return_code = res.returncode
        if return_code == 0:
            return True
        return False

    def port_inputs_for_threading(self, active_names_and_ips, resourceGroupName):
        port_details = []
        for server in active_names_and_ips:
            server_name = server[0]
            port_detail = self.VmPortDetail(server_name=server_name, resource_group_name=resourceGroupName,
                                            squid_port=self.SQUID_PORT)
            port_details.append(port_detail)
        return port_details

    def multi_threaded_port_opener(self, ports_to_open):
        print(Fore.LIGHTYELLOW_EX + "\nOpening Ports.." + Fore.WHITE)
        flag_list = []
        with Executor(10) as executor:
            for flag in tqdm(executor.map(self.open_ports_on_server, ports_to_open),
                             desc="Opening ports for SquidProxy",
                             unit="Ports Opened", total=len(ports_to_open)):
                flag_list.append(flag)
        time.sleep(1)
        print(Fore.LIGHTGREEN_EX + "\n{}/{} ports were opened successfully.".format(sum(flag_list),
                                                                                    len(ports_to_open)) + Fore.WHITE)

    def multi_threaded_ssh_checker(self, ssh_tuples):
        with Executor(10) as executor:
            flag_list = []
            for flag in tqdm(executor.map(self.check_ssh, ssh_tuples),
                             desc="Checking SSH Connections",
                             unit="SSH Active", total=len(ssh_tuples)):
                flag_list.append(flag)
        time.sleep(1)
        print(Fore.GREEN + "{}/{} SSH connections successful.".format(sum(flag_list), len(ssh_tuples)) + Fore.WHITE)

    def check_ssh(self, ssh_tuple):
        starting_time = datetime.datetime.now()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        time.sleep(ssh_tuple.initial_wait)

        for x in range(ssh_tuple.retries):
            try:
                ssh.connect(ssh_tuple.ip, username=ssh_tuple.user, password=ssh_tuple.password,
                            key_filename=ssh_tuple.key_file)
                return True
            except (BadHostKeyException, AuthenticationException,
                    SSHException, socket.error) as e:
                # print("Error: Could not connect to {}\n".format(ssh_tuple.ip), e)
                time.sleep(ssh_tuple.interval)
            loop_time = datetime.datetime.now()
            elapsed_time = loop_time - starting_time
            if elapsed_time.seconds > self.TIMEOUT:
                return print(Fore.RED + "Timeout Exceeded. " + Fore.WHITE)
        return False

    def create_ssh_tuples(self, server_ips, server_passwords):
        ssh_tuples = []
        for ip, passw in list(zip(server_ips, server_passwords)):
            ssh_tuple = self.SSH_TUPLE(ip=ip, user=self.SERVER_USER, password=self.SERVER_PASSWORD, key_file=None,
                                       initial_wait=10, interval=5, retries=60, )
            ssh_tuples.append(ssh_tuple)
        return ssh_tuples

    def list_servers(self):
        res = subprocess.Popen(
            "az vm list -d", shell=True,
            stdout=subprocess.PIPE, universal_newlines=True)
        s = res.communicate()
        return_code = res.returncode
        servers = json.loads(s[0])
        return servers

    def delete_vm(self, delete_tuple):
        result = subprocess.Popen(
            "az vm delete -g {} -n {} --yes".format(delete_tuple.resource_group, delete_tuple.server_name), shell=True,
            stdout=FNULL, stderr=subprocess.STDOUT)
        s = result.communicate()
        return_code = result.returncode
        if return_code == 0:
            return True
        return False

    def delete_resource_groups(self, resource_group):
        res = subprocess.Popen(
            "az group delete -n {} --yes".format(resource_group), shell=True,
            stdout=FNULL, universal_newlines=True)
        s = res.communicate()
        return_code = res.returncode
        #     servers = json.loads(s[0])
        if return_code == 0:
            return True
        return False

    def get_resource_groups(self):
        res = subprocess.Popen("az group list", shell=True,
                               stdout=subprocess.PIPE, universal_newlines=True)
        s = res.communicate()
        return_code = res.returncode
        resource_groups = json.loads(s[0])
        resource_groups = [x['name'] for x in resource_groups]
        return resource_groups

    def list_servers_in_resource_group(self, resource_group):
        res = subprocess.Popen(
            "az vm list -g {} -d".format(resource_group), shell=True,
            stdout=subprocess.PIPE, universal_newlines=True)
        s = res.communicate()
        return_code = res.returncode
        servers = json.loads(s[0])
        return servers

    def add_running_server_info_to_db(self):

        machines = subprocess.Popen("az vm list -d --query \"[?powerState=='VM running']\"", shell=True,
                                    stdout=subprocess.PIPE, universal_newlines=True)
        machines = machines.communicate()
        machines = json.loads(machines[0])
        virtual_machine_list = []

        for machine in machines:
            virtual_machine_list.append(VirtualMachines(name=machine['name'],
                                                        ip_address=machine['publicIps'],
                                                        location=machine['location'],
                                                        data_center=machine['location'],
                                                        resource_group=machine['resourceGroup'],
                                                        status='preconfigured',
                                                        server_user=machine['osProfile']['adminUsername'],
                                                        server_password="preconfigured",
                                                        squid_user="preconfigured",
                                                        squid_password="preconfigured",
                                                        squid_port="preconfigured",
                                                        login_type="UNKNOWN",
                                                        ))
        self.session.add_all(virtual_machine_list)
        self.session.commit()

def execute_term_cmd(cmd):
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True, shell=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        yield stdout_line
    popen.stdout.close()
    # return_code = popen.wait()
    # if return_code:
    #     raise subprocess.CalledProcessError(return_code, cmd)


def print_console(cmd):
    execute_term_cmd(Fore.YELLOW + "Configuring machine.." + Fore.WHITE)
    output_str = ""
    for path in execute_term_cmd(cmd):
        output_str += path
        print(path, end="")


def create_servers():
    az = Azure()
    datacenter_key = input("\n\nChoose DataCenter by Key: \n" +
                           # az.get_tabular_datacenter() +
                           "\nSelect: ")
    if datacenter_key not in az.data_center_dict.keys():
        print(Fore.RED + "Invalid server location selected\n\n" + Fore.WHITE)
        sys.exit()
    selectedRegion = az.data_center_dict[datacenter_key]
    int_key = int(datacenter_key) - 1
    az.SERVER_CREATION_LIMIT = az.LIMITS_LIST[int_key]['creatable_servers']
    az.MAX_ALLOWED_SERVERS = az.LIMITS_LIST[int_key]['limit']
    az.CURRENTLY_RUNNING_SERVERS = az.LIMITS_LIST[int_key]['current_value']
    resourceGroupName = "{}-{}".format(az.SERVER_SLUG, selectedRegion[0])
    if az.create_resource_group(resource_group_name=resourceGroupName, data_center_region=selectedRegion[0]) == 0:
        print(Fore.LIGHTGREEN_EX + "Resource Group `{}` has been created.".format(resourceGroupName) + Fore.WHITE)
    az.check_if_resource_group_is_active(resourceGroupName)
    if az.sku_allowed_with_vm_size(sku=selectedRegion[0], size=az.VM_SIZE):
        print(Fore.LIGHTGREEN_EX + "DataCenter `{}` supports the size `{}`".format(selectedRegion[0],
                                                                                   az.VM_SIZE) + Fore.WHITE)
    else:
        print(Fore.RED + "`{}` does not support the size `{}`".format(selectedRegion[0], az.VM_SIZE))
        print("Exiting Program.." + Fore.WHITE)
        sys.exit()

    num_servers = input(
        "How many server do you want to create: [[ " + Fore.RED + "CURRENT_LIMIT = {}".format(
            az.SERVER_CREATION_LIMIT) + Fore.WHITE + "  ]]: ")
    try:
        num_servers = int(num_servers)
    except ValueError:
        print(Fore.RED + "Invalid number provided.\n" + Fore.WHITE)
        print(Fore.RED + "Aborting...\n" + Fore.WHITE)
        sys.exit()
    if num_servers > az.SERVER_CREATION_LIMIT:
        print(Fore.RED + "You can't create more than {} servers".format(az.SERVER_CREATION_LIMIT) + Fore.WHITE)
        sys.exit()
    elif num_servers <= 0:
        print(Fore.RED + "Invalid number of servers provided = ", num_servers, Fore.WHITE)
        sys.exit()

    existing_ips = [x.ip_address for x in az.session.query(VirtualMachines).all()]
    if len(existing_ips) == 0:
        az.add_running_server_info_to_db()
    existing_ips = [x.ip_address for x in az.session.query(VirtualMachines).all()]

    vms_to_create = az.server_inputs_for_threading(num_servers, resourceGroupName)

    az.multi_threaded_vm_initializer(vms_to_create)

    print(Fore.LIGHTYELLOW_EX + "\n\nWaiting for Servers to Run.." + Fore.WHITE)
    total_ips_active = az.list_running_servers(num_servers + len(existing_ips))
    active_names_and_ips = az.server_names_and_ips(skip_list=existing_ips)
    server_ips = [x[1] for x in active_names_and_ips]
    server_passwords = [az.SERVER_PASSWORD] * len(server_ips)
    if len(active_names_and_ips) + len(existing_ips) != total_ips_active:
        print(Fore.RED + "There is a mismatch in the virtual machines running vs the ips")
        # print("Shutting down application." + Fore.WHITE)
        print("Continuing to configure servers.." + Fore.WHITE)
        # sys.exit()

    port_details = az.port_inputs_for_threading(active_names_and_ips, resourceGroupName)
    virtual_machine_list = []
    for name, ip in active_names_and_ips:
        virtual_machine_list.append(VirtualMachines(name=name,
                                                    ip_address=ip,
                                                    location=selectedRegion[0],
                                                    data_center=selectedRegion[1],
                                                    resource_group=resourceGroupName,
                                                    status='configured',
                                                    server_user=az.SERVER_USER,
                                                    server_password=az.SERVER_PASSWORD,
                                                    squid_user=az.SQUID_USER,
                                                    squid_password=az.SQUID_PASS,
                                                    squid_port=az.SQUID_PORT,
                                                    login_type=az.AUTH_TYPE,
                                                    ))
    az.session.add_all(virtual_machine_list)
    az.session.commit()

    az.multi_threaded_port_opener(port_details)
    ###############################
    ansible_host_format_yaml = """
            {ip}:
              ansible_connection: ssh 
              ansible_user: "{user}" 
              ansible_ssh_pass: !unsafe "{password}"
              squid_username: {squid_username}
              squid_password: {squid_password}
              squid_port: {squid_port}
              auth_type: {auth_type}
              ips_to_authenticate: {ips_to_authenticate}
    """
    canvas_str_yaml = ""
    for x in zip(server_ips, server_passwords):
        canvas_str_yaml += ansible_host_format_yaml.format(ip=x[0], password=x[1],
                                                           user=az.SERVER_USER,
                                                           squid_username=az.SQUID_USER,
                                                           squid_password=az.SQUID_PASS,
                                                           squid_port=az.SQUID_PORT,
                                                           auth_type=az.AUTH_TYPE,
                                                           ips_to_authenticate=az.IPS_TO_AUTHENTICATE,
                                                           )
    host_template_yaml_path = str(az.SCRIPT_PATH.joinpath('hosts.template.yaml'))
    with open(host_template_yaml_path, 'r') as r:
        hosts_yaml_template = r.read()
    host_yaml_path = str(az.SCRIPT_PATH.joinpath('hosts.yaml'))
    with open(host_yaml_path, 'w') as o:
        hosts_yaml_template = hosts_yaml_template.replace("*|ANSIBLE_HOST_PATTERN|*", canvas_str_yaml)
        o.write(hosts_yaml_template)
    # az.display_servers()
    print("\n")
    print(Fore.YELLOW + "Checking if SSH is alive on all hosts.." + Fore.WHITE)
    ssh_tuples = az.create_ssh_tuples(server_ips, server_passwords)

    az.multi_threaded_ssh_checker(ssh_tuples)

    time.sleep(.2)
    print(Fore.YELLOW + "Configuring Proxies..." + Fore.WHITE)
    time.sleep(10)
    playbook_path = str(az.SCRIPT_PATH.joinpath('squidproxy_installer.yml'))
    if len(server_ips) > 0:
        print_console("ansible-playbook -i \"{}\" \"{}\"".format(host_yaml_path, playbook_path))
    else:
        print(Fore.RED + "No IPs active." + Fore.WHITE)
        print(Fore.RED + "Exiting Program" + Fore.WHITE)
        sys.exit(2)


def delete_servers():
    az = Azure()
    servers = az.list_servers()
    DELETE_TUPLE = namedtuple('DELETE_TUPLE', ["server_name", "resource_group"])
    delete_tuples = [DELETE_TUPLE(x['name'], x['resourceGroup']) for x in servers]
    with Executor(10) as executor:
        flags_list = []
        for flag in tqdm(executor.map(az.delete_vm, delete_tuples), total=len(delete_tuples),
                         desc="Deleting Virtual Machines", unit="VM Deleted"):
            flags_list.append(flag)
        time.sleep(1)
        print(Fore.GREEN + "{}/{} VMs were Deleted successfully.".format(sum(flags_list),
                                                                         len(delete_tuples)) + Fore.WHITE)
    resource_groups = az.get_resource_groups()
    with Executor(10) as executor:
        flags_list = []
        for flag in tqdm(executor.map(az.delete_resource_groups, resource_groups), total=len(resource_groups),
                         desc="Deleting Resource Groups", unit="Resource Groups Deleted"):
            flags_list.append(flag)
        time.sleep(1)
        print(Fore.GREEN + "{}/{} Resource Groups were Deleted successfully.".format(sum(flags_list),
                                                                                     len(resource_groups)) + Fore.WHITE)
    az.session.query(VirtualMachines).delete()
    az.session.commit()


def display_servers():
    az = Azure()
    # print("Getting things ready. Please wait..")
    resource_names = az.get_resource_groups()
    server_info = []
    for resource_name in resource_names:
        vm_details = az.list_servers_in_resource_group(resource_name)
        server_info.extend(vm_details)

    if not server_info:
        print(Fore.GREEN + "No servers found.\n" + Fore.WHITE)
    else:
        server_ips = [x['publicIps'] for x in server_info]
        server_sr_no = list(range(len(server_ips)))
        server_names = [x['name'] for x in server_info]
        server_resource_groups = [x['resourceGroup'] for x in server_info]
        server_locations = [x['location'] for x in server_info]
        server_admin_user = [x['osProfile']['adminUsername'] for x in server_info]
        server_admin_password = [az.SERVER_PASSWORD for _ in server_info]
        server_hardware_profiles = [x['hardwareProfile']['vmSize'] for x in server_info]
        server_statuses = [x['powerState'] for x in server_info]

        print(Fore.YELLOW + "\n\nServer Info:" + Fore.WHITE)
        data_to_display = list(
            zip(server_sr_no, server_ips, server_names, server_resource_groups, server_admin_user,
                server_admin_password, server_locations, server_hardware_profiles,
                server_statuses, ))

        print(tabulate(data_to_display,
                       headers=(
                           "sr no", "IP", "Server Name", "Resource Group", "Admin User",
                           "Password", "location", "Hardware Profile", "Status",),
                       tablefmt='fancy_grid'))
        if az.INSTALL_PROXIES:
            home_path = str(Path.home())
            save_file_location = home_path + '/proxy-azure-' + datetime.datetime.now().strftime(
                '%Y-%m-%d-%H-%M-%S') + '.txt'
            if az.AUTH_TYPE == 'LOGIN':
                proxy_string_format = "{ip}:{squid_port}:{squid_user}:{squid_pass}\n"
                print("\n\n")
                print(Fore.LIGHTYELLOW_EX + "Displaying Proxies::\n" + Fore.WHITE)
                proxy_str_list = []
                for ip in server_ips:
                    proxy_str_list.append(
                        proxy_string_format.format(ip=ip, squid_port=az.SQUID_PORT,
                                                   squid_user=az.SQUID_USER,
                                                   squid_pass=az.SQUID_PASS))
                for proxy in proxy_str_list:
                    print(proxy, end="", )
                if az.SAVE_PROXIES:
                    with open(save_file_location, 'w') as w:
                        w.writelines(proxy_str_list, )
                    print(Fore.GREEN + "Proxy server info saved to file - {}".format(save_file_location) + Fore.WHITE)
            else:
                proxy_string_format = "{ip}:{squid_port}\n"
                print("\n\n")
                print(Fore.LIGHTYELLOW_EX + "Displaying Proxies::\n" + Fore.WHITE)
                proxy_str_list = []
                for ip in server_ips:
                    proxy_str_list.append(
                        proxy_string_format.format(ip=ip, squid_port=az.SQUID_PORT, ))
                for proxy in proxy_str_list:
                    print(proxy, end="", )
                if az.SAVE_PROXIES:
                    with open(save_file_location, 'w') as w:
                        w.writelines(proxy_str_list, )
                    print(Fore.GREEN + "Proxy server info saved to file - {}".format(save_file_location) + Fore.WHITE)


def display_servers2():
    az = Azure()
    print("Getting things ready. Please wait..")
    server_info = az.session.query(VirtualMachines).all()

    if not server_info:
        print(Fore.GREEN + "No servers found in DataBase. \nChecking for Servers by querying Azure..\n" + Fore.WHITE)
        display_servers()
        sys.exit()
    else:
        server_ips = [x.ip_address for x in server_info]
        server_sr_no = list(range(len(server_ips)))
        server_names = [x.name for x in server_info]
        server_resource_groups = [x.resource_group for x in server_info]
        server_locations = [x.location for x in server_info]
        server_admin_user = [x.server_user for x in server_info]
        server_admin_password = [x.server_password for x in server_info]
        # server_hardware_profiles = [x['hardwareProfile']['vmSize'] for x in server_info]
        # server_statuses = [x['powerState'] for x in server_info]
        server_auth_type = [x.login_type for x in server_info]

        print(Fore.YELLOW + "\n\nServer Info:" + Fore.WHITE)
        data_to_display = list(
            zip(server_sr_no, server_ips, server_names, server_resource_groups, server_admin_user,
                server_admin_password, server_locations, server_auth_type
                # server_hardware_profiles,
                # server_statuses,
                ))

        print(tabulate(data_to_display,
                       headers=(
                           "sr no", "IP", "Server Name", "Resource Group", "Admin User",
                           "Password", "location", "server_auth_type",
                           # "Hardware Profile", "Status",
                       ),
                       tablefmt='fancy_grid'))
        if az.INSTALL_PROXIES:
            home_path = str(Path.home())
            save_file_location = home_path + '/proxy-azure-' + datetime.datetime.now().strftime(
                '%Y-%m-%d-%H-%M-%S') + '.txt'

            # if az.AUTH_TYPE == 'LOGIN':
            #     proxy_string_format = "{ip}:{squid_port}:{squid_user}:{squid_pass}\n"
            #     print("\n\n")
            print(Fore.LIGHTYELLOW_EX + "Displaying Proxies::\n" + Fore.WHITE)
            proxy_str_list = []
            for info in server_info:
                proxy_info = [info.ip_address, info.squid_port, info.squid_user, info.squid_password]
                proxy_info = list(filter(None, proxy_info))
                proxy_info = ':'.join(proxy_info)
                proxy_str_list.append(proxy_info)

            for proxy in proxy_str_list:
                print(proxy, )
            if az.SAVE_PROXIES:
                with open(save_file_location, 'w') as w:
                    w.writelines(proxy_str_list, )
                print(Fore.GREEN + "Proxy server info saved to file - {}".format(save_file_location) + Fore.WHITE)


if __name__ == '__main__':
    create_servers()
    # delete_servers()
    # display_servers()
