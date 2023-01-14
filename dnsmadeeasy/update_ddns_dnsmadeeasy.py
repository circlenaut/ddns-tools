#!/usr/bin/env python3
#
# Script to update dynamic DNS records at Dnsmadeeasy with HTTPS support.
# Put your settings in settings.json in the same folder with the script 
# and set to run from cron.
#
# Requires following non-core modules;
#  * python-requests, https://pypi.python.org/pypi/requests/
#  * python-dns, https://pypi.python.org/pypi/dnspython/
#
# Author: Sandi Wallendahl <wyrmiyu@gmail.com>
# License: MIT, https://github.com/wyrmiyu/ddns-tools/blob/master/LICENSE

from __future__ import print_function

import socket
import json
import logging
import os
import sys
import requests
import dns.resolver
import json
import re
# import subprocess
import time
# import psutil
# import netifaces as ni
from urllib.parse import urlparse
from urllib.parse import urlencode
from urllib.parse import quote_plus
from requests import get
from datetime import datetime


# Set Constants, Get current directory and set DNS Made Easy Addresses
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_INTERFACE = '"eth0"'
BASE_DIR = os.path.dirname(__file__)
GET_DME_IP_URL = 'http://myip.dnsmadeeasy.com'
DME_UPDATE_IP_URL = 'https://cp.dnsmadeeasy.com/servlet/updateip'

def error(message):
    """
    Log an error and exit.
    """
    logger.error(message)
    sys.exit(1)

def check_ssl(url):
    """
    Check if a secure URL.
    """
    try:
        requests.get(url, verify=True)
    except requests.exceptions.SSLError:
        error('The SSL certificate for {0} is not valid.'.format(url))

def check_password(_password):
    """
    Checks password for invalid URL characters.
    """
    invalid_characters = re.findall(r'[^a-zA-Z0-9@#$%^&+=]', _password)
    if invalid_characters:
        error("Invalid password: '{}' contains invalid characters: {}".format(_password, invalid_characters))
    try:
        quote_plus(_password)
    except UnicodeEncodeError:
        error("Invalid password: '{}' contains invalid characters".format(_password))

def get_current_ip(url):
    """
    Get the IP of a URL.
    """
    try:
        url_ip = requests.get(url).text.strip()
        logger.debug(f"Got ip {url_ip} for url {url}")
        return url_ip
    except requests.ConnectionError:
        logger.debug(
            'Could not get the current IP from {0}'.format(GET_DME_IP_URL))

def get_dns_ip(name, target='A'):
    """
    Get the IP of a DNS record
    """
    bits = name.split('.')
    while bits:
        try:
            ns = str(dns.resolver.resolve('.'.join(bits), 'NS')[0])
        except:
            bits.pop(0)
        else:
            ns = socket.gethostbyname(ns)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            q = dns.resolver.resolve(name, target)
            dns_ip = str(q[0]).strip()
            logger.debug(f"Got ip {dns_ip} for DNS record {name}")
            return dns_ip
    error('Could not get the authoritative name server for {0}.'.format(name))

def update_ip_to_dns(ip, _username, _password, _record_id, url=None):
    """
    Update DNS Made Easy DNS entry's IP
    """
    url = url or DME_UPDATE_IP_URL
    check_ssl(url)
    check_password(_password)
    params = {
        'username': _username,
        'password': _password,
        'id': _record_id,
        'ip': ip,
    }
    logger.debug(url + '?' + urlencode(params))
    return requests.get(url, params=params)

def run_record_updater():
    """
    Run the DNS Made Easy record updater
    """

    # Get current time
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    logger.info(f"Checking record on: {dt_string}")

    # Update Record
    try:
        with open(os.path.join(BASE_DIR, 'settings.json')) as json_file:
            settings = json.load(json_file)
    except IOError:
        error('No `settings.json` file. Create one from the '
            '`settings.json.sample` file.')
    except ValueError:
        error('Invalid `settings.json` file. Check the `settings.json.sample` '
            'file for an example.')

    for record in settings:
        # Check fields
        pretty_record = json.dumps(record, indent=2)
        if 'USERNAME' not in record:
            error(f"settings.json record {pretty_record} is missing USERNAME field")
        if 'PASSWORD' not in record:
            error(f"settings.json record {pretty_record} is missing PASSWORD field")
        if 'RECORD_ID' not in record:
            error(f"settings.json record {pretty_record} is missing RECORD_ID field")
        if 'RECORD_NAME' not in record:
            error(f"settings.json record {pretty_record} is missing RECORD_NAME field")

        username = record.get('USERNAME')
        password = record.get('PASSWORD')
        record_id = record.get('RECORD_ID')
        record_name = record.get('RECORD_NAME')

        # Update the IP for this record
        current_ip = get_current_ip(GET_DME_IP_URL)
        logger.debug(f"{current_ip} => {pretty_record}")

        if current_ip:
            if current_ip != get_dns_ip(record_name):
                logger.debug('Current IP differs with DNS record, attempting to '
                'update DNS.')

                logger.info(f"Setting IP {current_ip} for record: {record_id} - {record_name}")

                if not urlparse(f"https://{record_name}").scheme:
                    error('{0} is not a valid URL. Please check your settings.json file.'.format(record_name))

                request = update_ip_to_dns(current_ip, username, password, record_id)

                if request and request.text == 'success':
                    logger.info('Updating record for {0} to {1} was '
                                'succesful.'.format(record_name, current_ip))
                else:
                    # logger.debug(f"request: {request.text}")
                    error('Updating record for {0} to {1} failed.'.format(
                        record_name, current_ip))
            else:
                logger.info(
                    'No changes for DNS record {0} to report.'.format(record_name))
        else:
            error('Unable to get current IP!')

def main():
    # interfaces = psutil.net_if_addrs()
    # logger.debug(interfaces)
    # first_interface_name = list(interfaces.keys())[1]
    # logger.debug(first_interface_name)

    # first_interface_name = ni.interfaces()[1]
    # logger.debug(first_interface_name)

    # # interface = first_interface_name or DEFAULT_INTERFACE
    # first_interface_name = list(interfaces.keys())[1]
    # logger.debug(first_interface_name)

    public_ip = get('https://api.ipify.org').content.decode('utf8')
    logger.debug('My public IP address is: {}'.format(public_ip))

    # Run the updater if the record has changed
    current_ip = ""
    while True:
        public_ip = requests.get('https://api.ipify.org').content.decode('utf8')
        if public_ip != current_ip:
            current_ip = public_ip
            run_record_updater()
        time.sleep(10)

if __name__ == '__main__':

    try:
        formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        screen_handler = logging.StreamHandler(stream=sys.stdout)
        screen_handler.setFormatter(formatter)

        logger = logging.getLogger(__name__)

        logger.setLevel(getattr(logging, DEFAULT_LOG_LEVEL))
        logger.addHandler(screen_handler)
    except AttributeError:
        error('Invalid `LOG_LEVEL` setting. Check `settings.json` file. Valid '
                'log levels are: DEBUG, INFO, WARNING, ERROR, CRITICAL.')

    main()
