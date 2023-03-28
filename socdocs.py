from datetime import date
import configparser
import argparse
import os
import pathlib
import requests
import re
from censys.search import CensysHosts

URL_REGEX = r'(?:http(?:s?)://)?(?:[\w]+\.)+[a-zA-Z]+(?::\d{1,5})?'
DOMAIN_REGEX = r'^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)'
IPV4_REGEX = r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}$'

def create_empty_file(file_path, file_name):
    """ Create an empty file at the specified file path """
    with open(f'{file_path}/{file_name}', 'w') as f:
        pass

def ioc_search(ioc, query_type):

    virustotal_api_key = config['API_KEYS']['virustotal']
    metadefender_api_key = config['API_KEYS']['metadefender']

    """ VirusTotal """
    try:
        if virustotal_api_key:
            match query_type:
                case 'domain':
                    query_type = '/domains/'
                case 'ip':
                    query_type = '/ip_addresses/'
                case 'hash':
                    query_type = '/files/'
            
            vt_query = f'https://www.virustotal.com/api/v3/{query_type}/{ioc}'
            vt_api_headers = {"accept": "application/json", "x-apikey": virustotal_api_key}
            vt_report = requests.request("GET", vt_query, headers=vt_api_headers)
            vt_report.raise_for_status()
            with open(f'{current_path}/VirusTotal-report_{ioc}.txt', 'w') as vt_reportfile:
                vt_reportfile.write(str(vt_report.text))
        else:
            print('VirusTotal API key is missing or invalid')
    except requests.exceptions.HTTPError as err:
        print(f'VirusTotal API error: {err}')
    except requests.exceptions.RequestException as err:
        print(f'VirusTotal API request error: {err}')
    
    """ MetaDefender """
    try:
        if metadefender_api_key:
            md_query = f'https://api.metadefender.com/v4/{query_type}/{ioc}'
            md_api_headers = {'apikey': metadefender_api_key}
            md_report = requests.request("GET", md_query, headers=md_api_headers)
            with open(f'{current_path}/MetaDefender-report_{ioc}.txt', 'w') as md_reportfile:
                md_reportfile.write(str(md_report.text))
        else:
            print('MetaDefender API key is missing or invalid.')
    except requests.exceptions.HTTPError as err:
        print(f'MetaDefender API error: {err}')
    except requests.exceptions.RequestException as err:
        print(f'MetaDefender API request error: {err}')

    """ Censys Search (IP Only) """
    if query_type == 'ip':
        censys_instance = CensysHosts()
        try:
            censys_report = censys_instance.view(ioc)
            with open(f'{current_path}/Censys-report_{ioc}.txt', 'w') as censys_report_file:
                censys_report_file.write(str(censys_report))
        except CensysException as err:
            print(f'Censys API error: {err}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--query', '-q', type=str, 
                        help='''execute IOC search and add report to todays folder''', default=False)
    parser.add_argument('--config','-c', type=argparse.FileType('r'),
                        help='''specify configuration file''', default='config.ini')
    parser.add_argument('--eventid', '-id', type=str, 
                        help='''specify an event ID''', default=False)
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read_file(args.config)

    doc_path = config['ARGUMENTS']['doc_path']

    dir_structure = date.today().strftime(config['ARGUMENTS']['date_format'])
    date_path = f'{doc_path}{dir_structure}'
    
    if os.path.exists(doc_path):
        pathlib.Path(date_path).mkdir(parents=True, exist_ok=True)
        create_empty_file(date_path, '/Scratchpad.md') # Create file to store notes specific to the day

    if args.eventid:
        current_path = os.path.join(date_path, args.eventid)
        pathlib.Path(current_path).mkdir(parents=True, exist_ok=True)
    else:
        current_path = date_path

    # determine if query is hash, IP or url/domain
    if args.query:
        if re.match(URL_REGEX, args.query): # check if url/domain
            # extract domain (includes subdomains if applicable)
            domain = re.search(DOMAIN_REGEX, args.query)
            ioc_search(domain.group(1), 'domain')
        elif re.match(IPV4_REGEX, args.query): # check if IPv4 address
            ioc_search(args.query, 'ip')
        else: # if not everything else than try searching as a file hash 
            ioc_search(args.query, 'hash')
