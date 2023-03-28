from datetime import date
import configparser
import argparse
import os
import pathlib
import vt
import requests
import re
import json
from constants import virustotal_api_key, metadefender_api_key

URL_REGEX = r'(?:http(?:s?)://)?(?:[\w]+\.)+[a-zA-Z]+(?::\d{1,5})?'
DOMAIN_REGEX = r'^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)'
IPV4_REGEX = r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}$'

def make_file(filepath, filename):
    with open(f'{filepath}/{filename}', 'w') as f:
        pass

def ioc_search(ioc, querytype):
    if virustotal_api_key:
        with vt.Client(virustotal_api_key) as client:
            match querytype:
                case 'domain':
                    queryvar = '/domains/'
                case 'ip':
                    queryvar = '/ip_addresses/'
                case 'hash':
                    queryvar = '/files/'
            vtreport = client.get_json(queryvar + ioc)

            with open(f'{currentpath}/VirusTotal-report_{ioc}.txt', 'w') as vtreportfile:
                vtreportfile.write(json.dumps(vtreport, indent=4))
            print(vtreport)

    if metadefender_api_key:
        mdapiquery = f'https://api.metadefender.com/v4/{querytype}/{ioc}'
        mdheaders = {'apikey': metadefender_api_key}
        mdreport = requests.request("GET", mdapiquery, headers=mdheaders)
        with open(f'{currentpath}/MetaDefender-report_{ioc}.txt', 'w') as mdreportfile:
            mdreportfile.write(str(mdreport.text))
        print(mdreport.text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--filename', '-f', type=str, 
                        help='''create a file in todays directory''', default=False)
    parser.add_argument('--query', '-q', type=str, 
                        help='''execute IOC search and add report to todays folder''', default=False)
    parser.add_argument('--config','-c', type=argparse.FileType('r'),
                        help='''specify configuration file''', default='config.ini')
    parser.add_argument('--eventid', '-id', type=str, 
                        help='''specify an event ID''', default=False)
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read_file(args.config)

    docpath = config['ARGUMENTS']['docpath']

    formatdate = date.today().strftime(config['ARGUMENTS']['dateformat'])
    datepath = f'{docpath}{formatdate}'
    
    if os.path.exists(docpath):
        pathlib.Path(datepath).mkdir(parents=True, exist_ok=True)
        make_file(datepath, '/Scratchpad.md') # Create file to store notes specific to the day
    
    if args.eventid:
        currentpath = os.path.join(datepath, args.eventid)
        pathlib.Path(currentpath).mkdir(parents=True, exist_ok=True)
    else:
        currentpath = datepath

    if args.filename:
        make_file(currentpath, f'/{args.filename}')

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
