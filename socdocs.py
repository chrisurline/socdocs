from datetime import date
import configparser
import argparse
import os
import pathlib
import vt
import requests
import re
from constants import virustotal_api_key, metadefender_api_key

def make_file(filepath, filename):
    newfile = filepath + filename
    if not os.path.exists(newfile):
        open(newfile, 'x')

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
            vtreportfile = open(datepath + '/VirusTotal-report_' + ioc + '.txt', 'w')
            vtreportfile.write(str(vtreport))
            vtreportfile.close()
            print(vtreport)

    if metadefender_api_key:
        mdapiquery = 'https://api.metadefender.com/v4/' + querytype + '/' + ioc
        mdheaders = {'apikey': metadefender_api_key}
        mdreport = requests.request("GET", mdapiquery, headers=mdheaders)
        mdreportfile = open(datepath + '/MetaDefender-report_' + ioc + '.txt', 'w')
        mdreportfile.write(str(mdreport.text))
        mdreportfile.close()
        print(mdreport.text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--filename', '-f', type=str, 
                        help='create a file in todays directory', default=False)
    parser.add_argument('--query', '-q', type=str, 
                        help='execute IOC search and add report to todays folder', default=False)
    parser.add_argument('--config','-c', type=argparse.FileType('r'),
                        help='specify configuration file', default='config.ini')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read_file(args.config)

    docpath = config['ARGUMENTS']['docpath']
    datepath = docpath + date.today().strftime(config['ARGUMENTS']['dateformat'])
    
    if os.path.exists(docpath):
        pathlib.Path(datepath).mkdir(parents=True, exist_ok=True)
        make_file(datepath, '/Scratchpad.md') # Create file to store notes specific to the day

    if args.filename:
        make_file(datepath, '/' + args.filename)

    # determine if query is hash, IP or url/domain
    elif re.match("(?:http(?:s?)://)?(?:[\w]+\.)+[a-zA-Z]+(?::\d{1,5})?", args.query): # check if url/domain
        # if it is a full URL strip it down to base domain
        domain = re.search('^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)', args.query)
        ioc_search(domain.group(1), 'domain')
    elif re.match("^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}$", args.query): # check if IPv4 address
        ioc_search(args.query, 'ip')
    else: # if not everything else than try searching as a file hash 
        ioc_search(args.query, 'hash')
