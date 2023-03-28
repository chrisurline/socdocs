# 03-20-2023 - Chris Surline

from datetime import date
import configparser
import argparse
import os
import pathlib
import vt
import requests
from constants import virustotal_api_key, metadefender_api_key

def make_file(filepath, filename):
    newfile = filepath + filename
    if not os.path.exists(newfile):
        open(newfile, 'x')

def hash_search(filehash):

    if virustotal_api_key:
        with vt.Client(virustotal_api_key) as client:
            vtreport = client.get_json('/files/' + filehash)
            vtreportfile = open(datepath + '/VirusTotal-report_' + filehash + '.txt', 'w')
            vtreportfile.write(str(vtreport))
            vtreportfile.close()
            print(vtreport)

    if metadefender_api_key:
        mdapiquery = 'https://api.metadefender.com/v4/hash/' + filehash
        mdheaders = {'apikey': metadefender_api_key}
        mdreport = requests.request("GET", mdapiquery, headers=mdheaders)
        mdreportfile = open(datepath + '/MetaDefender-report_' + filehash + '.txt', 'w')
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

    if args.query:
        hash_search(args.query)
