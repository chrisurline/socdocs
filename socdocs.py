from datetime import date
import configparser
import argparse
import os
import pathlib
import vt
import requests

def make_file(filepath, filename):
    newfile = filepath + filename
    if not os.path.exists(newfile):
        open(newfile, 'x')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--filename', '-f', type=str, 
                        help='create a file in todays directory', default=False)
    parser.add_argument('--vtapikey', type=str, 
                        help='API Key for VirusTotal queries', default=False)
    parser.add_argument('--query', '-q', type=str, 
                        help='Execute IOC search and add report to todays folder', default=False)
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
    
    with vt.Client(args.vtapikey) as client:
        vtreport = client.get_json('/files/' + args.query)
        vtreportfile = open(datepath + '/VirusTotal-report_' + args.query + '.txt', 'w')
        vtreportfile.write(str(vtreport))
        vtreportfile.close()
        print(vtreport)
