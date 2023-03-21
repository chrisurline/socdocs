# SOCDocs

## Overview:

Goal is to create a CLI tool for SOC analysts that will assist with organizing notes and supporting documentation for each investigation. 

## How to Use:

1. Update path in config.ini to point to a directory that will store documentation. 
2. Run using `python3 socdocs.py`
3. When the script is executed it will create a folder structure under this directory organized by year > month > day. 
4. Currently only has VT API for hash searches. This can be executed using the `-query` + `--vtapikey` arguments. At the moment this will save a text document containing a report from VT in JSON format. 

## To-Do:

- More threat intel sources and query options 
- Ability to run IOCs against multiple sources at once
- Secure API key storage so it wont need to be provided each time the user wants to run a query
- Functionality to take the response from TI sources and save it in a format that is a bit more readable than raw JSON, etc.
- Error handling and logging
- A lot more.....
