# SOCDocs

## Overview:

Goal is to create a CLI tool for SOC analysts that will assist with organizing notes and supporting documentation for each investigation. 

## How to Use:

1. Update path in config.ini to point to a directory that will store documentation. 
2. Add TI source API keys to constants.py
3. Run using `python3 socdocs.py`
4. When the script is executed it will create a folder structure under this directory organized by year > month > day. 
5. File hash, domain, and IP searches can be executed using `python3 socdocs.py -q [QUERY HERE]`

## To-Do:

- More threat intel sources and query options 
- Ability to run IOCs against multiple sources at once
- Functionality to take the response from TI sources and save it in a format that is a bit more readable than raw JSON, etc.
- Error handling and logging
- Move API key storage to environment variables versus storing in constants.py
- A lot more.....
