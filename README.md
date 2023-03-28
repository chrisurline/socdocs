# SOCDocs

## Overview:

Goal is to create a tool for SOC analysts that will assist with organizing notes and supporting documentation for each investigation. 

## How to Use:

- Update path where you'd like to store documentation/files and API keys in **`config.ini`**. 
- Run using `python3 socdocs.py`
- When the script is executed it will create a folder structure under the specified directory, organized by year > month > day. 
- File hash, domain, and IP searches can be executed using `python3 socdocs.py -q [QUERY HERE]`
- Folders for specific events can be created using the `-id` tag, additionally IOC searches tagged with an ID will put the output files in that folder.
    - Example: `python3 socdocs.py -q google.com -id EVENT-53823`
- Before using **Censys Search**, configure the API by running `censys config` and entering the API Key and Secret provided by Censys. 

## Current Threat Intel Sources:

- VirusTotal
- MetaDefender
- Censys Search (IP Addresses Only)

## To-Do:

- More threat intel sources and query options 
- Ability to run IOCs against multiple sources at once
- Functionality to take the response from TI sources and save it in a format that is a bit more readable than raw JSON, etc.
- Error handling and logging
- Move API key storage to environment variables(?)
- A lot more.....
