#!/usr/bin/env python3
import os
import sys
import requests
import argparse
import ipaddress
import json

# Help messages
msg_description = '''
This tool uses APIs from various services to provide IP information. This is intended to speed up the 
investigation process of suspicous IPs from SOC alerts.

Usage Examples:
./ip_tool.py 0.0.0.0
./ip_tool.py 0.0.0.0 --exclude_VT
'''

# Help messages
msg_setup = '''
This tool uses API keys from various services to provide IP information. To use this tool, you will need
to have an API key for the following services.

- VirusTotal: VIRUS_TOTAL_KEY
- SecurityTrails: SEC_TRAILS_KEY

These can be passed as parameters or read from environment variables. To export an environment variable, 
you can use the following commands.
- Powershell: $Env:VAR_NAME="<Key>"
- Bash/Linux: export VAR_NAME=<Key>

Environment Variable Examples: 
$Env:VIRUS_TOTAL_KEY=1234567890abcdefghij
export VIRUS_TOTAL_KEY=1234567890abcdefghij

Usage Examples:
./ip_tool.py 0.0.0.0 --VirusTotal <Key> --SecurityTrails <Key>
./ip_tool.py 0.0.0.0 --SecurityTrails <Key>
./ip_tool.py 0.0.0.0
'''

def search_vt(ip, key):
    '''Uses an API key to search VirusTotal for IP information'''

    # Build the request
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Make the call
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        response = f'Error Getting VirusTotal Data: {e}'
        return response
    
    # Convert data to JSON
    response = response.json()

    # Init a payload
    vt_data = {}

    # Extract relevant data
    important_attrs = {
        'Country': 'country', 
        'Owner': 'as_owner',
        'Scores': 'last_analysis_stats'
    }

    for attr, key in important_attrs.items():
        vt_data[attr] = response['data']['attributes'][key]
    
    # Calculate score
    vt_data['Threat Score'] = f"{(vt_data['Scores']['malicious'] / (vt_data['Scores']['harmless'] + vt_data['Scores']['malicious'] + vt_data['Scores']['suspicious'])) * 100}%"

    # Return results
    return vt_data

def search_st(ip, key):
    '''Uses an API key to search SecurityTrails for IP information'''

    # Build the request
    url = f'https://api.securitytrails.com/v1/ips/{ip}/whois'
    headers = {
        'APIKEY': key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Make the call
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        response = f'Error Getting SecurityTrails Data: {e}'
        return response
    
    # Convert data to JSON
    response = response.json()

    # Send it back
    return response

# Build a parser
if __name__ == '__main__':
    # Define the parser
    parser = argparse.ArgumentParser(
        description=msg_description,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Add arguments
    parser.add_argument('IP',                   metavar='<IP>',     type=str,   help='IP Address to Look Up')
    parser.add_argument('--VirusTotal',         metavar='<Key>',    type=str,   help='VirusTotal API key - If not specified, environment variable is used')
    parser.add_argument('--SecurityTrails',     metavar='<Key>',    type=str,   help='SecurityTrails API key - If not specified, environment variable is used')
    parser.add_argument('--exclude_VT',         action='store_true',            help='Exclude VirusTotal from search')
    parser.add_argument('--exclude_ST',         action='store_true',            help='Exclude SecurityTrails from search')
    
    # Collect arguments
    args = parser.parse_args()

    # Validate IP address
    try:
        ipaddress.ip_address(args.IP)
    except Exception as e:
        print(e)
            
    # Check for optional parameters and set them
    if not args.exclude_VT:
        # Set the key
        print('Note: Including VirusTotal in search')
        if args.VirusTotal is None:
            print('Note: Using VIRUS_TOTAL_KEY env variable')
            vt_key = os.getenv('VIRUS_TOTAL_KEY')
            if vt_key is None:
                print(f'VIRUS_TOTAL_KEY Key not found.\n{msg_setup}')
                sys.exit(1)
        else:
            vt_key = args.VirusTotal
        
        # Make the search
        vt_data = search_vt(args.IP, vt_key)
        print('\n----- VirusTotal Search -----')
        print(json.dumps(vt_data, indent=4))
    
    if not args.exclude_ST:
        print('Note: Including SecurityTrails in search')
        if args.SecurityTrails is None:
            print('Note: Using SEC_TRAILS_KEY env variable')
            st_key = os.getenv('SEC_TRAILS_KEY')
            if st_key is None:
                print(f'SEC_TRAILS_KEY not found.\n{msg_setup}')
                sys.exit(1)
        else:
            st_key = args.SecurityTrails
        
        # Make the search
        st_data = search_st(args.IP, st_key)
        print('\n----- SecurityTrails Search -----')
        print(json.dumps(st_data, indent=4))