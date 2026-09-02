#!/usr/bin/env python3

# import sys
import requests
# from datetime import datetime, timedelta
from pathlib import Path

API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'

PROXIES = {}

#uncomment lines below to specify proxy server
# HTTPS_PROXY = "http://yourproxy.example.com:8000"
# PROXIES = { "https" : HTTPS_PROXY }

def get_data(query):

    full_query = API_HOST + query
    try:
        r = requests.get(full_query, proxies=PROXIES, timeout=20)
    except requests.RequestException as e:
        print(f"Error fetching data for {query}: {e}")
        return None

    if r.status_code != 200:
        print(f"HTTP {r.status_code} for {full_query}")
        return None
    
    try:
        data = r.json()
    except ValueError:
        print(f"Invalid JSON response for {full_query}")
        return None

    if not data:
        print(f'No data returned for {full_query}')
        return None

    return data

BASE_DIR = Path(__file__).resolve().parent
CVES_PATH = BASE_DIR / 'input' / 'cves.txt'

with CVES_PATH.open('r', encoding='utf-8') as f:
    cves = [line.strip() for line in f if line.strip()]

affected_want_keys = ["product_name", "package", "advisory"]
package_want_keys = ["product_name", "package_name", "fix_state"]
want_rhels_MA = {
                "Red Hat Enterprise Linux 7", 
                "Red Hat Enterprise Linux 7.3", 
                "Red Hat Enterprise Linux 7.5",
                "Red Hat Enterprise Linux 8", 
                "Red Hat Enterprise Linux 8.4", 
                "Red Hat Enterprise Linux 8.8", 
                "Red Hat Enterprise Linux 8.10"
                }

# uncomment the following lines if you want to include RHEL 9 and RHEL 9.6 in the search
#want_rhels_CCBP = {
#                "Red Hat Enterprise Linux 9", 
#                "Red Hat Enterprise Linux 9.6", 
#                }

fix_states = {
                "Affected",
                "Fix deferred"
#                "Not affected",
#                "Will not fix",
#                "Out of support scope"
                }                          

for cve in cves:
    print('*' * 50)
    endpoint = '/cve/' + cve + '.json'
    data = get_data(endpoint)

    if data is None:
        print(f"{cve}: skipped or no data")
        continue

    if data.get('message') == 'Not Found' or ('package_state' not in data and 'affected_release' not in data):
        print(cve + ' does not affect Red Hat software.')
        continue

    affected_releases = {}
    package_states = {}

    if "affected_release" in data:
        for rel in data.get("affected_release", []):
            prd_name = rel.get("product_name")
            if prd_name in want_rhels_MA: 
                #针对修复部分构建字典,是否已有该版本,没有添加键值对,有的话追加该键值
                if prd_name not in affected_releases:   
                    affected_releases[prd_name] = [[ rel.get(k) for k in affected_want_keys[1:] ]]
                else:
                    affected_releases[prd_name].append([ rel.get(k) for k in affected_want_keys[1:] ])

    if "package_state" in data:
        for rel in data.get("package_state", []):
            prd_name = rel.get("product_name")
            if prd_name in want_rhels_MA and rel.get("fix_state") in fix_states:
                #针对无修复部分构建字典,是否已有该版本,没有添加键值对,有的话追加该键值
                if prd_name not in package_states:   
                    package_states[prd_name] = [[ rel.get(k) for k in package_want_keys[1:-1] ]]
                else:
                    package_states[prd_name].append([ rel.get(k) for k in package_want_keys[1:-1] ])

    print(data.get('name', cve), "\n红帽有修复: ", affected_releases, "\n红帽无修复: ", package_states)