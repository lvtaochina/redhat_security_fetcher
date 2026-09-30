from pathlib import Path

API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'

PROXIES = {}
        
REQ_TIME_OUT = 20

#uncomment lines below to specify proxy server
# HTTPS_PROXY = "http://yourproxy.example.com:8000"
# PROXIES = { "https" : HTTPS_PROXY }

CVE_INPUT_PATH = Path(__file__).resolve().parent / "input" / "cves.d260721.txt"

want_rhels = {
                "Red Hat Enterprise Linux 7", 
                "Red Hat Enterprise Linux 7.3", 
                "Red Hat Enterprise Linux 7.5",
                "Red Hat Enterprise Linux 8", 
                "Red Hat Enterprise Linux 8.4", 
                "Red Hat Enterprise Linux 8.8", 
                "Red Hat Enterprise Linux 8.10",
             #   "Red Hat Enterprise Linux 9", 
             #   "Red Hat Enterprise Linux 9.6"
                }

fix_states = {
                "Affected",
                "Fix deferred",
#                "Not affected",
#                "Will not fix",
#                "Out of support scope",
                }      

affected_keys = [
                "product_name", 
                "package", 
                "advisory",
                ]

package_keys = [
                "product_name", 
                "package_name", 
                "fix_state",
                ]