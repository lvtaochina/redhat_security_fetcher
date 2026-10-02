import logging
from pathlib import Path

API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'

PROXIES = {}
        
REQ_TIME_OUT = 20

#uncomment lines below to specify proxy server
# HTTPS_PROXY = "http://yourproxy.example.com:8000"
# PROXIES = { "https" : HTTPS_PROXY }

CVE_INPUT_PATH = Path(__file__).resolve().parent / "input" / "cves.d260721.txt"

WANT_RHELS = {
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

FIX_STATES = {
                "Affected",
                "Fix deferred",
#                "Not affected",
#                "Will not fix",
#                "Out of support scope",
                }      

AFFECTED_KEYS = [
                "product_name", 
                "package", 
                "advisory",
                ]

PACKAGE_KEYS = [
                "product_name", 
                "package_name", 
                "fix_state",
                ]

LOG_FORMAT  = "%(asctime)s - %(levelname)s - %(message)s"
LOG_FILENAME = Path(__file__).resolve().parent / "log" / "rhel_cve_fetcher.log"
# LOG_LEVEL = logging.DEBUG MAY GET ADDITIONAL debug INFO FROM requests(URLLIB3)
LOG_LEVEL = logging.INFO
LOG_FILEMODE = "a"
LOG_ENCODING = 'utf-8'
LOG_MAX_BYTES = 1024 * 1024  # 1 MB NOT APPLICABLE TO logging.basicConfig()
BACKUP_COUNT = 5 # NOT APPLICABLE TO logging.basicConfig() 