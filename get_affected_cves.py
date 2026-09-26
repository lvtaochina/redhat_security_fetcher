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


"""
get_data(endpoint: str)
函数职责：从指定端点获取数据

参数：
    endpoint: str
    例如：
    "/cve/CVE-2026-1234.json"

处理(包含异常处理):
    1. 使用 requests 发起 HTTP 请求
    2. 检查 HTTP 状态码
    3. 将响应转换为 JSON
    4. 检查返回数据是否为空

返回：
    成功 → JSON 数据
    失败 → None
"""
def get_data(endpoint: str):

    full_query = API_HOST + endpoint
    try:
        r = requests.get(full_query, proxies=PROXIES, timeout=20)
    except requests.RequestException as e:
        print(f"Error fetching data for {endpoint}: {e}")
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


"""
filter_rhel_data(data: dict, want_rhels: set[str], fix_states: set[str], affected_want_keys: list[str], package_want_keys: list[str]) -> tuple[dict, dict]
函数职责：
    处理一个 CVE API 响应数据，
    从中筛选指定 RHEL 版本的受影响数据。
    可进一步抽象本函数?

输入：
    一个 CVE 对应的 JSON 数据
    目标 RHEL 版本集合
    允许的修复状态集合
    期望的 affected_release 键列表
    期望的 package_state 键列表

处理：
    1. 筛选目标 RHEL 版本
    2. 处理有 FIX 的 affected_release 数据
    3. 处理无 FIX 的 package_state 数据

返回：
    包含两个字典的元组
        ├── 有 FIX 的数据
        └── 无 FIX 的数据
"""
def filter_rhel_data(data: dict, want_rhels: set[str], fix_states: set[str], affected_keys: list[str], package_keys: list[str]) -> tuple[dict, dict]:
    # Implementation for filtering RHEL data
    affected_releases = {}
    package_states = {}

    if "affected_release" in data:
        for rel in data.get("affected_release", []):
            prd_name = rel.get("product_name")
            if prd_name in want_rhels:
                rel_to_add = [ rel.get(k) for k in affected_keys[1:] ] 
                #用有修复的数据构建字典；是否已有该版本数据,没有的话添加新的键值对,有的话直接追加数据
                if prd_name not in affected_releases:                     
                    affected_releases[prd_name] = [rel_to_add]
                elif rel_to_add not in affected_releases[prd_name]: # Append with de-duplication.
                    affected_releases[prd_name].append(rel_to_add)

    if "package_state" in data:
        for rel in data.get("package_state", []):
            prd_name = rel.get("product_name")
            if prd_name in want_rhels and rel.get("fix_state") in fix_states:
                rel_to_add = [ rel.get(k) for k in package_keys[1:] ]
                #用无修复的数据构建字典；是否已有该版本数据,没有的话添加新的键值对,有的话直接追加数据
                if prd_name not in package_states:   
                    package_states[prd_name] = [rel_to_add]
                elif rel_to_add not in package_states[prd_name]: # Append with de-duplication.
                    package_states[prd_name].append(rel_to_add)    

    return affected_releases, package_states


"""
print_rhel_table(d:dict[str, list[list[str]]]) -> None
    函数职责：格式化输出 RHEL 版本和对应数据
    输入: 一个包含 RHEL 版本和对应数据的字典
    处理: 格式化输出 RHEL 版本和对应数据
    返回: None
"""
def print_rhel_table(d:dict[str, list[list[str]]]) -> None:
    for rhel_ver, item_list in d.items():
        print(f"\n----{rhel_ver}----")
        print(f"{'组件':<85}{'勘误编号':<20}")
        for pkg, rhsa in item_list:
            print(f"{pkg:<85}{rhsa:<20}")


"""
read_cves()
    函数职责: 将CVE ID列表文件读入到一个list
    参数: N/A
    数据来源: input/cves.txt
    处理：逐行读取，去除空白，忽略空行
    返回: list[str]
    如果input/cves.txt不存在或cves.txt为空,read_cves() &调用者如何协同？ 
"""
def read_cves() -> list[str]:
    cves_path = Path(__file__).resolve().parent / 'input' / 'cves.txt'
    try:
        with cves_path.open('r', encoding='utf-8') as f:
            cves = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: input/cves.txt not found.")
        return []
    return cves


"""
main()
    函数职责: 主函数, 用于执行CVE数据获取和过滤逻辑
    参数: N/A
    数据来源: input/cves.txt
    处理: 
        读取CVE数据文件
        从红帽官网获取CVE完整安全数据
        过滤所需的安全数据
        展示安全数据
    返回: None
"""

def main() -> None:
    cves = read_cves()

    for cve in cves:
        print('\n'+'*' * 100)
        endpoint = '/cve/' + cve + '.json'
        data = get_data(endpoint)

        if data is None:
            print(f"{cve}: skipped or no data")
            continue

        if data.get('message') == 'Not Found' or ('package_state' not in data and 'affected_release' not in data):
            print(cve + ' does not affect Red Hat software.')
            continue

        affected_releases = filter_rhel_data(data, want_rhels, fix_states, affected_keys, package_keys)[0]
                        
        #print(data.get('name', cve), "\n红帽有修复: ", affected_releases, "\n红帽无修复: ", package_states)
        print(data.get('name', cve))
        print(data.get('threat_severity', 'NO threat_severity FOUND'), data.get('public_date', 'NO public_date FOUND')[0:10])
        if affected_releases:
            print_rhel_table(affected_releases)
        else:
            print("有修复部分: 红帽相关版本产品不受影响")
        #if package_states:
        #   print_rhel_table(package_states)
        #else:
         #  print("无修复部分: 红帽相关版本产品不受影响")

if __name__ == "__main__":
    main()